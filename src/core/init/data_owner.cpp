#include "data_owner.h"
#include "../../utils/merkle_tree.h"
#include "../../tee_simulator/enclave_sign.h"
#include "../../utils/time_utils.h"
#include "../../../include/config.h"

int DataOwner::split_and_encrypt(const std::vector<uint8_t>& raw_file,
                                const std::array<uint8_t, 32>& key,
                                std::vector<EncryptedBlock>& encrypted_blocks,
                                std::array<uint8_t, 32>& file_fingerprint) {
    encrypted_blocks.clear();
    
    // 计算文件分块数量
    size_t num_blocks = (raw_file.size() + Config::BLOCK_SIZE - 1) / Config::BLOCK_SIZE;
    
    // 存储所有块的哈希，用于计算文件指纹
    std::vector<std::array<uint8_t, 32>> block_hashes;
    
    // 分块并加密
    for (size_t i = 0; i < num_blocks; ++i) {
        // 计算当前块的起始和结束索引
        size_t start = i * Config::BLOCK_SIZE;
        size_t end = std::min(start + Config::BLOCK_SIZE, raw_file.size());
        std::vector<uint8_t> block_data(raw_file.begin() + start, raw_file.begin() + end);
        
        // 生成随机IV
        EncryptedBlock encrypted_block;
        if (tee_get_random(encrypted_block.iv.data(), 12) != 0) {
            return -1;
        }
        
        // 加密块数据
        if (aes_gcm_encrypt(key, block_data, encrypted_block.iv, 
                           encrypted_block.ciphertext, encrypted_block.auth_tag) != 0) {
            return -1;
        }
        
        encrypted_blocks.push_back(encrypted_block);
        
        // 计算块哈希并存储
        block_hashes.push_back(hash_encrypted_block(encrypted_block));
    }
    
    // 计算文件指纹（所有块哈希的哈希）
    if (block_hashes.empty()) {
        file_fingerprint.fill(0);
    } else {
        MerkleTree merkle(block_hashes);
        file_fingerprint = merkle.get_root();
    }
    
    return 0;
}

bool DataOwner::verify_proof(const ProofPackage& proof,
                            const std::array<uint8_t, 65>& enclave_pub_key,
                            const MerkleTree& merkle_tree) {
    // 1. 验证签名
    std::vector<uint8_t> sign_data;
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&proof.time_slot_id), 
                     reinterpret_cast<const uint8_t*>(&proof.time_slot_id) + 8);
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&proof.t_start), 
                     reinterpret_cast<const uint8_t*>(&proof.t_start) + 8);
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&proof.t_slot), 
                     reinterpret_cast<const uint8_t*>(&proof.t_slot) + 4);
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&proof.rep_snapshot), 
                     reinterpret_cast<const uint8_t*>(&proof.rep_snapshot) + 8);
    sign_data.insert(sign_data.end(), proof.random_r.begin(), proof.random_r.end());
    
    if (!tee_verify_signature(enclave_pub_key, sign_data.data(), sign_data.size(), proof.enclave_sig)) {
        return false;
    }
    
    // 2. 验证Merkle路径（需要解析merkle_path）
    std::vector<std::pair<std::array<uint8_t, 32>, bool>> path;
    size_t pos = 0;
    
    while (pos + 32 + 1 <= proof.merkle_path.size()) {
        std::array<uint8_t, 32> hash;
        memcpy(hash.data(), proof.merkle_path.data() + pos, 32);
        pos += 32;
        
        bool is_left = (proof.merkle_path[pos] == 0x01);
        pos += 1;
        
        path.emplace_back(hash, is_left);
    }
    
    // 这里需要获取挑战块的哈希来验证，实际应用中应该从存储节点获取
    // 简化处理：假设我们可以获取到挑战块的哈希
    // 注意：在实际系统中，这需要通过其他方式验证
    
    // 3. 验证时间有效性
    uint64_t current_time = get_current_timestamp();
    if (!is_time_valid(proof.t_start, proof.t_slot, current_time, Config::NETWORK_DELAY)) {
        return false;
    }
    
    return true;
}

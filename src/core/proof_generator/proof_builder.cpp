#include "proof_builder.h"
#include "challenge.h"
#include "../../tee_simulator/random_source.h"
#include "../../tee_simulator/enclave_sign.h"
#include "../../utils/crypto_utils.h"
#include "../../utils/merkle_tree.h"
#include "../../utils/time_utils.h"
#include "../../../include/common_type.h"
#include "../../../include/config.h"

#include <cstdio>

int ProofBuilder::build_proof_package(const EnclaveKeyPair& enclave_key,
                                     const MerkleTree& merkle_tree,
                                     double current_rep,
                                     uint64_t time_slot_id,
                                     uint64_t t_start,
                                     const std::array<uint8_t, 32>& prev_proof_hash,
                                     size_t total_blocks,
                                     ProofPackage& proof) {
    // 1. 生成挑战随机数（调用TEE模拟熵源）
    ChallengeGenerator challenge_gen;
    if (challenge_gen.generate_random_challenge(proof.random_r) != 0) {
        return -1;
    }

    // 2. 计算挑战块索引（i = R mod N）
    proof.challenge_idx = challenge_gen.calculate_challenge_index(proof.random_r, total_blocks);

    // 3. 获取Merkle路径（验证证据）
    std::vector<std::pair<std::array<uint8_t, 32>, bool>> merkle_path;
    if (!merkle_tree.get_proof(proof.challenge_idx, merkle_path)) {
        return -1;
    }
    
    // 序列化Merkle路径（存储到证明包）
    proof.merkle_path.clear();
    for (const auto& [hash, dir] : merkle_path) {
        proof.merkle_path.insert(proof.merkle_path.end(), hash.begin(), hash.end());
        proof.merkle_path.push_back(dir ? 0x01 : 0x00);
    }

    // 4. 计算动态时间槽长度（T = T_min + (T_max - T_min)*(1 - Rep)）
    proof.t_slot = Config::T_MIN + (Config::T_MAX - Config::T_MIN) * (1 - current_rep);

    // 5. 填充证明包基础字段
    proof.time_slot_id = time_slot_id;
    proof.prev_hash = prev_proof_hash;
    proof.rep_snapshot = current_rep;
    proof.t_start = t_start;

    // 6. 飞地签名（签名内容：时间槽ID + t_start + t_slot + rep_snapshot + random_r）
    std::vector<uint8_t> sign_data;
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&time_slot_id), 
                     reinterpret_cast<const uint8_t*>(&time_slot_id) + 8);
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&t_start), 
                     reinterpret_cast<const uint8_t*>(&t_start) + 8);
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&proof.t_slot), 
                     reinterpret_cast<const uint8_t*>(&proof.t_slot) + 4);
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&current_rep), 
                     reinterpret_cast<const uint8_t*>(&current_rep) + 8);
    sign_data.insert(sign_data.end(), proof.random_r.begin(), proof.random_r.end());

    if (tee_enclave_sign(enclave_key, sign_data.data(), sign_data.size(), proof.enclave_sig) != 0) {
        return -1;
    }

    return 0;
}

int ProofBuilder::build_segment_credential(double rep_low, double rep_high,
                                          uint64_t epoch_start, uint64_t epoch_end,
                                          const std::vector<ProofPackage>& proofs_in_segment,
                                          SegmentCredential& seg_cred) {
    if (proofs_in_segment.empty()) {
        return -1;
    }
    
    seg_cred.rep_low = rep_low;
    seg_cred.rep_high = rep_high;
    seg_cred.epoch_start = epoch_start;
    seg_cred.epoch_end = epoch_end;

    // 1. 计算分段Merkle根（叶子：每个证明包的SHA3-256哈希）
    std::vector<std::array<uint8_t, 32>> proof_hashes;
    for (const auto& proof : proofs_in_segment) {
        std::array<uint8_t, 32> proof_hash;
        sha3_256_hash(reinterpret_cast<const uint8_t*>(&proof), sizeof(ProofPackage), proof_hash);
        proof_hashes.push_back(proof_hash);
    }
    MerkleTree seg_merkle(proof_hashes);
    seg_cred.seg_root = seg_merkle.get_root();

    // 2. 计算锚点哈希（首尾证明包哈希拼接）
    std::array<uint8_t, 32> first_hash, last_hash;
    sha3_256_hash(reinterpret_cast<const uint8_t*>(&proofs_in_segment[0]), sizeof(ProofPackage), first_hash);
    sha3_256_hash(reinterpret_cast<const uint8_t*>(&proofs_in_segment.back()), sizeof(ProofPackage), last_hash);
    memcpy(seg_cred.anchor_hash.data(), first_hash.data(), 32);
    memcpy(seg_cred.anchor_hash.data() + 32, last_hash.data(), 32);

    return 0;
}

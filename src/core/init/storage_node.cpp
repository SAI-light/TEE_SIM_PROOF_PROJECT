#include "storage_node.h"
#include "../../utils/crypto_utils.h"

int StorageNode::init_tee(EnclaveKeyPair& key_pair, std::vector<uint8_t>& report) {
    // 初始化飞地密钥对
    if (tee_init_key_pair(key_pair) != 0) {
        return -1;
    }
    
    // 生成远程证明报告
    if (tee_create_attestation(key_pair.pk, report) != 0) {
        return -1;
    }
    
    return 0;
}

int StorageNode::build_merkle_tree(const std::vector<EncryptedBlock>& blocks, MerkleTree& merkle_tree) {
    if (blocks.empty()) {
        return -1;
    }
    
    // 计算每个块的哈希
    std::vector<std::array<uint8_t, 32>> block_hashes;
    for (const auto& block : blocks) {
        block_hashes.push_back(hash_encrypted_block(block));
    }
    
    // 构建Merkle树
    merkle_tree = MerkleTree(block_hashes);
    return 0;
}

int StorageNode::store_blocks(const std::vector<EncryptedBlock>& blocks) {
    stored_blocks_ = blocks;
    return 0;
}

bool StorageNode::get_block(size_t index, EncryptedBlock& block) const {
    if (index >= stored_blocks_.size()) {
        return false;
    }
    
    block = stored_blocks_[index];
    return true;
}

size_t StorageNode::get_block_count() const {
    return stored_blocks_.size();
}

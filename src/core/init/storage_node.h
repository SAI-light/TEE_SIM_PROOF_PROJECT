#ifndef STORAGE_NODE_H
#define STORAGE_NODE_H

#include <vector>
#include <array>
#include <string>
#include "../../../include/common_type.h"
#include "../../tee_simulator/enclave_sign.h"
#include "../../tee_simulator/attestation_sim.h"
#include "../../utils/merkle_tree.h"

class StorageNode {
public:
    // 构造函数
    StorageNode() = default;
    
    // 析构函数
    ~StorageNode() = default;
    
    // 初始化TEE环境
    // key_pair: 输出飞地密钥对
    // report: 输出远程证明报告
    int init_tee(EnclaveKeyPair& key_pair, std::vector<uint8_t>& report);
    
    // 构建数据块的Merkle树
    // blocks: 加密的数据块
    // merkle_tree: 输出构建的Merkle树
    int build_merkle_tree(const std::vector<EncryptedBlock>& blocks, MerkleTree& merkle_tree);
    
    // 存储数据块
    int store_blocks(const std::vector<EncryptedBlock>& blocks);
    
    // 获取指定索引的数据块
    bool get_block(size_t index, EncryptedBlock& block) const;
    
    // 获取存储的数据块数量
    size_t get_block_count() const;

private:
    std::vector<EncryptedBlock> stored_blocks_; // 存储的数据块
};

#endif // STORAGE_NODE_H

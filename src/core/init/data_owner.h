#ifndef DATA_OWNER_H
#define DATA_OWNER_H

#include <vector>
#include <array>
#include <cstdint>
#include "../../../include/common_type.h"
#include "../../tee_simulator/random_source.h"
#include "../../utils/crypto_utils.h"
#include "../../utils/merkle_tree.h"  // 引入MerkleTree类定义

class DataOwner {
public:
    // 构造函数
    DataOwner() = default;
    
    // 析构函数
    ~DataOwner() = default;
    
    // 将原始文件分块并加密
    // raw_file: 原始文件数据
    // key: 加密密钥
    // encrypted_blocks: 输出加密后的块
    // file_fingerprint: 输出文件指纹（所有块哈希的哈希）
    int split_and_encrypt(const std::vector<uint8_t>& raw_file,
                         const std::array<uint8_t, 32>& key,
                         std::vector<EncryptedBlock>& encrypted_blocks,
                         std::array<uint8_t, 32>& file_fingerprint);
    
    // 验证存储节点返回的证明
    bool verify_proof(const ProofPackage& proof,
                     const std::array<uint8_t, 65>& enclave_pub_key,
                     const MerkleTree& merkle_tree);
};

#endif // DATA_OWNER_H

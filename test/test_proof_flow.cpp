#include <gtest/gtest.h>
#include "../src/core/init/data_owner.h"
#include "../src/core/init/storage_node.h"
#include "../src/core/proof_generator/proof_builder.h"
#include "../src/core/verifier/single_verifier.h"
#include "../src/blockchain_sim/reputation_contract.h"
#include "../src/utils/merkle_tree.h"
#include <vector>
#include <array>

TEST(ProofFlowTest, FullProofCycle) {
    // 1. 初始化组件
    DataOwner data_owner;
    StorageNode storage_node;
    ProofBuilder proof_builder;
    SingleVerifier verifier;
    ReputationContract rep_contract;
    
    // 2. 准备测试数据
    std::vector<uint8_t> raw_file(1024 * 10, 0xAA); // 10KB测试文件
    std::array<uint8_t, 32> aes_key;
    tee_get_random(aes_key.data(), 32);
    
    // 3. 数据拥有者分块并加密
    std::vector<EncryptedBlock> encrypted_blocks;
    std::array<uint8_t, 32> file_fingerprint;
    ASSERT_EQ(data_owner.split_and_encrypt(raw_file, aes_key, encrypted_blocks, file_fingerprint), 0);
    ASSERT_FALSE(encrypted_blocks.empty());
    
    // 4. 存储节点初始化
    EnclaveKeyPair enclave_key;
    std::vector<uint8_t> attestation_report;
    ASSERT_EQ(storage_node.init_tee(enclave_key, attestation_report), 0);
    
    // 5. 存储节点存储数据并构建Merkle树
    ASSERT_EQ(storage_node.store_blocks(encrypted_blocks), 0);
    MerkleTree merkle_tree;
    ASSERT_EQ(storage_node.build_merkle_tree(encrypted_blocks, merkle_tree), 0);
    
    // 6. 部署信誉合约
    ReputationParams rep_params;
    rep_contract.deploy(rep_params, "test_node");
    double initial_rep = rep_contract.get_reputation("test_node");
    
    // 7. 生成证明
    ProofPackage proof;
    std::array<uint8_t, 32> prev_hash = {0}; // 第一个证明包的前向哈希为0
    uint64_t current_time = get_current_timestamp();
    
    ASSERT_EQ(proof_builder.build_proof_package(enclave_key, merkle_tree,
                                               initial_rep, 0, current_time,
                                               prev_hash, encrypted_blocks.size(), proof), 0);
    
    // 8. 验证证明
    bool verification_result = verifier.verify(proof, enclave_key.pk,
                                              initial_rep, current_time, 30);
    EXPECT_TRUE(verification_result);
    
    // 9. 验证失败情况：篡改证明
    ProofPackage tampered_proof = proof;
    tampered_proof.challenge_idx = 9999; // 无效的索引
    
    verification_result = verifier.verify(tampered_proof, enclave_key.pk,
                                         initial_rep, current_time, 30);
    EXPECT_FALSE(verification_result);
}

TEST(ProofFlowTest, SegmentCredential) {
    // 1. 初始化组件
    StorageNode storage_node;
    ProofBuilder proof_builder;
    AggregateVerifier agg_verifier;
    
    // 2. 初始化存储节点
    EnclaveKeyPair enclave_key;
    std::vector<uint8_t> attestation_report;
    ASSERT_EQ(storage_node.init_tee(enclave_key, attestation_report), 0);
    
    // 3. 创建测试数据块
    std::vector<EncryptedBlock> blocks;
    for (int i = 0; i < 5; ++i) {
        EncryptedBlock block;
        block.iv.fill(i);
        block.ciphertext.resize(1024, i + 1);
        block.auth_tag.fill(i + 2);
        blocks.push_back(block);
    }
    ASSERT_EQ(storage_node.store_blocks(blocks), 0);
    
    // 4. 构建Merkle树
    MerkleTree merkle_tree;
    ASSERT_EQ(storage_node.build_merkle_tree(blocks, merkle_tree), 0);
    
    // 5. 生成多个证明包
    std::vector<ProofPackage> proofs;
    std::array<uint8_t, 32> prev_hash = {0};
    uint64_t current_time = get_current_timestamp();
    double rep = 0.5;
    
    for (uint64_t i = 0; i < 5; ++i) {
        ProofPackage proof;
        ASSERT_EQ(proof_builder.build_proof_package(enclave_key, merkle_tree,
                                                   rep, i, current_time,
                                                   prev_hash, blocks.size(), proof), 0);
        proofs.push_back(proof);
        
        // 更新前向哈希
        sha3_256_hash(reinterpret_cast<const uint8_t*>(&proof), sizeof(ProofPackage), prev_hash);
        
        // 更新时间
        current_time += 300000; // 5分钟（毫秒）
    }
    
    // 6. 生成分段凭证
    SegmentCredential credential;
    ASSERT_EQ(proof_builder.build_segment_credential(0.4, 0.6, 0, 4, proofs, credential), 0);
    
    // 7. 验证分段凭证
    EXPECT_TRUE(agg_verifier.verify({credential}, merkle_tree.get_root(), enclave_key.pk, blocks.size()));
    EXPECT_TRUE(agg_verifier.spot_check(credential, proofs, enclave_key.pk));
}

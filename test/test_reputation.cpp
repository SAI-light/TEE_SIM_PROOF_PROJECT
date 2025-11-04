#include <gtest/gtest.h>
#include "../src/blockchain_sim/reputation_contract.h"
#include "../src/blockchain_sim/verification_contract.h"
#include "../src/core/init/storage_node.h"
#include "../src/core/proof_generator/proof_builder.h"
#include "../src/utils/merkle_tree.h"
#include <vector>

TEST(ReputationTest, ReputationUpdates) {
    // 1. 初始化合约
    ReputationContract rep_contract;
    VerificationContract verify_contract;
    
    // 2. 部署合约
    ReputationParams params;
    rep_contract.deploy(params, "node1");
    verify_contract.deploy();
    
    // 3. 检查初始信誉
    EXPECT_EQ(rep_contract.get_reputation("node1"), params.init_rep);
    
    // 4. 初始化存储节点和证明生成器
    StorageNode storage_node;
    EnclaveKeyPair enclave_key;
    std::vector<uint8_t> report;
    ASSERT_EQ(storage_node.init_tee(enclave_key, report), 0);
    
    // 5. 创建测试数据
    std::vector<EncryptedBlock> blocks;
    for (int i = 0; i < 3; ++i) {
        EncryptedBlock block;
        block.iv.fill(i);
        block.ciphertext.resize(1024, i);
        block.auth_tag.fill(i);
        blocks.push_back(block);
    }
    storage_node.store_blocks(blocks);
    
    MerkleTree merkle_tree;
    storage_node.build_merkle_tree(blocks, merkle_tree);
    
    // 6. 生成有效证明并提交，应该提升信誉
    ProofBuilder proof_builder;
    ProofPackage valid_proof;
    std::array<uint8_t, 32> prev_hash = {0};
    uint64_t current_time = get_current_timestamp();
    
    ASSERT_EQ(proof_builder.build_proof_package(enclave_key, merkle_tree,
                                               rep_contract.get_reputation("node1"),
                                               0, current_time, prev_hash,
                                               blocks.size(), valid_proof), 0);
    
    double rep_before = rep_contract.get_reputation("node1");
    EXPECT_TRUE(verify_contract.submit_single_proof("node1", valid_proof, enclave_key.pk, rep_contract));
    EXPECT_GT(rep_contract.get_reputation("node1"), rep_before);
    
    // 7. 生成无效证明并提交，应该降低信誉
    ProofPackage invalid_proof = valid_proof;
    invalid_proof.challenge_idx = 999; // 无效索引
    
    rep_before = rep_contract.get_reputation("node1");
    EXPECT_FALSE(verify_contract.submit_single_proof("node1", invalid_proof, enclave_key.pk, rep_contract));
    EXPECT_LT(rep_contract.get_reputation("node1"), rep_before);
    
    // 8. 验证信誉边界
    // 连续提交失败，直到信誉达到最小值
    for (int i = 0; i < 10; ++i) {
        verify_contract.submit_single_proof("node1", invalid_proof, enclave_key.pk, rep_contract);
    }
    EXPECT_EQ(rep_contract.get_reputation("node1"), params.init_rep - 10 * 0.1);
    if (params.init_rep - 10 * 0.1 < 0) {
        EXPECT_EQ(rep_contract.get_reputation("node1"), 0.0);
    }
}

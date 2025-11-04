#include <gtest/gtest.h>
#include "../src/utils/merkle_tree.h"
#include "../src/utils/crypto_utils.h"
#include <vector>
#include <array>
#include <cstring>

TEST(MerkleTreeTest, BasicFunctionality) {
    // 创建测试数据
    std::vector<std::array<uint8_t, 32>> leaves;
    for (int i = 0; i < 4; ++i) {
        std::array<uint8_t, 32> leaf;
        memset(leaf.data(), i, 32);
        leaves.push_back(leaf);
    }
    
    // 构建Merkle树
    MerkleTree tree(leaves);
    
    // 验证根不为空
    std::array<uint8_t, 32> root = tree.get_root();
    std::array<uint8_t, 32> empty_root;
    empty_root.fill(0);
    EXPECT_NE(root, empty_root);
    
    // 验证证明生成和验证
    for (size_t i = 0; i < leaves.size(); ++i) {
        std::vector<std::pair<std::array<uint8_t, 32>, bool>> path;
        EXPECT_TRUE(tree.get_proof(i, path));
        EXPECT_TRUE(MerkleTree::verify_proof(leaves[i], path, root));
    }
}

TEST(MerkleTreeTest, OddNumberOfLeaves) {
    // 创建奇数个叶子节点
    std::vector<std::array<uint8_t, 32>> leaves;
    for (int i = 0; i < 3; ++i) {
        std::array<uint8_t, 32> leaf;
        memset(leaf.data(), i, 32);
        leaves.push_back(leaf);
    }
    
    // 构建Merkle树
    MerkleTree tree(leaves);
    
    // 验证证明
    for (size_t i = 0; i < leaves.size(); ++i) {
        std::vector<std::pair<std::array<uint8_t, 32>, bool>> path;
        EXPECT_TRUE(tree.get_proof(i, path));
        EXPECT_TRUE(MerkleTree::verify_proof(leaves[i], path, tree.get_root()));
    }
}

TEST(MerkleTreeTest, SingleLeaf) {
    // 单个叶子节点
    std::vector<std::array<uint8_t, 32>> leaves;
    std::array<uint8_t, 32> leaf;
    memset(leaf.data(), 0xAA, 32);
    leaves.push_back(leaf);
    
    MerkleTree tree(leaves);
    
    // 根应该等于叶子本身
    EXPECT_EQ(tree.get_root(), leaf);
    
    // 验证证明
    std::vector<std::pair<std::array<uint8_t, 32>, bool>> path;
    EXPECT_TRUE(tree.get_proof(0, path));
    EXPECT_TRUE(MerkleTree::verify_proof(leaf, path, tree.get_root()));
}

TEST(MerkleTreeTest, TamperedData) {
    std::vector<std::array<uint8_t, 32>> leaves;
    for (int i = 0; i < 4; ++i) {
        std::array<uint8_t, 32> leaf;
        memset(leaf.data(), i, 32);
        leaves.push_back(leaf);
    }
    
    MerkleTree tree(leaves);
    std::array<uint8_t, 32> root = tree.get_root();
    
    // 篡改数据
    std::array<uint8_t, 32> tampered_leaf = leaves[0];
    tampered_leaf[0] ^= 0x01; // 改变一个字节
    
    // 获取原始叶子的证明
    std::vector<std::pair<std::array<uint8_t, 32>, bool>> path;
    EXPECT_TRUE(tree.get_proof(0, path));
    
    // 验证篡改后的数据应该失败
    EXPECT_FALSE(MerkleTree::verify_proof(tampered_leaf, path, root));
}

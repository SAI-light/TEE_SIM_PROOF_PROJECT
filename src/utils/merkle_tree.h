#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <vector>
#include <array>
#include <cstdint>

// Merkle树类
class MerkleTree {
public:
    //添加默认构造函数
    MerkleTree() = default;
    // 初始化：输入所有叶子节点的哈希（每个叶子为SHA-256哈希）
    MerkleTree(const std::vector<std::array<uint8_t, 32>>& leaf_hashes);

    // 获取Merkle根
    std::array<uint8_t, 32> get_root() const;

    // 获取指定叶子的Merkle路径（路径：从叶子到根的哈希序列，包含方向标记）
    // leaf_idx: 叶子索引（0-based），path: 输出路径（每个元素：哈希+方向（0=左，1=右））
    bool get_proof(size_t leaf_idx, std::vector<std::pair<std::array<uint8_t, 32>, bool>>& path) const;

    // 验证叶子哈希是否属于Merkle树
    static bool verify_proof(const std::array<uint8_t, 32>& leaf_hash,
                             const std::vector<std::pair<std::array<uint8_t, 32>, bool>>& path,
                             const std::array<uint8_t, 32>& root_hash);

private:
    std::vector<std::vector<std::array<uint8_t, 32>>> layers_; // Merkle树各层
};

#endif // MERKLE_TREE_H

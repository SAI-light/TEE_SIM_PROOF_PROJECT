#include "merkle_tree.h"
#include "crypto_utils.h"
#include <cstring>
#include <stdexcept>

MerkleTree::MerkleTree(const std::vector<std::array<uint8_t, 32>>& leaf_hashes) {
    if (leaf_hashes.empty()) return;
    
    // 初始化叶子层
    layers_.push_back(leaf_hashes);
    
    // 构建上层节点（每层哈希两两合并）
    while (layers_.back().size() > 1) {
        const auto& prev_layer = layers_.back();
        std::vector<std::array<uint8_t, 32>> curr_layer;
        
        for (size_t i = 0; i < prev_layer.size(); i += 2) {
            std::array<uint8_t, 64> combined;
            
            if (i + 1 < prev_layer.size()) {
                // 合并两个节点（左+右）
                memcpy(combined.data(), prev_layer[i].data(), 32);
                memcpy(combined.data() + 32, prev_layer[i + 1].data(), 32);
            } else {
                // 奇数节点：复制自身（补全）
                memcpy(combined.data(), prev_layer[i].data(), 32);
                memcpy(combined.data() + 32, prev_layer[i].data(), 32);
            }
            
            // 计算SHA-256哈希作为父节点
            std::array<uint8_t, 32> parent_hash;
            sha256_hash(combined.data(), 64, parent_hash);
            curr_layer.push_back(parent_hash);
        }
        
        layers_.push_back(curr_layer);
    }
}

std::array<uint8_t, 32> MerkleTree::get_root() const {
    return layers_.empty() ? std::array<uint8_t, 32>() : layers_.back()[0];
}

bool MerkleTree::get_proof(size_t leaf_idx, std::vector<std::pair<std::array<uint8_t, 32>, bool>>& path) const {
    path.clear();
    
    if (layers_.empty() || leaf_idx >= layers_[0].size()) {
        return false;
    }
    
    size_t current_idx = leaf_idx;
    
    // 从叶子层向上遍历到根的下一层
    for (size_t i = 0; i < layers_.size() - 1; ++i) {
        const auto& current_layer = layers_[i];
        size_t sibling_idx = (current_idx % 2 == 0) ? current_idx + 1 : current_idx - 1;
        
        // 检查兄弟节点是否存在
        if (sibling_idx < current_layer.size()) {
            // 方向：true表示当前节点在左，兄弟节点在右
            bool is_left = (current_idx % 2 == 0);
            path.emplace_back(current_layer[sibling_idx], is_left);
        } else {
            // 没有兄弟节点，使用当前节点作为兄弟（补全情况）
            path.emplace_back(current_layer[current_idx], true);
        }
        
        // 计算上一层的索引
        current_idx = current_idx / 2;
    }
    
    return true;
}

bool MerkleTree::verify_proof(const std::array<uint8_t, 32>& leaf_hash,
                             const std::vector<std::pair<std::array<uint8_t, 32>, bool>>& path,
                             const std::array<uint8_t, 32>& root_hash) {
    std::array<uint8_t, 32> current_hash = leaf_hash;
    
    for (const auto& [sibling_hash, is_left] : path) {
        std::array<uint8_t, 64> combined;
        
        if (is_left) {
            // 当前节点在左，兄弟节点在右
            memcpy(combined.data(), current_hash.data(), 32);
            memcpy(combined.data() + 32, sibling_hash.data(), 32);
        } else {
            // 当前节点在右，兄弟节点在左
            memcpy(combined.data(), sibling_hash.data(), 32);
            memcpy(combined.data() + 32, current_hash.data(), 32);
        }
        
        // 计算父节点哈希
        sha256_hash(combined.data(), 64, current_hash);
    }
    
    // 检查计算得到的根是否与提供的根匹配
    return memcmp(current_hash.data(), root_hash.data(), 32) == 0;
}

#ifndef CHALLENGE_H
#define CHALLENGE_H

#include <cstdint>
#include <array>
#include <vector>
#include "../../../include/common_type.h"
#include "../../tee_simulator/random_source.h"

class ChallengeGenerator {
public:
    // 构造函数
    ChallengeGenerator() = default;
    
    // 析构函数
    ~ChallengeGenerator() = default;
    
    // 生成挑战随机数
    int generate_random_challenge(std::array<uint8_t, 32>& challenge);
    
    // 根据挑战随机数和总块数计算挑战块索引
    uint32_t calculate_challenge_index(const std::array<uint8_t, 32>& challenge, size_t total_blocks);
    
    // 批量生成挑战
    int generate_batch_challenges(size_t count, size_t total_blocks, 
                                 std::vector<std::pair<std::array<uint8_t, 32>, uint32_t>>& challenges);
};

#endif // CHALLENGE_H

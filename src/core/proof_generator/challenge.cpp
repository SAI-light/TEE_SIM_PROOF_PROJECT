#include "challenge.h"
#include <cstring>

int ChallengeGenerator::generate_random_challenge(std::array<uint8_t, 32>& challenge) {
    return tee_get_random(challenge.data(), 32);
}

uint32_t ChallengeGenerator::calculate_challenge_index(const std::array<uint8_t, 32>& challenge, size_t total_blocks) {
    if (total_blocks == 0) return 0;
    
    // 使用挑战随机数的前4字节作为uint32_t值
    uint32_t rand_val;
    memcpy(&rand_val, challenge.data(), sizeof(uint32_t));
    
    // 计算索引：i = rand_val mod total_blocks
    return rand_val % static_cast<uint32_t>(total_blocks);
}

int ChallengeGenerator::generate_batch_challenges(size_t count, size_t total_blocks, 
                                                std::vector<std::pair<std::array<uint8_t, 32>, uint32_t>>& challenges) {
    challenges.clear();
    challenges.reserve(count);
    
    for (size_t i = 0; i < count; ++i) {
        std::array<uint8_t, 32> challenge;
        if (generate_random_challenge(challenge) != 0) {
            return -1;
        }
        
        uint32_t index = calculate_challenge_index(challenge, total_blocks);
        challenges.emplace_back(challenge, index);
    }
    
    return 0;
}

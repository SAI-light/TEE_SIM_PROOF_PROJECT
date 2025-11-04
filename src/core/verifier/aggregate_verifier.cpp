#include "aggregate_verifier.h"
#include "../proof_generator/challenge.h"
#include "single_verifier.h"
#include "../../utils/crypto_utils.h"
#include "../../utils/merkle_tree.h"
#include "../../utils/time_utils.h"
#include <random>
#include <chrono>

bool AggregateVerifier::verify(const std::vector<SegmentCredential>& credentials,
                              const std::array<uint8_t, 32>& data_root,
                              const std::array<uint8_t, 65>& enclave_pub_key,
                              size_t total_blocks) {
    if (credentials.empty()) {
        return false;
    }
    
    // 1. 验证分段的连续性
    uint64_t last_end = 0;
    for (size_t i = 0; i < credentials.size(); ++i) {
        const auto& cred = credentials[i];
        
        // 第一个分段应该从0开始
        if (i == 0 && cred.epoch_start != 0) {
            return false;
        }
        
        // 后续分段应该紧接上一个分段
        if (i > 0 && cred.epoch_start != last_end + 1) {
            return false;
        }
        
        // 分段的开始应该小于等于结束
        if (cred.epoch_start > cred.epoch_end) {
            return false;
        }
        
        last_end = cred.epoch_end;
    }
    
    // 2. 验证信誉区间的合理性
    double last_high = -1.0;
    for (const auto& cred : credentials) {
        // 信誉值应该在有效范围内
        if (cred.rep_low < 0.0 || cred.rep_high > 1.0 || cred.rep_low > cred.rep_high) {
            return false;
        }
        
        // 信誉区间应该有合理的重叠或连续性
        if (last_high >= 0.0 && cred.rep_low > last_high + 0.001) {
            return false;
        }
        
        last_high = cred.rep_high;
    }
    
    return true;
}

bool AggregateVerifier::spot_check(const SegmentCredential& credential,
                                  const std::vector<ProofPackage>& proofs_in_segment,
                                  const std::array<uint8_t, 65>& enclave_pub_key,
                                  size_t check_count) {
    if (proofs_in_segment.empty() || check_count == 0) {
        return false;
    }
    
    // 1. 验证分段Merkle根
    std::vector<std::array<uint8_t, 32>> proof_hashes;
    for (const auto& proof : proofs_in_segment) {
        std::array<uint8_t, 32> proof_hash;
        sha3_256_hash(reinterpret_cast<const uint8_t*>(&proof), sizeof(ProofPackage), proof_hash);
        proof_hashes.push_back(proof_hash);
    }
    
    MerkleTree seg_merkle(proof_hashes);
    if (seg_merkle.get_root() != credential.seg_root) {
        return false;
    }
    
    // 2. 验证锚点哈希
    std::array<uint8_t, 32> first_hash, last_hash;
    sha3_256_hash(reinterpret_cast<const uint8_t*>(&proofs_in_segment[0]), sizeof(ProofPackage), first_hash);
    sha3_256_hash(reinterpret_cast<const uint8_t*>(&proofs_in_segment.back()), sizeof(ProofPackage), last_hash);
    
    std::array<uint8_t, 64> computed_anchor;
    memcpy(computed_anchor.data(), first_hash.data(), 32);
    memcpy(computed_anchor.data() + 32, last_hash.data(), 32);
    
    if (computed_anchor != credential.anchor_hash) {
        return false;
    }
    
    // 3. 随机抽查部分证明
    SingleVerifier single_verifier;
    size_t num_to_check = std::min(check_count, proofs_in_segment.size());
    
    // 使用当前时间作为随机种子
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine generator(seed);
    std::uniform_int_distribution<size_t> distribution(0, proofs_in_segment.size() - 1);
    
    for (size_t i = 0; i < num_to_check; ++i) {
        size_t idx = distribution(generator);
        const auto& proof = proofs_in_segment[idx];
        
        // 验证单个证明
        uint64_t current_time = get_current_timestamp();
        if (!single_verifier.verify(proof, enclave_pub_key, 
                                   (credential.rep_low + credential.rep_high) / 2,
                                   current_time, 30)) {
            return false;
        }
    }
    
    return true;
}

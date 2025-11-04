#ifndef PROOF_BUILDER_H
#define PROOF_BUILDER_H

#include <vector>
#include <array>
#include <cstdint>
#include "../../../include/common_type.h"
#include "../../tee_simulator/enclave_sign.h"
#include "../../utils/merkle_tree.h"

class ProofBuilder {
public:
    // 构造函数
    ProofBuilder() = default;
    
    // 析构函数
    ~ProofBuilder() = default;
    
    // 构建链式证明包
    int build_proof_package(const EnclaveKeyPair& enclave_key,
                           const MerkleTree& merkle_tree,
                           double current_rep,
                           uint64_t time_slot_id,
                           uint64_t t_start,
                           const std::array<uint8_t, 32>& prev_proof_hash,
                           size_t total_blocks,
                           ProofPackage& proof);
    
    // 生成信誉分段凭证（当信誉变化超阈值时）
    int build_segment_credential(double rep_low, double rep_high,
                                uint64_t epoch_start, uint64_t epoch_end,
                                const std::vector<ProofPackage>& proofs_in_segment,
                                SegmentCredential& seg_cred);
};

#endif // PROOF_BUILDER_H

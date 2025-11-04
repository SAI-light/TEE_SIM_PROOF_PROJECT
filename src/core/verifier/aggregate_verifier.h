#ifndef AGGREGATE_VERIFIER_H
#define AGGREGATE_VERIFIER_H

#include <vector>
#include <array>
#include <cstdint>
#include "../../../include/common_type.h"
#include "../../tee_simulator/enclave_sign.h"
#include "../../utils/merkle_tree.h"

class AggregateVerifier {
public:
    // 构造函数
    AggregateVerifier() = default;
    
    // 析构函数
    ~AggregateVerifier() = default;
    
    // 验证分段凭证
    // credentials: 待验证的分段凭证列表
    // data_root: 数据的Merkle根
    // enclave_pub_key: 飞地公钥
    // total_blocks: 总数据块数
    bool verify(const std::vector<SegmentCredential>& credentials,
               const std::array<uint8_t, 32>& data_root,
               const std::array<uint8_t, 65>& enclave_pub_key,
               size_t total_blocks);
    
    // 抽查验证：从分段中随机选择部分证明进行验证
    bool spot_check(const SegmentCredential& credential,
                   const std::vector<ProofPackage>& proofs_in_segment,
                   const std::array<uint8_t, 65>& enclave_pub_key,
                   size_t check_count = 3);
};

#endif // AGGREGATE_VERIFIER_H

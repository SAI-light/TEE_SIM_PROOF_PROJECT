#ifndef SINGLE_VERIFIER_H
#define SINGLE_VERIFIER_H

#include <cstdint>
#include <array>
#include "../../../include/common_type.h"
#include "../../tee_simulator/enclave_sign.h"
#include "../../utils/merkle_tree.h"

class SingleVerifier {
public:
    // 构造函数
    SingleVerifier() = default;
    
    // 析构函数
    ~SingleVerifier() = default;
    
    // 验证单次证明
    // proof: 待验证的证明包
    // enclave_pub_key: 飞地公钥
    // current_rep: 当前信誉值
    // submit_time: 证明提交时间戳
    // max_delay: 最大网络延迟（秒）
    bool verify(const ProofPackage& proof,
               const std::array<uint8_t, 65>& enclave_pub_key,
               double current_rep,
               uint64_t submit_time,
               uint32_t max_delay);
};

#endif // SINGLE_VERIFIER_H

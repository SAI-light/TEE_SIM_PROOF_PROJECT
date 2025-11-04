#include "single_verifier.h"
#include "../../tee_simulator/enclave_sign.h"
#include "../../utils/time_utils.h"
#include "../../utils/crypto_utils.h"
#include "../../utils/merkle_tree.h"
#include "../../../include/config.h"
#include <cmath>

bool SingleVerifier::verify(const ProofPackage& proof,
                           const std::array<uint8_t, 65>& enclave_pub_key,
                           double current_rep,
                           uint64_t submit_time,
                           uint32_t max_delay) {
    // 1. 验证签名
    std::vector<uint8_t> sign_data;
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&proof.time_slot_id), 
                     reinterpret_cast<const uint8_t*>(&proof.time_slot_id) + 8);
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&proof.t_start), 
                     reinterpret_cast<const uint8_t*>(&proof.t_start) + 8);
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&proof.t_slot), 
                     reinterpret_cast<const uint8_t*>(&proof.t_slot) + 4);
    sign_data.insert(sign_data.end(), reinterpret_cast<const uint8_t*>(&proof.rep_snapshot), 
                     reinterpret_cast<const uint8_t*>(&proof.rep_snapshot) + 8);
    sign_data.insert(sign_data.end(), proof.random_r.begin(), proof.random_r.end());
    
    if (!tee_verify_signature(enclave_pub_key, sign_data.data(), sign_data.size(), proof.enclave_sig)) {
        return false;
    }
    
    // 2. 验证时间有效性
    if (!is_time_valid(proof.t_start, proof.t_slot, submit_time, max_delay)) {
        return false;
    }
    
    // 3. 验证信誉快照与当前信誉的一致性（允许一定范围内的波动）
    if (fabs(proof.rep_snapshot - current_rep) > Config::DELTA_REP) {
        return false;
    }
    
    // 4. 验证时间槽长度是否与信誉匹配
    uint32_t expected_slot = static_cast<uint32_t>(Config::T_MIN + 
                                                  (Config::T_MAX - Config::T_MIN) * (1 - proof.rep_snapshot));
    // 允许微小的计算误差
    if (abs(static_cast<int>(proof.t_slot) - static_cast<int>(expected_slot)) > 1) {
        return false;
    }
    
    // 5. 验证Merkle路径格式（实际验证需要挑战块的哈希）
    // 这里只验证路径格式是否正确
    if (proof.merkle_path.size() % 33 != 0) {
        return false; // 每个路径元素应该是32字节哈希 + 1字节方向标记
    }
    
    return true;
}

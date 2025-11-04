#ifndef COMMON_TYPE_H
#define COMMON_TYPE_H

#include <vector>
#include <array>
#include <string>
#include <cstdint>

// 1. 加密数据块结构体
struct EncryptedBlock {
    std::vector<uint8_t> ciphertext;  // 密文（AES-GCM）
    std::array<uint8_t, 12> iv;       // 初始化向量（96位）
    std::array<uint8_t, 16> auth_tag; // 认证标签（128位）
};

// 2. 证明包结构体（链式）
struct ProofPackage {
    uint64_t time_slot_id;            // 时间槽ID
    std::array<uint8_t, 32> prev_hash;// 链式指针（SHA3-256(前一个证明包)）
    double rep_snapshot;              // 信誉快照
    uint32_t t_slot;                  // 时间槽长度（秒）
    std::array<uint8_t, 32> random_r; // 挑战随机数（256位）
    uint32_t challenge_idx;           // 挑战块索引
    std::vector<uint8_t> merkle_path; // Merkle路径（验证证据）
    std::array<uint8_t, 64> enclave_sig; // 飞地签名（ECC-Secp256k1）
    uint64_t t_start;                 // 时间槽起点（时间戳）
};

// 3. 分段凭证结构体
struct SegmentCredential {
    double rep_low;                   // 信誉区间下限
    double rep_high;                  // 信誉区间上限
    uint64_t epoch_start;             // 时间槽范围起点
    uint64_t epoch_end;               // 时间槽范围终点
    std::array<uint8_t, 32> seg_root; // 分段Merkle根（SHA3-256）
    std::array<uint8_t, 64> anchor_hash; // 锚点哈希（首尾证明包哈希拼接）
};

// 4. 信誉合约参数结构体
struct ReputationParams {
    double init_rep = 0.5;            // 初始信誉分
    double delta_rep = 0.1;           // 信誉变化阈值
    uint32_t t_min = 300;             // 最小时间槽（5分钟，秒）
    uint32_t t_max = 86400;           // 最大时间槽（24小时，秒）
};

#endif // COMMON_TYPE_H

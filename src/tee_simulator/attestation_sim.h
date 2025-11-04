#ifndef ATTESTATION_SIM_H
#define ATTESTATION_SIM_H

#include <vector>
#include <array>
#include <cstdint>

// 模拟远程证明：生成EPID签名的证明报告（后期替换为SGX的sgx_create_attestation_report）
// pub_key: 飞地公钥，report: 输出证明报告
int tee_create_attestation(const std::array<uint8_t, 65>& pub_key, std::vector<uint8_t>& report);

// 验证远程证明（模拟：直接返回成功，后期替换为SGX验证逻辑）
int tee_verify_attestation(const std::vector<uint8_t>& report, const std::array<uint8_t, 65>& pub_key);

#endif // ATTESTATION_SIM_H

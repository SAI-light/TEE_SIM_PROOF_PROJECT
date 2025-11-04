#include "attestation_sim.h"
#include <cstring>
#include <cstdint>

// 模拟生成EPID证明报告（格式：[报告类型(1字节)+公钥(65字节)+模拟签名(64字节)]）
int tee_create_attestation(const std::array<uint8_t, 65>& pub_key, std::vector<uint8_t>& report) {
    report.clear();
    report.push_back(0x01); // 模拟报告类型
    report.insert(report.end(), pub_key.begin(), pub_key.end());
    report.resize(report.size() + 64, 0xAA); // 模拟EPID签名
    return 0;
}

// 模拟验证：仅检查报告长度和公钥一致性
int tee_verify_attestation(const std::vector<uint8_t>& report, const std::array<uint8_t, 65>& pub_key) {
    if (report.size() != 1 + 65 + 64) return -1;
    // 检查公钥是否匹配
    for (size_t i = 0; i < 65; ++i) {
        if (report[1 + i] != pub_key[i]) return -1;
    }
    return 0; // 模拟验证通过
}

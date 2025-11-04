#ifndef ENCLAVE_SIGN_H
#define ENCLAVE_SIGN_H

#include <cstdint>
#include <cstddef>
#include <array>

// 飞地密钥对（模拟：实际SGX中密钥存储在飞地内，不可泄露）
struct EnclaveKeyPair {
    std::array<uint8_t, 32> sk; // 私钥（256位）
    std::array<uint8_t, 65> pk; // 公钥（65位，非压缩格式）
};

// 初始化飞地密钥对（后期替换为SGX的密钥生成）
int tee_init_key_pair(EnclaveKeyPair& key_pair);

// 飞地签名（后期替换为SGX的sgx_ecdsa_sign）
// data: 待签名数据，len: 数据长度，sig: 输出签名（64位）
int tee_enclave_sign(const EnclaveKeyPair& key_pair, const uint8_t* data, size_t len, std::array<uint8_t, 64>& sig);

// 验证飞地签名
bool tee_verify_signature(const std::array<uint8_t, 65>& pub_key, const uint8_t* data, size_t len, const std::array<uint8_t, 64>& sig);

#endif // ENCLAVE_SIGN_H

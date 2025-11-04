#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <array>
#include <cstdint>
#include "D:\Code\C\tee_sim_proof_project\include\common_type.h"

// AES-GCM加密（方案：数据块加密）
int aes_gcm_encrypt(const std::array<uint8_t, 32>& key, // 256位密钥
                    const std::vector<uint8_t>& plaintext,
                    const std::array<uint8_t, 12>& iv,   // 96位IV
                    std::vector<uint8_t>& ciphertext,
                    std::array<uint8_t, 16>& auth_tag);  // 128位认证标签

// AES-GCM解密
int aes_gcm_decrypt(const std::array<uint8_t, 32>& key,
                    const std::vector<uint8_t>& ciphertext,
                    const std::array<uint8_t, 12>& iv,
                    const std::array<uint8_t, 16>& auth_tag,
                    std::vector<uint8_t>& plaintext);

// SHA-256哈希
void sha256_hash(const uint8_t* data, size_t len, std::array<uint8_t, 32>& hash_out);

// SHA3-256哈希（用于链式指针）
void sha3_256_hash(const uint8_t* data, size_t len, std::array<uint8_t, 32>& hash_out);

// 计算数据块的哈希（用于Merkle树叶子）
std::array<uint8_t, 32> hash_encrypted_block(const EncryptedBlock& block);

#endif // CRYPTO_UTILS_H

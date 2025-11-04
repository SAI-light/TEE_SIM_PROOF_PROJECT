#include "crypto_utils.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <cstring>
#include <iostream>
#include "../../include/common_type.h"

int aes_gcm_encrypt(const std::array<uint8_t, 32>& key,
                    const std::vector<uint8_t>& plaintext,
                    const std::array<uint8_t, 12>& iv,
                    std::vector<uint8_t>& ciphertext,
                    std::array<uint8_t, 16>& auth_tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    ciphertext.resize(plaintext.size());
    int len = 0, cipher_len = 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) ||
        !EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipher_len += len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    cipher_len += len;
    ciphertext.resize(cipher_len);

    // 获取认证标签
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, auth_tag.data());
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aes_gcm_decrypt(const std::array<uint8_t, 32>& key,
                    const std::vector<uint8_t>& ciphertext,
                    const std::array<uint8_t, 12>& iv,
                    const std::array<uint8_t, 16>& auth_tag,
                    std::vector<uint8_t>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    plaintext.resize(ciphertext.size());
    int len = 0, plain_len = 0;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) ||
        !EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plain_len += len;

    // 设置认证标签
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(auth_tag.data()));

    // 完成解密，检查认证
    if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // 认证失败
    }
    plain_len += len;
    plaintext.resize(plain_len);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// void sha256_hash(const uint8_t* data, size_t len, std::array<uint8_t, 32>& hash_out) {
//     SHA256_CTX ctx;
//     SHA256_Init(&ctx);
//     SHA256_Update(&ctx, data, len);
//     SHA256_Final(hash_out.data(), &ctx);
// }
void sha256_hash(const uint8_t* data, size_t len, std::array<unsigned char, 32>& hash_out) {
    // 1. 创建并初始化哈希上下文
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "SHA256 上下文创建失败" << std::endl;
        return;
    }

    // 2. 初始化 SHA256 哈希（使用默认 provider）
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        std::cerr << "SHA256 初始化失败" << std::endl;
        EVP_MD_CTX_free(ctx);
        return;
    }

    // 3. 传入数据计算哈希
    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        std::cerr << "SHA256 数据更新失败" << std::endl;
        EVP_MD_CTX_free(ctx);
        return;
    }

    // 4. 获取最终哈希结果（len 会自动设为 32）
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash_out.data(), &hash_len) != 1) {
        std::cerr << "SHA256 结果获取失败" << std::endl;
    }

    // 5. 释放上下文（避免内存泄漏）
    EVP_MD_CTX_free(ctx);
}

void sha3_256_hash(const uint8_t* data, size_t len, std::array<uint8_t, 32>& hash_out) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, hash_out.data(), nullptr);
    EVP_MD_CTX_free(ctx);
}

std::array<uint8_t, 32> hash_encrypted_block(const EncryptedBlock& block) {
    std::vector<uint8_t> data;
    // 合并IV、密文和认证标签进行哈希
    data.insert(data.end(), block.iv.begin(), block.iv.end());
    data.insert(data.end(), block.ciphertext.begin(), block.ciphertext.end());
    data.insert(data.end(), block.auth_tag.begin(), block.auth_tag.end());
    
    std::array<uint8_t, 32> hash;
    sha256_hash(data.data(), data.size(), hash);
    return hash;
}

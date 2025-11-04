#include "enclave_sign.h"
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>

// 初始化飞地密钥对（使用OpenSSL 3.0+推荐的EVP接口）
int tee_init_key_pair(EnclaveKeyPair& key_pair) {
    // 1. 加载 legacy provider（解决旧曲线兼容性问题）
    OSSL_PROVIDER* legacy = OSSL_PROVIDER_load(nullptr, "legacy");
    if (!legacy) {
        std::cerr << "[错误] 加载 legacy provider 失败（OpenSSL错误：" << ERR_error_string(ERR_get_error(), nullptr) << "）" << std::endl;
        return -1;
    }

    // 2. 验证曲线是否支持（通过创建曲线组）
    int nid = NID_X9_62_prime256v1;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
    if (!group) {
        std::cerr << "[错误] OpenSSL 不支持 secp256r1 曲线（OpenSSL错误：" << ERR_error_string(ERR_get_error(), nullptr) << "）" << std::endl;
        OSSL_PROVIDER_unload(legacy);
        return -1;
    }
    EC_GROUP_free(group);

    // 3. 创建EVP_PKEY上下文
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!pctx) {
        std::cerr << "[错误] 创建EVP_PKEY_CTX失败（OpenSSL错误：" << ERR_error_string(ERR_get_error(), nullptr) << "）" << std::endl;
        OSSL_PROVIDER_unload(legacy);
        return -1;
    }

    // 4. 初始化密钥生成
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        std::cerr << "[错误] 初始化密钥生成失败（OpenSSL错误：" << ERR_error_string(ERR_get_error(), nullptr) << "）" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        OSSL_PROVIDER_unload(legacy);
        return -1;
    }

    // 5. 设置曲线参数
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0) {
        std::cerr << "[错误] 设置曲线参数失败（OpenSSL错误：" << ERR_error_string(ERR_get_error(), nullptr) << "）" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        OSSL_PROVIDER_unload(legacy);
        return -1;
    }

    // 6. 生成密钥对
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        std::cerr << "[错误] 生成EC密钥对失败（OpenSSL错误：" << ERR_error_string(ERR_get_error(), nullptr) << "）" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        OSSL_PROVIDER_unload(legacy);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    // 新增：验证生成的密钥是否为EC类型
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        std::cerr << "[错误] 生成的密钥不是EC类型（实际类型：" << EVP_PKEY_base_id(pkey) << "）" << std::endl;
        EVP_PKEY_free(pkey);
        OSSL_PROVIDER_unload(legacy);
        return -1;
    }

    // 7. 提取私钥（32字节）
    size_t sk_len = 32;//key_pair.sk.size();
    // 新增：检查密钥是否有效
    if (EVP_PKEY_size(pkey) == 0) {
        std::cerr << "[错误] 生成的密钥无效" << std::endl;
        EVP_PKEY_free(pkey);
        OSSL_PROVIDER_unload(legacy);
        return -1;
    }
    if (EVP_PKEY_get_raw_private_key(pkey, key_pair.sk.data(), &sk_len) <= 0) {
        unsigned long err_code = ERR_get_error();
        std::cerr << "[错误] 私钥提取失败（错误码：" << err_code << "，信息：" << ERR_error_string(err_code, nullptr) << "）" << std::endl;
        //std::cerr << "[错误] 私钥提取失败（OpenSSL错误：" << ERR_error_string(ERR_get_error(), nullptr) << "）" << std::endl;
        EVP_PKEY_free(pkey);
        OSSL_PROVIDER_unload(legacy);
        return -1;
    }
    if (sk_len != 32) {
        std::cerr << "[错误] 私钥长度错误（实际：" << sk_len << "，预期：32）" << std::endl;
        EVP_PKEY_free(pkey);
        OSSL_PROVIDER_unload(legacy);
        return -1;
    }

    // 8. 提取公钥（65字节）
    size_t pk_len = key_pair.pk.size();
    if (EVP_PKEY_get_raw_public_key(pkey, key_pair.pk.data(), &pk_len) <= 0) {
        std::cerr << "[错误] 公钥提取失败（OpenSSL错误：" << ERR_error_string(ERR_get_error(), nullptr) << "）" << std::endl;
        EVP_PKEY_free(pkey);
        OSSL_PROVIDER_unload(legacy);
        return -1;
    }
    if (pk_len != 65) {
        std::cerr << "[错误] 公钥长度错误（实际：" << pk_len << "，预期：65）" << std::endl;
        EVP_PKEY_free(pkey);
        OSSL_PROVIDER_unload(legacy);
        return -1;
    }

    // 9. 清理资源
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(legacy);
    return 0;
}

int tee_enclave_sign(const EnclaveKeyPair& key_pair, const uint8_t* data, size_t data_len, std::array<unsigned char, 64>& sig) {
    // 1. 从私钥创建EVP_PKEY对象
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_EC, nullptr, key_pair.sk.data(), 32);
    if (!pkey) {
        std::cerr << "私钥加载失败" << std::endl;
        return -1;
    }

    // 2. 创建签名上下文
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "签名上下文创建失败" << std::endl;
        EVP_PKEY_free(pkey);
        return -1;
    }

    // 3. 初始化ECDSA-SHA256签名
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
        std::cerr << "签名初始化失败" << std::endl;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // 4. 传入待签名数据
    if (EVP_DigestSignUpdate(ctx, data, data_len) != 1) {
        std::cerr << "签名数据更新失败" << std::endl;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // 5. 获取签名结果（ECDSA签名：r(32) + s(32) → 64字节）
    size_t sig_len = sig.size();
    if (EVP_DigestSignFinal(ctx, sig.data(), &sig_len) != 1 || sig_len != 64) {
        std::cerr << "签名生成失败" << std::endl;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // 6. 释放资源
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
}

bool tee_verify_signature(const std::array<unsigned char, 65>& pub_key, const uint8_t* data, size_t data_len, const std::array<unsigned char, 64>& sig) {
    // 1. 从公钥创建EVP_PKEY对象
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_EC, nullptr, pub_key.data(), 65);
    if (!pkey) {
        std::cerr << "公钥加载失败" << std::endl;
        return false;
    }

    // 2. 创建验证上下文
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "验证上下文创建失败" << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }

    // 3. 初始化ECDSA-SHA256验证
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
        std::cerr << "验证初始化失败" << std::endl;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    // 4. 传入待验证数据
    if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1) {
        std::cerr << "验证数据更新失败" << std::endl;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    // 5. 执行验证（成功返回1，失败返回0）
    int verify_ret = EVP_DigestVerifyFinal(ctx, sig.data(), sig.size());

    // 6. 释放资源
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return (verify_ret == 1);
}
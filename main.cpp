#include <windows.h>
#include <iostream>
#include <vector>
#include <array>
#include <iomanip>
#include <openssl/ssl.h>
#include "include/common_type.h"
#include "include/config.h"
#include "src/core/init/data_owner.h"
#include "src/core/init/storage_node.h"
#include "src/core/proof_generator/challenge.h"
#include "src/core/proof_generator/proof_builder.h"
#include "src/core/proof_generator/time_slot.h"
#include "src/core/verifier/single_verifier.h"
#include "src/core/verifier/aggregate_verifier.h"
#include "src/blockchain_sim/reputation_contract.h"
#include "src/blockchain_sim/verification_contract.h"
#include "src/utils/crypto_utils.h"
#include "src/utils/merkle_tree.h"
#include "src/utils/time_utils.h"
#include <cmath>

// 打印字节数组的辅助函数
void print_bytes(const uint8_t* data, size_t len, const std::string& prefix = "") {
    if (!prefix.empty()) {
        std::cout << prefix << ": ";
    }
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    // 初始化 OpenSSL 库（必须放在所有 OpenSSL 操作之前）
    OPENSSL_init_ssl(0, nullptr);
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nullptr);

    // 新增：设置控制台为 UTF-8 编码，解决中文乱码
    SetConsoleOutputCP(CP_UTF8);
    std::cout << "=== 基于TEE模拟的动态信誉存储时间证明实验 ===" << std::endl;

    // 1. 初始化阶段
    DataOwner data_owner;
    StorageNode storage_node;
    ReputationContract rep_contract;
    VerificationContract verify_contract;

    // 1.1 数据拥有者：文件分块+加密+合约部署
    std::vector<uint8_t> raw_file(10240, 0x01); // 模拟10KB文件
    std::vector<EncryptedBlock> encrypted_blocks;
    std::array<uint8_t, 32> file_fingerprint;
    std::array<uint8_t, 32> aes_key;
    tee_get_random(aes_key.data(), 32); // 生成AES密钥

    if (data_owner.split_and_encrypt(raw_file, aes_key, encrypted_blocks, file_fingerprint) != 0) {
        std::cerr << "文件分块加密失败！" << std::endl;
        return -1;
    }
    std::cout << "\n1. 文件分块完成（" << encrypted_blocks.size() << "块），文件指纹：";
    print_bytes(file_fingerprint.data(), 32);

    // 部署信誉合约
    ReputationParams rep_params;
    rep_contract.deploy(rep_params, "node_001"); // 存储节点ID：node_001
    std::cout << "2. 信誉合约部署完成，初始信誉分：" << rep_contract.get_reputation("node_001") << std::endl;

    // 1.2 存储节点：TEE初始化+Merkle树构建
    EnclaveKeyPair enclave_key;
    std::vector<uint8_t> attestation_report;

    // 直接通过build_merkle_tree函数内部构造并返回，而不是传引用
    MerkleTree data_merkle;  // 移到这里，并通过函数返回值初始化
    if (storage_node.build_merkle_tree(encrypted_blocks, data_merkle) != 0) {
        std::cerr << "Merkle树构建失败！" << std::endl;
        return -1;
    }


    if (storage_node.init_tee(enclave_key, attestation_report) != 0) {
        std::cerr << "TEE初始化失败！" << std::endl;
        return -1;
    }
    std::cout << "3. TEE初始化完成，飞地公钥：";
    print_bytes(enclave_key.pk.data(), 65);

    if (storage_node.store_blocks(encrypted_blocks) != 0) {
        std::cerr << "存储数据块失败！" << std::endl;
        return -1;
    }
    std::cout << "4. 数据块存储完成（" << encrypted_blocks.size() << "块）" << std::endl;

    if (storage_node.build_merkle_tree(encrypted_blocks, data_merkle) != 0) {
        std::cerr << "Merkle树构建失败！" << std::endl;
        return -1;
    }
    std::cout << "5. Merkle树构建完成，根哈希：";
    auto merkle_root = data_merkle.get_root();
    print_bytes(merkle_root.data(), 32);

    // 在“5. Merkle树构建完成”之后，添加私钥打印
    std::cout << "6. 验证私钥存储：" << std::endl;
    print_bytes(enclave_key.sk.data(), 32);

    // 2. 证明生成阶段
    ProofBuilder proof_builder;
    std::vector<ProofPackage> proof_packages;
    std::vector<SegmentCredential> seg_credentials;
    std::array<uint8_t, 32> prev_proof_hash = {0}; // 首包prev_hash为0
    uint64_t time_slot_id = 0;
    uint64_t t_start = get_current_timestamp(); // 模拟当前时间戳
    double last_segment_rep = rep_contract.get_reputation("node_001");

    // 模拟3个时间槽的证明生成
    for (int i = 0; i < 3; ++i) {
        double current_rep = rep_contract.get_reputation("node_001");
        // 计算动态时间槽
        uint32_t t_slot = Config::T_MIN + (Config::T_MAX - Config::T_MIN) * (1 - current_rep);
        std::cout << "\n=== 时间槽 " << time_slot_id << "（长度：" << t_slot << "秒）===" << std::endl;

        // 构建证明包
        ProofPackage proof;
        if (proof_builder.build_proof_package(enclave_key, data_merkle, current_rep,
                                              time_slot_id, t_start, prev_proof_hash,
                                              encrypted_blocks.size(), proof) != 0) {
            std::cerr << "证明包构建失败！" << std::endl;
            return -1;
        }
        proof_packages.push_back(proof);
        std::cout << "证明包生成完成，挑战块索引：" << proof.challenge_idx << std::endl;

        // 检查是否触发分段（信誉变化超Δrep=0.1）
        if (fabs(current_rep - last_segment_rep) > Config::DELTA_REP) {
            SegmentCredential seg;
            if (proof_builder.build_segment_credential(last_segment_rep, current_rep,
                                                      time_slot_id - proof_packages.size() + 1,
                                                      time_slot_id, proof_packages, seg) != 0) {
                std::cerr << "分段凭证生成失败！" << std::endl;
                return -1;
            }
            seg_credentials.push_back(seg);
            std::cout << "触发信誉分段，分段凭证生成完成（信誉区间：[" << seg.rep_low << "," << seg.rep_high << "]）" << std::endl;
            last_segment_rep = current_rep;
            proof_packages.clear(); // 重置当前分段证明包
        }

        // 更新状态
        sha3_256_hash(reinterpret_cast<const uint8_t*>(&proof), sizeof(ProofPackage), prev_proof_hash);
        time_slot_id++;
        t_start += t_slot * 1000; // 转换为毫秒
    }

    // 3. 验证阶段
    SingleVerifier single_verifier;
    AggregateVerifier agg_verifier;

    // 3.1 单次证明验证（验证第1个时间槽的证明）
    std::cout << "\n=== 单次证明验证 ===" << std::endl;
    uint64_t submit_time = get_current_timestamp(); // 模拟提交时间
    bool single_pass = single_verifier.verify(proof_packages[0], enclave_key.pk,
                                             rep_contract.get_reputation("node_001"),
                                             submit_time, Config::NETWORK_DELAY);
    if (single_pass) {
        rep_contract.update_reputation("node_001", true); // 验证成功，信誉提升
        std::cout << "单次验证通过！更新后信誉分：" << rep_contract.get_reputation("node_001") << std::endl;
    } else {
        rep_contract.update_reputation("node_001", false); // 验证失败，信誉降低
        std::cout << "单次验证失败！更新后信誉分：" << rep_contract.get_reputation("node_001") << std::endl;
    }

    // 3.2 提交证明到区块链合约
    std::cout << "\n=== 提交证明到区块链合约 ===" << std::endl;
    bool contract_verify = verify_contract.submit_single_proof("node_001", proof_packages[0], enclave_key.pk, rep_contract);
    std::cout << "合约验证" << (contract_verify ? "通过！" : "失败！") << "，当前信誉分：" << rep_contract.get_reputation("node_001") << std::endl;

    // 3.3 聚合证明验证（验证分段凭证）
    if (!seg_credentials.empty()) {
        std::cout << "\n=== 聚合证明验证 ===" << std::endl;
        bool agg_pass = agg_verifier.verify(seg_credentials, data_merkle.get_root(),
                                           enclave_key.pk, encrypted_blocks.size());
        std::cout << "聚合验证" << (agg_pass ? "通过！" : "失败！") << std::endl;
        
        // 提交分段凭证到合约
        if (!proof_packages.empty()) {
            bool seg_submit = verify_contract.submit_segment_credential("node_001", seg_credentials[0],
                                                                       proof_packages, data_merkle.get_root(),
                                                                       enclave_key.pk);
            std::cout << "分段凭证提交" << (seg_submit ? "成功！" : "失败！") << std::endl;
        }
    }

    std::cout << "\n=== 实验流程结束 ===" << std::endl;
    return 0;
}

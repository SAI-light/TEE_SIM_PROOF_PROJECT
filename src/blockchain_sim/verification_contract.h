#ifndef VERIFICATION_CONTRACT_H
#define VERIFICATION_CONTRACT_H

#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include "../../include/common_type.h"
#include "../core/verifier/single_verifier.h"
#include "../core/verifier/aggregate_verifier.h"
#include "D:/Code/C/tee_sim_proof_project/src/utils/time_utils.h"
#include "D:/Code/C/tee_sim_proof_project/src/blockchain_sim/reputation_contract.h"

class VerificationContract {
public:
    // 构造函数
    VerificationContract() = default;
    
    // 析构函数
    ~VerificationContract() = default;
    
    // 部署合约
    void deploy();
    
    // 提交单次证明并验证
    bool submit_single_proof(const std::string& node_id,
                            const ProofPackage& proof,
                            const std::array<uint8_t, 65>& enclave_pub_key,
                            ReputationContract& rep_contract);
    
    // 提交分段凭证并验证
    bool submit_segment_credential(const std::string& node_id,
                                  const SegmentCredential& credential,
                                  const std::vector<ProofPackage>& proofs_in_segment,
                                  const std::array<uint8_t, 32>& data_root,
                                  const std::array<uint8_t, 65>& enclave_pub_key);
    
    // 获取节点的所有分段凭证
    std::vector<SegmentCredential> get_node_credentials(const std::string& node_id) const;

private:
    // 节点ID到分段凭证的映射
    std::unordered_map<std::string, std::vector<SegmentCredential>> node_credentials_;
    SingleVerifier single_verifier_;
    AggregateVerifier aggregate_verifier_;
};

#endif // VERIFICATION_CONTRACT_H

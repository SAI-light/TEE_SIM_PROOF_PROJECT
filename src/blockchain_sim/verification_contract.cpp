#include "verification_contract.h"
//#include "../../utils/time_utils.h"
#include "D:/Code/C/tee_sim_proof_project/src/utils/time_utils.h"
#include "D:\Code\C\tee_sim_proof_project\src\blockchain_sim\reputation_contract.h"
#include "../../include/config.h"

void VerificationContract::deploy() {
    // 初始化验证器
}

bool VerificationContract::submit_single_proof(const std::string& node_id,
                                             const ProofPackage& proof,
                                             const std::array<uint8_t, 65>& enclave_pub_key,
                                             ReputationContract& rep_contract) {
    if (!rep_contract.has_node(node_id)) {
        return false;
    }
    
    // 获取当前时间作为提交时间
    uint64_t submit_time = get_current_timestamp();
    
    // 验证证明
    bool verified = single_verifier_.verify(proof, enclave_pub_key,
                                           rep_contract.get_reputation(node_id),
                                           submit_time, Config::NETWORK_DELAY);
    
    // 更新信誉
    rep_contract.update_reputation(node_id, verified);
    
    return verified;
}

bool VerificationContract::submit_segment_credential(const std::string& node_id,
                                                   const SegmentCredential& credential,
                                                   const std::vector<ProofPackage>& proofs_in_segment,
                                                   const std::array<uint8_t, 32>& data_root,
                                                   const std::array<uint8_t, 65>& enclave_pub_key) {
    // 验证分段凭证
    if (!aggregate_verifier_.verify({credential}, data_root, enclave_pub_key, 0)) {
        return false;
    }
    
    // 抽查部分证明
    if (!aggregate_verifier_.spot_check(credential, proofs_in_segment, enclave_pub_key)) {
        return false;
    }
    
    // 存储分段凭证
    node_credentials_[node_id].push_back(credential);
    return true;
}

std::vector<SegmentCredential> VerificationContract::get_node_credentials(const std::string& node_id) const {
    auto it = node_credentials_.find(node_id);
    if (it == node_credentials_.end()) {
        return {};
    }
    return it->second;
}

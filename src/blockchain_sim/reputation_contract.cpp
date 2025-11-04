#include "reputation_contract.h"
#include <stdexcept>
#include <cmath>

void ReputationContract::deploy(const ReputationParams& params, const std::string& node_id) {
    params_ = params;
    reputations_[node_id] = params_.init_rep;
}

double ReputationContract::get_reputation(const std::string& node_id) const {
    auto it = reputations_.find(node_id);
    if (it == reputations_.end()) {
        throw std::invalid_argument("Node not found");
    }
    return it->second;
}

void ReputationContract::update_reputation(const std::string& node_id, bool is_success) {
    auto it = reputations_.find(node_id);
    if (it == reputations_.end()) {
        throw std::invalid_argument("Node not found");
    }
    
    double new_rep;
    if (is_success) {
        // 验证成功，提升信誉
        new_rep = it->second + Config::REP_INC;
        if (new_rep > Config::MAX_REP) {
            new_rep = Config::MAX_REP;
        }
    } else {
        // 验证失败，降低信誉
        new_rep = it->second - Config::REP_DEC;
        if (new_rep < Config::MIN_REP) {
            new_rep = Config::MIN_REP;
        }
    }
    
    it->second = new_rep;
}

ReputationParams ReputationContract::get_params() const {
    return params_;
}

bool ReputationContract::has_node(const std::string& node_id) const {
    return reputations_.find(node_id) != reputations_.end();
}

void ReputationContract::add_node(const std::string& node_id, double initial_rep) {
    if (has_node(node_id)) {
        throw std::invalid_argument("Node already exists");
    }
    
    // 确保初始信誉在有效范围内
    if (initial_rep < Config::MIN_REP) initial_rep = Config::MIN_REP;
    if (initial_rep > Config::MAX_REP) initial_rep = Config::MAX_REP;
    
    reputations_[node_id] = initial_rep;
}

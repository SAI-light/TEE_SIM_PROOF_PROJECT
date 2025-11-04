#ifndef REPUTATION_CONTRACT_H
#define REPUTATION_CONTRACT_H

#include <string>
#include <unordered_map>
#include "../../include/common_type.h"
#include "../../include/config.h"

class ReputationContract {
public:
    // 构造函数
    ReputationContract() = default;
    
    // 析构函数
    ~ReputationContract() = default;
    
    // 部署合约
    void deploy(const ReputationParams& params, const std::string& node_id);
    
    // 获取节点信誉值
    double get_reputation(const std::string& node_id) const;
    
    // 更新节点信誉值
    // node_id: 节点ID
    // is_success: 证明是否验证成功
    void update_reputation(const std::string& node_id, bool is_success);
    
    // 获取信誉合约参数
    ReputationParams get_params() const;
    
    // 检查节点是否存在
    bool has_node(const std::string& node_id) const;
    
    // 添加新节点
    void add_node(const std::string& node_id, double initial_rep = Config::MIN_REP + 0.5 * (Config::MAX_REP - Config::MIN_REP));

private:
    ReputationParams params_;
    std::unordered_map<std::string, double> reputations_; // 节点ID到信誉值的映射
};

#endif // REPUTATION_CONTRACT_H

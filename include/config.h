#ifndef CONFIG_H
#define CONFIG_H

#include <cstdint>

class Config {
public:
    // 时间槽配置
    static constexpr uint32_t T_MIN = 300;       // 最小时间槽（5分钟，秒）
    static constexpr uint32_t T_MAX = 86400;     // 最大时间槽（24小时，秒）
    
    // 信誉配置
    static constexpr double DELTA_REP = 0.1;     // 信誉变化阈值
    static constexpr double REP_INC = 0.05;      // 信誉提升幅度
    static constexpr double REP_DEC = 0.1;       // 信誉降低幅度
    static constexpr double MIN_REP = 0.0;       // 最低信誉分
    static constexpr double MAX_REP = 1.0;       // 最高信誉分
    
    // 网络配置
    static constexpr uint32_t NETWORK_DELAY = 30; // 最大网络延迟（秒）
    
    // 加密配置
    static constexpr size_t BLOCK_SIZE = 1024;    // 文件分块大小（字节）
};

#endif // CONFIG_H

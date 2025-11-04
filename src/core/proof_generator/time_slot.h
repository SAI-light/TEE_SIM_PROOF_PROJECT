#ifndef TIME_SLOT_H
#define TIME_SLOT_H

#include <cstdint>
#include <chrono>
#include <thread>
#include <functional>
#include "../../../include/config.h"

class TimeSlot {
public:
    // 构造函数
    TimeSlot(double initial_rep);
    
    // 析构函数
    ~TimeSlot();
    
    // 启动时间槽计时器
    void start(std::function<void(uint64_t, uint32_t)> callback);
    
    // 停止时间槽计时器
    void stop();
    
    // 更新信誉值，影响下一个时间槽长度
    void update_reputation(double new_rep);
    
    // 获取当前时间槽ID
    uint64_t get_current_slot_id() const;
    
    // 获取当前时间槽长度
    uint32_t get_current_slot_length() const;

private:
    double current_rep_;          // 当前信誉值
    uint64_t current_slot_id_;    // 当前时间槽ID
    uint32_t current_slot_length_;// 当前时间槽长度（秒）
    bool running_;                // 计时器是否运行
    std::thread timer_thread_;    // 计时器线程
    
    // 计算时间槽长度
    uint32_t calculate_slot_length(double rep);
    
    // 计时器主循环
    void timer_loop(std::function<void(uint64_t, uint32_t)> callback);
};

#endif // TIME_SLOT_H

#ifndef TIME_UTILS_H
#define TIME_UTILS_H

#include <cstdint>
#include <chrono>

// 获取当前时间戳（毫秒）
uint64_t get_current_timestamp();

// 检查时间是否在有效窗口内
bool is_time_valid(uint64_t t_start, uint32_t t_slot, uint64_t submit_time, uint32_t max_delay);

// 计算两个时间戳之间的差值（秒）
uint64_t time_diff_seconds(uint64_t t1, uint64_t t2);

#endif // TIME_UTILS_H

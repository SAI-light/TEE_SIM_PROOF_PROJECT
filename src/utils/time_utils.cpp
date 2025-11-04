#include <algorithm>
#include "time_utils.h"

uint64_t get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

bool is_time_valid(uint64_t t_start, uint32_t t_slot, uint64_t submit_time, uint32_t max_delay) {
    // 时间戳单位为毫秒，需要转换为秒进行计算
    uint64_t t_start_sec = t_start / 1000;
    uint64_t submit_time_sec = submit_time / 1000;
    
    // 检查提交时间是否在 [t_start, t_start + t_slot + max_delay] 范围内
    return (submit_time_sec >= t_start_sec) && 
           (submit_time_sec <= t_start_sec + t_slot + max_delay);
}

uint64_t time_diff_seconds(uint64_t t1, uint64_t t2) {
    // 确保t1 >= t2
    if (t1 < t2) std::swap(t1, t2);
    return (t1 - t2) / 1000;
}

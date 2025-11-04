#include "time_slot.h"
#include "../../utils/time_utils.h"
#include <iostream>

TimeSlot::TimeSlot(double initial_rep) 
    : current_rep_(initial_rep), current_slot_id_(0), 
      current_slot_length_(calculate_slot_length(initial_rep)),
      running_(false) {}

TimeSlot::~TimeSlot() {
    stop();
}

uint32_t TimeSlot::calculate_slot_length(double rep) {
    // 确保信誉值在有效范围内
    if (rep < Config::MIN_REP) rep = Config::MIN_REP;
    if (rep > Config::MAX_REP) rep = Config::MAX_REP;
    
    // T = T_min + (T_max - T_min) * (1 - Rep)
    return static_cast<uint32_t>(Config::T_MIN + 
                                (Config::T_MAX - Config::T_MIN) * (1 - rep));
}

void TimeSlot::start(std::function<void(uint64_t, uint32_t)> callback) {
    if (running_) return;
    
    running_ = true;
    timer_thread_ = std::thread(&TimeSlot::timer_loop, this, callback);
}

void TimeSlot::stop() {
    if (!running_) return;
    
    running_ = false;
    if (timer_thread_.joinable()) {
        timer_thread_.join();
    }
}

void TimeSlot::update_reputation(double new_rep) {
    current_rep_ = new_rep;
    current_slot_length_ = calculate_slot_length(new_rep);
}

uint64_t TimeSlot::get_current_slot_id() const {
    return current_slot_id_;
}

uint32_t TimeSlot::get_current_slot_length() const {
    return current_slot_length_;
}

void TimeSlot::timer_loop(std::function<void(uint64_t, uint32_t)> callback) {
    while (running_) {
        // 等待当前时间槽长度的时间
        std::this_thread::sleep_for(std::chrono::seconds(current_slot_length_));
        
        if (running_) {
            // 触发回调
            callback(current_slot_id_, current_slot_length_);
            
            // 更新时间槽ID
            current_slot_id_++;
        }
    }
}

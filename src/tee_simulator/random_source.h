#ifndef RANDOM_SOURCE_H
#define RANDOM_SOURCE_H

#include <cstdint>
#include <cstddef>

// 模拟硬件熵源：生成len字节真随机数（后期替换为SGX的sgx_read_rand）
int tee_get_random(uint8_t* buf, size_t len);

#endif // RANDOM_SOURCE_H

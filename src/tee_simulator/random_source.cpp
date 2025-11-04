#include "random_source.h"
#include <openssl/rand.h>

int tee_get_random(uint8_t* buf, size_t len) {
    if (buf == nullptr || len == 0) return -1;
    // 模拟：用OpenSSL生成伪随机数（后期替换为RDRAND）
    return RAND_bytes(buf, len) == 1 ? 0 : -1;
}

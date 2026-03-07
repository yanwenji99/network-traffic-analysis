#pragma once

#include <cstdint>

struct Flow
{                            // 获取的会话信息
    char source_ip[16];      // 源IP
    char destination_ip[16]; // 目的IP
    uint8_t protocol;        // TCP=6, UDP=17, ICMP=1
    uint16_t src_port;       // 源端口
    uint16_t dst_port;       // 目的端口
    uint64_t data_size;      // 会话数据量（字节）
    double duration;         // 会话持续时间（秒）
};
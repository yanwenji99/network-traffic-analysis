#pragma once

#include "graph.h"
#include <algorithm>
#include <iomanip>

#define HTTPS_PORT 443
#define TCP_PROTOCOL 6
#define RATIO_THRESHOLD 0.8

struct NodeFlow
{
    // char ip[16];                  节点IP地址不是必须的，可以将ip转换成id用数组表示
    uint8_t protocol = 0;         // TCP=6, UDP=17, ICMP=1, 0表示所有协议
    uint16_t dst_port = 0;        // 目的端口, 0表示所有端口
    uint64_t total_data_size = 0; // 与该节点相关的会话数据量总和
    uint64_t out_data_size = 0;   // 发出会话数据量总和
    double out_ratio = 0.0;       // 发出会话数据量占总数据量的比例
};

extern std::vector<Flow> flows; // 存储所有会话信息的全局变量

std::vector<NodeFlow> sort_all_flow(const CSRGraph &graph, const std::vector<Flow> &flows);
std::vector<NodeFlow> sort_ratio_flow(const CSRGraph &graph, const std::vector<Flow> &flows);
std::vector<NodeFlow> sort_HTTPS_flow(const CSRGraph &graph, const std::vector<Flow> &flows);
void printf_sort_result(const std::vector<NodeFlow> &result);
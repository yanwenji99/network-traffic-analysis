#include "check_range.h"
#include <cstdio>

namespace
{
    bool parse_ipv4_to_uint32(const char *ip, uint32_t &value)
    {
        if (ip == nullptr)
        {
            return false;
        }

        unsigned int a = 0;
        unsigned int b = 0;
        unsigned int c = 0;
        unsigned int d = 0;
        char tail = '\0';
        if (std::sscanf(ip, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4)
        {
            return false;
        }

        if (a > 255 || b > 255 || c > 255 || d > 255)
        {
            return false;
        }

        value = (static_cast<uint32_t>(a) << 24) |
                (static_cast<uint32_t>(b) << 16) |
                (static_cast<uint32_t>(c) << 8) |
                static_cast<uint32_t>(d);
        return true;
    }
}

/**
 * 检测范围会话
 * 功能：查找从源IP到指定IP范围内的所有会话，用于定向攻击检测或内网渗透监控
 * 核心思想：遍历源节点的所有出边，按目的IP数值判断是否落在范围内
 * 入口参数：
 *     graph - CSR图结构对象
 *     src_ip - 源IP地址
 *     start_ip - 起始IP地址（范围下界）
 *     end_ip - 结束IP地址（范围上界）
 * 出口参数：
 *     返回范围内会话的Flow向量
 */
std::vector<Flow> check_illegal_flows(const CSRGraph &graph, const char *src_ip, const char *start_ip, const char *end_ip)
{
    std::vector<Flow> illegal_flows;

    // 源IP必须存在于图中；范围边界IP允许不在图中
    int src_id = graph.getIdByIp(src_ip);

    uint32_t start_value = 0;
    uint32_t end_value = 0;
    if (src_id < 0 || !parse_ipv4_to_uint32(start_ip, start_value) || !parse_ipv4_to_uint32(end_ip, end_value))
    {
        return illegal_flows;
    }

    // 获取图的CSR表示
    const std::vector<int> &offset = graph.getOffset();
    const std::vector<Edge> &edges = graph.getEdges();

    // 确定IP范围上下界（处理start_ip > end_ip的情况）
    uint32_t lower_ip = std::min(start_value, end_value);
    uint32_t upper_ip = std::max(start_value, end_value);

    // 遍历源节点的所有出边
    for (int i = offset[src_id]; i < offset[src_id + 1]; ++i)
    {
        uint32_t dst_value = 0;
        if (!parse_ipv4_to_uint32(edges[i].flow.destination_ip, dst_value))
        {
            continue;
        }

        // 检查目标IP是否在指定范围内
        if (dst_value >= lower_ip && dst_value <= upper_ip)
        {
            illegal_flows.push_back(edges[i].flow);
        }
    }
    return illegal_flows;
}

/**
 * 打印非法会话检测结果
 * 功能：格式化输出范围内会话检测结果，显示每条会话的详细信息
 * 核心思想：遍历非法会话向量，输出源IP、目标IP、协议、端口等信息
 * 入口参数：
 *     illegal_flows - 非法会话向量
 * 出口参数：
 *     无返回值，直接输出到控制台
 */
void print_illegal_flows(const std::vector<Flow> &illegal_flows)
{
    if (illegal_flows.empty())
    {
        std::cout << "No illegal flows found." << std::endl;
        return;
    }

    std::cout << "Illegal flows:" << std::endl;
    for (const auto &flow : illegal_flows)
    {
        std::cout << "Source IP: " << flow.source_ip
                  << ", Destination IP: " << flow.destination_ip
                  << ", Protocol: " << static_cast<int>(flow.protocol)
                  << ", Source Port: " << flow.src_port
                  << ", Destination Port: " << flow.dst_port
                  << ", Data Size: " << flow.data_size
                  << ", Duration: " << flow.duration
                  << std::endl;
    }
}
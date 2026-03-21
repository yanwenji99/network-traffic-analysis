#include "check_range.h"

/**
 * 检测范围会话
 * 功能：查找从源IP到指定IP范围内的所有会话，用于定向攻击检测或内网渗透监控
 * 核心思想：遍历源节点的所有出边，检查目标节点ID是否在指定范围内
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

    // 将IP地址转换为节点ID
    int src_id = graph.getIdByIp(src_ip);
    int start_id = graph.getIdByIp(start_ip);
    int end_id = graph.getIdByIp(end_ip);

    // 如果任一IP不存在于图中，返回空结果
    if (src_id < 0 || start_id < 0 || end_id < 0)
    {
        return illegal_flows;
    }

    // 获取图的CSR表示
    const std::vector<int> &offset = graph.getOffset();
    const std::vector<Edge> &edges = graph.getEdges();

    // 确定IP范围的上下界（处理start_id > end_id的情况）
    int lower_id = std::min(start_id, end_id);
    int upper_id = std::max(start_id, end_id);

    // 遍历源节点的所有出边
    for (int i = offset[src_id]; i < offset[src_id + 1]; ++i)
    {
        int to_id = edges[i].to;
        
        // 检查目标节点是否在指定范围内
        if (to_id >= lower_id && to_id <= upper_id)
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
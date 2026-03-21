#include "sorting.h"

#include <algorithm>
#include <iomanip>

namespace // 匿名命名空间，这些函数是内部实现细节，不应该被其他文件直接调用
{
    /**
     * 判断一条流是否属于HTTPS流量
     * 功能：检查流量是否使用TCP协议且端口为443
     * 核心思想：HTTPS流量的特征是TCP协议且端口为443
     * 入口参数：
     *     flow - 要检查的流量对象
     * 出口参数：
     *     返回true表示是HTTPS流量，false表示不是
     */
    bool is_https_flow(const Flow &flow)
    {
        return flow.protocol == TCP_PROTOCOL && (flow.dst_port == HTTPS_PORT || flow.src_port == HTTPS_PORT);
    }

    /**
     * 统一统计函数：按节点累计流量统计信息
     * 功能：遍历所有流量，统计每个节点的总流量、出流量和外发占比
     * 核心思想：使用节点ID作为数组索引，累计流量信息，最后计算外发占比
     * 入口参数：
     *     graph - CSR图结构对象
     *     flows - 流量数据向量
     *     https_only - 是否仅统计HTTPS流量
     * 出口参数：
     *     返回节点流量统计信息向量
     */
    std::vector<NodeFlow> build_node_stats(const CSRGraph &graph, const std::vector<Flow> &flows, bool https_only)
    {
        // 按图中节点数量初始化，确保后续按节点 ID 下标访问不会越界
        std::vector<NodeFlow> node_flows(graph.getNodeCount());

        for (const auto &flow : flows)
        {
            // 如果开启 HTTPS 过滤，则只保留 HTTPS 流
            if (https_only && !is_https_flow(flow))
            {
                continue;
            }

            // 通过公开接口获取节点 ID，避免访问 CSRGraph 私有成员
            int src_id = graph.getIdByIp(flow.source_ip);
            int dst_id = graph.getIdByIp(flow.destination_ip);

            // 若某条流的 IP 不在图中，跳过该条，避免异常
            if (src_id < 0 || dst_id < 0)
            {
                continue;
            }

            // 源节点：总流量 + 出流量
            node_flows[src_id].total_data_size += flow.data_size;
            node_flows[src_id].out_data_size += flow.data_size;

            // 目的节点：只记入总流量
            node_flows[dst_id].total_data_size += flow.data_size;
        }

        // 计算每个节点的外发占比
        for (auto &node_flow : node_flows)
        {
            if (node_flow.total_data_size > 0)
            {
                node_flow.out_ratio = static_cast<double>(node_flow.out_data_size) / node_flow.total_data_size;
            }
        }

        return node_flows;
    }
} // namespace

/**
 * 按总流量排序所有节点
 * 功能：统计每个节点的总流量，并按总流量降序排序
 * 核心思想：调用build_node_stats统计流量，使用std::sort按总流量降序排序
 * 入口参数：
 *     graph - CSR图结构对象
 *     flows - 流量数据向量
 * 出口参数：
 *     返回按总流量降序排序的节点流量向量
 */
std::vector<NodeFlow> sort_all_flow(const CSRGraph &graph, const std::vector<Flow> &flows)
{
    // 统计全部流量
    std::vector<NodeFlow> node_flows = build_node_stats(graph, flows, false);

    // 按总流量降序排序
    std::sort(node_flows.begin(), node_flows.end(), [](const NodeFlow &a, const NodeFlow &b)
              {
                  return a.total_data_size > b.total_data_size; // 按照总数据量降序排序
              });
    return node_flows;
}

/**
 * 按外发占比排序节点
 * 功能：筛选外发占比超过阈值的节点，并按外发占比降序排序
 * 核心思想：统计流量后过滤外发占比大于0.8的节点，按外发占比和总流量排序
 * 入口参数：
 *     graph - CSR图结构对象
 *     flows - 流量数据向量
 * 出口参数：
 *     返回按外发占比降序排序的节点流量向量
 */
std::vector<NodeFlow> sort_ratio_flow(const CSRGraph &graph, const std::vector<Flow> &flows)
{
    // 先统计全部流量，再基于 out_ratio 过滤
    std::vector<NodeFlow> node_flows = build_node_stats(graph, flows, false);

    std::vector<NodeFlow> ratio_node_flows;
    ratio_node_flows.reserve(node_flows.size());

    // 仅保留外发占比大于 0.8 的节点
    for (const auto &node_flow : node_flows)
    {
        if (node_flow.out_ratio > RATIO_THRESHOLD)
        {
            ratio_node_flows.push_back(node_flow);
        }
    }

    // 先按外发占比降序，其次按总流量降序
    std::sort(ratio_node_flows.begin(), ratio_node_flows.end(), [](const NodeFlow &a, const NodeFlow &b)
              {
             if (a.out_ratio == b.out_ratio)
             {
                 return a.total_data_size > b.total_data_size;
             }
             return a.out_ratio > b.out_ratio; });
    return ratio_node_flows;
}

/**
 * 按HTTPS流量排序节点
 * 功能：仅统计HTTPS流量，并按总流量降序排序
 * 核心思想：调用build_node_stats时启用HTTPS过滤，然后按总流量排序
 * 入口参数：
 *     graph - CSR图结构对象
 *     flows - 流量数据向量
 * 出口参数：
 *     返回按HTTPS流量降序排序的节点流量向量
 */
std::vector<NodeFlow> sort_HTTPS_flow(const CSRGraph &graph, const std::vector<Flow> &flows)
{
    // 仅统计 HTTPS 流量
    std::vector<NodeFlow> node_flows = build_node_stats(graph, flows, true);

    // 按总流量降序排序
    std::sort(node_flows.begin(), node_flows.end(), [](const NodeFlow &a, const NodeFlow &b)
              {
                  return a.total_data_size > b.total_data_size; // 按照总数据量降序排序
              });
    return node_flows;
}

/**
 * 打印排序结果
 * 功能：格式化输出节点流量排序结果，显示前10名
 * 核心思想：遍历结果向量，格式化输出排名、总流量、出流量和外发占比
 * 入口参数：
 *     result - 节点流量统计结果向量
 * 出口参数：
 *     无返回值，直接输出到控制台
 */
void printf_sort_result(const std::vector<NodeFlow> &result)
{
    if (result.empty())
    {
        std::cout << "No node results to display." << std::endl;
        return;
    }

    std::cout << "---------------------------------------------" << std::endl;
    std::cout << std::left << std::setw(6) << "Rank"
              << std::setw(16) << "TotalData"
              << std::setw(16) << "OutData"
              << std::setw(10) << "OutRatio" << std::endl;

    const std::size_t show_count = std::min<std::size_t>(10, result.size());
    for (std::size_t i = 0; i < show_count; ++i)
    {
        std::cout << std::left << std::setw(6) << (i + 1)
                  << std::setw(16) << result[i].total_data_size
                  << std::setw(16) << result[i].out_data_size
                  << std::setw(10) << std::fixed << std::setprecision(3) << result[i].out_ratio << std::endl;
    }
}
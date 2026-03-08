#include "sorting.h"

#include <algorithm>
#include <iomanip>

namespace // 匿名命名空间，这些函数是内部实现细节，不应该被其他文件直接调用
{
    // 判断一条流是否属于 HTTPS（TCP 且端口包含 443）
    bool is_https_flow(const Flow &flow)
    {
        return flow.protocol == TCP_PROTOCOL && (flow.dst_port == HTTPS_PORT || flow.src_port == HTTPS_PORT);
    }

    // 统一统计函数：
    // 1) 按节点累计 total_data_size / out_data_size
    // 2) 计算 out_ratio
    // 3) 可选仅统计 HTTPS 流量
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
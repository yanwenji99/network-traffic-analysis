#include "check_scan.h"

// 扫描行为检测阈值：节点出度超过此值才进入详细检查
#define SCAN_OUT_DEGREE_THRESHOLD 20

// 扫描行为数据包阈值：数据包大小超过此值才判定为正常（非扫描）
#define SCAN_DATA_SIZE_THRESHOLD 1000

/**
 * 检测扫描行为节点
 * 功能：查找高出度且小数据包的节点，这类行为常见于端口扫描或网络侦察
 * 核心思想：遍历所有节点，检查出度是否超过阈值，且所有边的数据包大小是否都较小
 * 入口参数：
 *     graph - CSR图结构对象
 * 出口参数：
 *     返回可疑节点ID向量
 */
std::vector<int> check_scan(const CSRGraph &graph)
{
    // 获取图的基本信息
    const std::size_t node_count = graph.getNodeCount();
    const std::vector<int> &offset = graph.getOffset();
    const std::vector<Edge> &edges = graph.getEdges();

    std::vector<int> suspicious_nodes;

    // 遍历所有节点，检查是否为扫描行为
    for (std::size_t i = 0; i < node_count; ++i)
    {
        // 计算当前节点的出度（通过CSR的offset数组差值）
        int out_degree = offset[i + 1] - offset[i];

        // 仅当出度超过阈值时才进行详细检查
        if (out_degree > SCAN_OUT_DEGREE_THRESHOLD)
        {
            bool flag = true;

            // 遍历当前节点的所有出边，检查数据包大小
            for (int j = offset[i]; j < offset[i + 1]; ++j)
            {
                const Edge &edge = edges[j];

                // 如果存在数据包大小小于阈值的边，则不是扫描行为
                if (edge.flow.data_size < SCAN_DATA_SIZE_THRESHOLD)
                {
                    flag = false;
                    break;
                }
            }

            // 如果所有边的数据包大小都超过阈值，判定为扫描节点
            if (flag)
            {
                suspicious_nodes.push_back(static_cast<int>(i));
            }
        }
    }
    return suspicious_nodes;
}

/**
 * 打印扫描检测结果
 * 功能：格式化输出扫描行为检测结果，显示可疑节点的IP地址
 * 核心思想：遍历可疑节点向量，通过节点ID获取IP地址并输出
 * 入口参数：
 *     graph - CSR图结构对象
 *     suspicious_nodes - 可疑节点ID向量
 * 出口参数：
 *     无返回值，直接输出到控制台
 */
void printf_scan_result(const CSRGraph &graph, const std::vector<int> &suspicious_nodes)
{
    if (suspicious_nodes.empty())
    {
        std::cout << "No scan-like nodes found." << std::endl;
        return;
    }

    std::cout << "Scan-like Nodes Found:" << std::endl;
    for (int node_id : suspicious_nodes)
    {
        std::cout << " IP: " << graph.getIpById(static_cast<std::size_t>(node_id))
                  << std::endl;
    }
}
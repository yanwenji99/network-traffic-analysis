#include "check_scan.h"

#define SCAN_OUT_DEGREE_THRESHOLD 20
#define SCAN_DATA_SIZE_THRESHOLD 1000

std::vector<int> check_scan(const CSRGraph &graph)
{
    const std::size_t node_count = graph.getNodeCount();
    const std::vector<int> &offset = graph.getOffset();
    const std::vector<Edge> &edges = graph.getEdges();

    std::vector<int> suspicious_nodes;

    for (std::size_t i = 0; i < node_count; ++i)
    {
        int out_degree = offset[i + 1] - offset[i];
        if (out_degree > SCAN_OUT_DEGREE_THRESHOLD) // 这里的阈值可以根据实际情况调整
        {
            bool flag = true;
            for (int j = offset[i]; j < offset[i + 1]; ++j)
            {
                const Edge &edge = edges[j];
                if (edge.flow.data_size < SCAN_DATA_SIZE_THRESHOLD)
                {
                    flag = false;
                    break;
                }
            }
            if (flag)
            {
                suspicious_nodes.push_back(static_cast<int>(i));
            }
        }
    }
    return suspicious_nodes;
}

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
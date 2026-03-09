#pragma once

#include "graph.h"

#include <string>

struct SubgraphEdge
{
    int from_id = -1; // 源节点ID
    int to_id = -1;   // 目标节点ID
    Flow flow{};
};

struct SubgraphResult
{
    std::string target_ip;                     // 目标IP地址
    int target_node_id = -1;                   // 目标节点ID
    std::size_t outgoing_reachable_count = 0;  // 可从目标节点到达的节点数
    std::size_t incoming_reachable_count = 0;  // 可到达目标节点的节点数
    std::vector<int> node_ids;                 // 子图中的节点ID列表
    std::vector<std::string> node_ips;         // 子图中的节点IP地址列表
    std::vector<SubgraphEdge> edges;           // 子图中的边列表
    bool found = false;
};

SubgraphResult find_subgraph_by_ip(const CSRGraph &graph, const char *target_ip);
void printf_subgraph_result(const CSRGraph &graph, const SubgraphResult &result, std::size_t max_edges_to_print = 50);
bool export_subgraph_json(const CSRGraph &graph, const SubgraphResult &result, const std::string &json_path);

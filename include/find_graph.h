#pragma once

#include "graph.h"

#include <string>

struct SubgraphEdge
{
    int from_id = -1;
    int to_id = -1;
    Flow flow{};
};

struct SubgraphResult
{
    std::string target_ip;
    int target_node_id = -1;
    std::size_t outgoing_reachable_count = 0; // reachable from target (exclude target)
    std::size_t incoming_reachable_count = 0; // can reach target (exclude target)
    std::vector<int> node_ids;
    std::vector<std::string> node_ips;
    std::vector<SubgraphEdge> edges;
    bool found = false;
};

// Build a directed subgraph around target_ip:
// nodes = {target} U outgoing-reachable(target) U incoming-reachable(target).
SubgraphResult find_subgraph_by_ip(const CSRGraph &graph, const char *target_ip);
void printf_subgraph_result(const CSRGraph &graph, const SubgraphResult &result, std::size_t max_edges_to_print = 50);
bool export_subgraph_json(const CSRGraph &graph, const SubgraphResult &result, const std::string &json_path);

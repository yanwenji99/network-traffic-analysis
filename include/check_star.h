#pragma once

#include "graph.h"
#include <unordered_set>

struct StarNode{
    int node_id;                           // 中心节点ID
    std::vector<int> connected_nodes;      // 与中心节点直接连接的节点ID列表
};

std::vector<StarNode> check_star(const CSRGraph &graph); 
void printf_star_result(const CSRGraph &graph, const std::vector<StarNode> &star_nodes);
#pragma once

#include "graph.h"
#include <limits>
#include <iomanip>

struct PathResult
{
    std::vector<int> node_ids;         // 路径上的节点ID序列
    std::vector<std::string> node_ips; // 路径上的IP地址序列
    double total_duration = 0.0;       // 总持续时间
    uint64_t total_data_size = 0;      // 总数据量
    double jamb_score = 0.0;           // 拥塞评分
    bool found = false;                // 是否找到路径
};

PathResult BFS(const CSRGraph &graph, const char *src_ip, const char *dst_ip);

struct DijkstraNode
{
    int node_id;       // 节点ID
    double distance;   // 从源节点到当前节点的距离（总持续时间）

    DijkstraNode(int id, double dist) : node_id(id), distance(dist) {}

    // 定义比较运算符，用于优先队列排序
    bool operator>(const DijkstraNode &other) const
    {
        return distance > other.distance; // 否则比较距离
    }
};

PathResult Dejkstra(const CSRGraph &graph, const char *src_ip, const char *dst_ip);
void printf_path(const PathResult result);
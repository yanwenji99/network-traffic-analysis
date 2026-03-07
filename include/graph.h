#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <iostream>
#include "flow.h"

extern std::vector<Flow> flows; // 存储所有会话信息的全局变量

struct Edge
{              // 图的边结构
    int to;    // 目标节点索引
    Flow flow; // 会话信息
};

struct Node
{                       // 图的节点结构
    char ip[16];        // 节点IP地址
    std::vector<Edge> edges; // 与其他节点的连接边
};

class CSRGraph
{
public:
    void addFlow(const Flow &flow); // 添加会话信息到图中
    void buildCSR();                // 构建CSR格式的图
    const std::vector<int> &getOffset() const; // 获取CSR行偏移数组
    const std::vector<Edge> &getEdges() const; // 获取CSR边数组
    int getIdByIp(const std::string &ip) const; // 通过IP获取节点ID，不存在返回-1
    std::string getIpById(std::size_t node_id) const; // 通过节点ID获取IP，不存在返回空字符串
    std::size_t getNodeCount() const;              // 获取节点数量

private:
    struct tempEdge
    {              // 临时边结构，用于构建图
        int from;  // 源节点索引
        int to;    // 目标节点索引
        Flow flow; // 会话信息
    };
    std::unordered_map<std::string, int> ip_to_id; // IP地址到节点ID的映射
    std::vector<std::string> id_to_ip;             // 节点ID到IP地址的映射（反向查找）
    std::vector<tempEdge> temp_edges;              // 存储临时边
    std::vector<int> offset;                       // CSR行偏移数组
    std::vector<Edge> edges;                       // CSR边数组
};
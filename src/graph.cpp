#include "graph.h"

std::vector<Flow> flows;

void CSRGraph::addFlow(const Flow &flow)
{
    // 将源IP和目的IP转换为节点ID
    int from_id, to_id;

    // 将Flow结构体中的字符数组转换为C++ string，便于在unordered_map中查找
    std::string src_ip(flow.source_ip), dst_ip(flow.destination_ip);

    if (ip_to_id.find(src_ip) == ip_to_id.end())
    { // 在ip_to_id映射表中查找源IP是否已存在
        // 源IP不存在，创建新节点
        // 新节点的ID = 当前映射表的大小（因为ID从0开始连续分配）
        from_id = ip_to_id.size();

        // 建立正向映射：IP地址 -> 节点ID
        ip_to_id[src_ip] = from_id;

        // 建立反向映射：节点ID -> IP地址
        id_to_ip.push_back(src_ip);
    }
    else
    {
        from_id = ip_to_id[src_ip];
    }
    if (ip_to_id.find(dst_ip) == ip_to_id.end())
    {
        to_id = ip_to_id.size();
        ip_to_id[dst_ip] = to_id;
        id_to_ip.push_back(dst_ip);
    }
    else
    {
        to_id = ip_to_id[dst_ip];
    }
    // 添加临时边
    temp_edges.push_back({from_id, to_id, flow});
}

void CSRGraph::buildCSR()
{
    // 构建CSR格式的图
    int num_nodes = id_to_ip.size();
    int num_edges = temp_edges.size();

    offset.assign(num_nodes + 1, 0); // 存储每个节点的边的起始位置
    edges.assign(num_edges, Edge{}); // 存储所有边的信息

    // 计算每个节点的边的数量
    for (const auto &edge : temp_edges)
    {
        offset[edge.from + 1]++; // 注意：offset数组的第0个元素为0，边的起始位置从offset[1]开始
    }
    // 计算offset数组的前缀和
    for (int i = 1; i <= num_nodes; i++)
    {
        offset[i] += offset[i - 1];
    }

    std::vector<int> current_offset = offset; // 用于记录当前边的插入位置

    // 填充edges数组
    for (const auto &edge : temp_edges)
    {
        int pos = current_offset[edge.from]++; // 获取当前边的插入位置，并将current_offset[from]递增
        edges[pos] = {edge.to, edge.flow};     // 将边的信息存储到edges数组中
    }
}

const std::vector<int> &CSRGraph::getOffset() const
{
    return offset;
}

const std::vector<Edge> &CSRGraph::getEdges() const
{
    return edges;
}

int CSRGraph::getIdByIp(const std::string &ip) const
{
    auto it = ip_to_id.find(ip);
    if (it == ip_to_id.end())
    {
        return -1;
    }
    return it->second;
}

std::string CSRGraph::getIpById(std::size_t node_id) const
{
    if (node_id >= id_to_ip.size())
    {
        return "";
    }
    return id_to_ip[node_id];
}

std::size_t CSRGraph::getNodeCount() const
{
    return id_to_ip.size();
}
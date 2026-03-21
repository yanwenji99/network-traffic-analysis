#include "graph.h"

std::vector<Flow> flows;

/**
 * 添加流量到图中
 * 功能：将一条流量记录添加到图中，自动创建节点并建立IP到节点ID的映射
 * 核心思想：使用哈希表维护IP到ID的映射，新IP自动分配新ID，边信息暂存到临时向量
 * 入口参数：
 *     flow - 要添加的流量记录
 * 出口参数：
 *     无返回值，结果存储在图对象的成员变量中
 */
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

/**
 * 构建CSR格式的图
 * 功能：将临时边列表转换为CSR（Compressed Sparse Row）格式，优化图遍历性能
 * 核心思想：统计每个节点的出度，计算前缀和得到offset数组，然后将边按源节点分组存储
 * 入口参数：
 *     无
 * 出口参数：
 *     无返回值，结果存储在offset和edges成员变量中
 */
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

/**
 * 获取CSR格式的offset数组
 * 功能：返回offset数组的常量引用，用于遍历图结构
 * 核心思想：offset[i]表示节点i的边在edges数组中的起始位置
 * 入口参数：无
 * 出口参数：返回offset数组的常量引用
 */
const std::vector<int> &CSRGraph::getOffset() const
{
    return offset;
}

/**
 * 获取CSR格式的edges数组
 * 功能：返回edges数组的常量引用，包含所有边的信息
 * 核心思想：edges数组按源节点分组存储，配合offset数组实现快速访问
 * 入口参数：无
 * 出口参数：返回edges数组的常量引用
 */
const std::vector<Edge> &CSRGraph::getEdges() const
{
    return edges;
}

/**
 * 通过IP地址获取节点ID
 * 功能：在ip_to_id哈希表中查找IP地址对应的节点ID
 * 核心思想：使用unordered_map实现O(1)时间的快速查找
 * 入口参数：
 *     ip - IP地址字符串
 * 出口参数：
 *     返回节点ID，不存在返回-1
 */
int CSRGraph::getIdByIp(const std::string &ip) const
{
    auto it = ip_to_id.find(ip);
    if (it == ip_to_id.end())
    {
        return -1; // IP不存在于图中
    }
    return it->second; // 返回对应的节点ID
}

/**
 * 通过节点ID获取IP地址
 * 功能：在id_to_ip向量中查找节点ID对应的IP地址
 * 核心思想：使用vector实现O(1)时间的快速访问
 * 入口参数：
 *     node_id - 节点ID
 * 出口参数：
 *     返回IP地址字符串，不存在返回空字符串
 */
std::string CSRGraph::getIpById(std::size_t node_id) const
{
    if (node_id >= id_to_ip.size())
    {
        return ""; // 节点ID越界
    }
    return id_to_ip[node_id]; // 返回对应的IP地址
}

std::size_t CSRGraph::getNodeCount() const
{
    return id_to_ip.size();
}
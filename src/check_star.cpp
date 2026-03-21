#include "check_star.h"

#include <algorithm>

// 星型结构检测阈值：节点出度超过此值才进入详细检查
#define STAR_OUT_DEGREE_THRESHOLD 20

/**
 * 检测星型结构节点
 * 功能：查找连接大量叶子节点的中心节点，这类结构常见于C&C通信或DDoS攻击
 * 核心思想：遍历所有节点，检查出度是否超过阈值，且连接的邻居是否都是叶子节点（出度为0）
 * 入口参数：
 *     graph - CSR图结构对象
 * 出口参数：
 *     返回检测到的星型节点向量
 */
std::vector<StarNode> check_star(const CSRGraph &graph)
{
    // 获取图的基本信息
    const std::size_t node_count = graph.getNodeCount();
    const std::vector<int> &offset = graph.getOffset();
    const std::vector<Edge> &edges = graph.getEdges();

    std::vector<StarNode> star_nodes;
    
    // 遍历所有节点，检查是否为星型结构
    for (std::size_t i = 0; i < node_count; ++i)
    {
        StarNode node;
        node.node_id = static_cast<int>(i);

        // 计算当前节点的出度（通过CSR的offset数组差值）
        // offset[i+1] - offset[i] 表示节点i的出边数量
        const int out_degree = offset[i + 1] - offset[i];
        
        // 仅当出度超过阈值时才进行详细检查
        if (out_degree > STAR_OUT_DEGREE_THRESHOLD)
        {
            // 使用集合去重，避免重复记录同一叶子节点
            std::unordered_set<int> seen_leaf_ids;
            
            // 遍历当前节点的所有出边
            for (int j = offset[i]; j < offset[i + 1]; ++j)
            {
                int dst_id = edges[j].to;
                
                // 判断目标节点是否为叶子节点：出度为0（offset差值为0）
                if (offset[dst_id + 1] == offset[dst_id])
                {
                    // insert返回pair<iterator, bool>，second为true表示插入成功（首次出现）
                    if (seen_leaf_ids.insert(dst_id).second)
                    {
                        node.connected_nodes.push_back(dst_id);
                    }
                }
            }
        }

        // 如果连接的叶子节点数量也超过阈值，判定为星型结构
        if (node.connected_nodes.size() >= STAR_OUT_DEGREE_THRESHOLD)
        {
            star_nodes.push_back(node);
        }
    }

    return star_nodes;
}

// std::vector<StarNode> check_star(const CSRGraph &graph)
// {
//     const std::size_t node_count = graph.getNodeCount();
//     const std::vector<int> &offset = graph.getOffset();
//     const std::vector<Edge> &edges = graph.getEdges();

//     // 构建无向邻接集合，避免入度和出度重复计数。
//     std::vector<std::unordered_set<int>> undirected_neighbors(node_count);
//     for (std::size_t from = 0; from < node_count; ++from)
//     {
//         for (int edge_idx = offset[from]; edge_idx < offset[from + 1]; ++edge_idx)
//         {
//             const int to = edges[edge_idx].to;
//             if (to == static_cast<int>(from))
//             {
//                 continue;
//             }

//             undirected_neighbors[from].insert(to);
//             undirected_neighbors[static_cast<std::size_t>(to)].insert(static_cast<int>(from));
//         }
//     }

//     std::vector<StarNode> star_nodes;
//     for (std::size_t i = 0; i < node_count; ++i)
//     {
//         if (undirected_neighbors[i].size() < STAR_OUT_DEGREE_THRESHOLD)
//         {
//             continue;
//         }

//         StarNode node;
//         node.node_id = static_cast<int>(i);

//         bool all_neighbors_are_leaf = true;
//         for (int neighbor_id : undirected_neighbors[i])
//         {
//             const auto &neighbor_set = undirected_neighbors[static_cast<std::size_t>(neighbor_id)];
//             if (neighbor_set.size() != 1 || neighbor_set.find(static_cast<int>(i)) == neighbor_set.end())
//             {
//                 all_neighbors_are_leaf = false;
//                 break;
//             }

//             node.connected_nodes.push_back(neighbor_id);
//         }

//         if (all_neighbors_are_leaf)
//         {
//             std::sort(node.connected_nodes.begin(), node.connected_nodes.end());
//             star_nodes.push_back(node);
//         }
//     }

//     return star_nodes;
// }

/**
 * 打印星型结构检测结果
 * 功能：格式化输出星型结构检测结果，显示中心节点及其连接的叶子节点
 * 核心思想：遍历星型节点向量，输出中心节点IP和所有连接节点的IP
 * 入口参数：
 *     graph - CSR图结构对象
 *     star_nodes - 星型节点向量
 * 出口参数：
 *     无返回值，直接输出到控制台
 */
void printf_star_result(const CSRGraph &graph, const std::vector<StarNode> &star_nodes)
{
    if (star_nodes.empty())
    {
        std::cout << "No star-like nodes found." << std::endl;
        return;
    }

    std::cout << "Star Nodes Found:" << std::endl;
    for (const auto &node : star_nodes)
    {
        std::cout << "Center Node ID: " << node.node_id
                  << " IP: " << graph.getIpById(static_cast<std::size_t>(node.node_id))
                  << std::endl;

        for (std::size_t i = 0; i < node.connected_nodes.size(); ++i)
        {
            int connected_node_id = node.connected_nodes[i];
            std::cout << "  Connected Node " << (i + 1)
                      << " IP: " << graph.getIpById(static_cast<std::size_t>(connected_node_id))
                      << std::endl;
        }
    }
}
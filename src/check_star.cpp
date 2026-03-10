#include "check_star.h"

#include <algorithm>

#define STAR_OUT_DEGREE_THRESHOLD 20

std::vector<StarNode> check_star(const CSRGraph &graph)
{
    const std::size_t node_count = graph.getNodeCount();
    const std::vector<int> &offset = graph.getOffset();
    const std::vector<Edge> &edges = graph.getEdges();

    std::vector<StarNode> star_nodes;
    for (std::size_t i = 0; i < node_count; ++i)
    {
        StarNode node;
        node.node_id = static_cast<int>(i);

        const int out_degree = offset[i + 1] - offset[i];
        if (out_degree > STAR_OUT_DEGREE_THRESHOLD)
        {
            std::unordered_set<int> seen_leaf_ids;
            for (int j = offset[i]; j < offset[i + 1]; ++j)
            {
                int dst_id = edges[j].to;
                if (offset[dst_id + 1] == offset[dst_id])
                {
                    if (seen_leaf_ids.insert(dst_id).second)
                    {
                        node.connected_nodes.push_back(dst_id);
                    }
                }
            }
        }

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
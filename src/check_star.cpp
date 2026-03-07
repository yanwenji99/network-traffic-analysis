#include "check_star.h"
#include <unordered_set>

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
#include "find_graph.h"

#include <algorithm>
#include <fstream>
#include <numeric>

namespace
{
    std::string escape_json(const std::string &text)
    {
        std::string escaped;
        escaped.reserve(text.size() + 8);
        for (char ch : text)
        {
            switch (ch)
            {
            case '\\':
                escaped += "\\\\";
                break;
            case '"':
                escaped += "\\\"";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                escaped += "\\r";
                break;
            case '\t':
                escaped += "\\t";
                break;
            default:
                escaped += ch;
                break;
            }
        }
        return escaped;
    }

    class DisjointSet
    {
    public:
        explicit DisjointSet(std::size_t n)
            : parent(n), rank(n, 0)
        {
            std::iota(parent.begin(), parent.end(), 0);
        }

        int find(int x)
        {
            const int px = parent[static_cast<std::size_t>(x)];
            if (px == x)
            {
                return x;
            }
            parent[static_cast<std::size_t>(x)] = find(px);
            return parent[static_cast<std::size_t>(x)];
        }

        void unite(int a, int b)
        {
            int root_a = find(a);
            int root_b = find(b);
            if (root_a == root_b)
            {
                return;
            }

            const int rank_a = rank[static_cast<std::size_t>(root_a)];
            const int rank_b = rank[static_cast<std::size_t>(root_b)];
            if (rank_a < rank_b)
            {
                std::swap(root_a, root_b);
            }

            parent[static_cast<std::size_t>(root_b)] = root_a;
            if (rank_a == rank_b)
            {
                ++rank[static_cast<std::size_t>(root_a)];
            }
        }

    private:
        std::vector<int> parent;
        std::vector<int> rank;
    };
} // namespace

SubgraphResult find_subgraph_by_ip(const CSRGraph &graph, const char *target_ip)
{
    SubgraphResult result;
    result.target_ip = target_ip == nullptr ? "" : std::string(target_ip);

    if (result.target_ip.empty())
    {
        return result;
    }

    const int target_id = graph.getIdByIp(result.target_ip);
    if (target_id < 0)
    {
        return result;
    }

    const std::size_t node_count = graph.getNodeCount();
    const std::vector<int> &offset = graph.getOffset();
    const std::vector<Edge> &edges = graph.getEdges();

    // 用并查集把所有有连接的节点合并到同一连通分量（忽略边方向）
    DisjointSet dsu(node_count);
    for (std::size_t from = 0; from < node_count; ++from)
    {
        for (int i = offset[from]; i < offset[from + 1]; ++i)
        {
            const int to = edges[i].to;
            if (to >= 0 && static_cast<std::size_t>(to) < node_count)
            {
                dsu.unite(static_cast<int>(from), to);
            }
        }
    }

    const int target_root = dsu.find(target_id);

    // 标记与目标节点处于同一连通分量的所有节点
    std::vector<bool> in_subgraph(node_count, 0);
    for (std::size_t node_id = 0; node_id < node_count; ++node_id)
    {
        if (dsu.find(static_cast<int>(node_id)) == target_root)
        {
            in_subgraph[node_id] = 1;
            result.node_ids.push_back(static_cast<int>(node_id));
        }
    }

    const std::size_t reachable_count = result.node_ids.empty() ? 0 : result.node_ids.size() - 1;
    result.outgoing_reachable_count = reachable_count;
    result.incoming_reachable_count = reachable_count;

    // 获取每个节点对应的IP地址
    std::sort(result.node_ids.begin(), result.node_ids.end());
    for (int node_id : result.node_ids)
    {
        result.node_ips.push_back(graph.getIpById(static_cast<std::size_t>(node_id)));
    }

    // 收集子图内的所有边
    for (int from_id : result.node_ids)
    {
        const std::size_t from = static_cast<std::size_t>(from_id);
        for (int i = offset[from]; i < offset[from + 1]; ++i)
        {
            const int to_id = edges[i].to;
            if (to_id >= 0 && static_cast<std::size_t>(to_id) < node_count && in_subgraph[static_cast<std::size_t>(to_id)])
            {
                result.edges.push_back({from_id, to_id, edges[i].flow});
            }
        }
    }

    result.target_node_id = target_id;
    result.found = true;
    return result;
}

void printf_subgraph_result(const CSRGraph &graph, const SubgraphResult &result, std::size_t max_edges_to_print)
{
    if (!result.found)
    {
        std::cout << "Target IP not found in graph: " << result.target_ip << std::endl;
        return;
    }

    std::cout << "Connected subgraph for target IP " << result.target_ip
              << " (node_id=" << result.target_node_id << ")" << std::endl;
    std::cout << "Reachable in same connected component: " << result.outgoing_reachable_count << std::endl;
    std::cout << "Nodes: " << result.node_ids.size()
              << ", Edges: " << result.edges.size() << std::endl;

    std::cout << "Node list:" << std::endl;
    for (int node_id : result.node_ids)
    {
        std::cout << "  [" << node_id << "] "
                  << graph.getIpById(static_cast<std::size_t>(node_id)) << std::endl;
    }

    std::cout << "Edge list (showing up to " << max_edges_to_print << "):" << std::endl;
    const std::size_t edge_show_count = std::min(max_edges_to_print, result.edges.size());
    for (std::size_t i = 0; i < edge_show_count; ++i)
    {
        const SubgraphEdge &edge = result.edges[i];
        std::cout << "  [" << i + 1 << "] "
                  << graph.getIpById(static_cast<std::size_t>(edge.from_id))
                  << " -> "
                  << graph.getIpById(static_cast<std::size_t>(edge.to_id))
                  << " | protocol=" << static_cast<int>(edge.flow.protocol)
                  << ", data_size=" << edge.flow.data_size
                  << ", duration=" << edge.flow.duration
                  << std::endl;
    }

    if (result.edges.size() > edge_show_count)
    {
        std::cout << "  ... " << (result.edges.size() - edge_show_count)
                  << " more edges not shown" << std::endl;
    }
}

bool export_subgraph_json(const CSRGraph &graph, const SubgraphResult &result, const std::string &json_path)
{
    if (!result.found)
    {
        std::cerr << "Subgraph export failed: target not found" << std::endl;
        return false;
    }

    std::ofstream out(json_path);
    if (!out.is_open())
    {
        std::cerr << "Failed to open subgraph json output file: " << json_path << std::endl;
        return false;
    }

    const std::size_t node_count = graph.getNodeCount();
    std::vector<char> in_subgraph(node_count, 0);
    for (int node_id : result.node_ids)
    {
        if (node_id >= 0 && static_cast<std::size_t>(node_id) < node_count)
        {
            in_subgraph[static_cast<std::size_t>(node_id)] = 1;
        }
    }

    const std::vector<int> &offset = graph.getOffset();
    const std::vector<Edge> &edges = graph.getEdges();
    std::vector<int> in_degree(node_count, 0);
    std::vector<int> out_degree(node_count, 0);

    for (int from_id : result.node_ids)
    {
        const std::size_t from = static_cast<std::size_t>(from_id);
        for (int i = offset[from]; i < offset[from + 1]; ++i)
        {
            const int to_id = edges[i].to;
            if (to_id >= 0 && static_cast<std::size_t>(to_id) < node_count && in_subgraph[static_cast<std::size_t>(to_id)])
            {
                ++out_degree[from];
                ++in_degree[static_cast<std::size_t>(to_id)];
            }
        }
    }

    out << "{\n";
    out << "  \"target_ip\": \"" << escape_json(result.target_ip) << "\",\n";
    out << "  \"target_node_id\": " << result.target_node_id << ",\n";
    out << "  \"mode\": \"undirected_connected_component\",\n";
    out << "  \"outgoing_reachable_count\": " << result.outgoing_reachable_count << ",\n";
    out << "  \"incoming_reachable_count\": " << result.incoming_reachable_count << ",\n";
    out << "  \"node_count\": " << result.node_ids.size() << ",\n";
    out << "  \"edge_count\": " << result.edges.size() << ",\n";

    out << "  \"nodes\": [\n";
    for (std::size_t i = 0; i < result.node_ids.size(); ++i)
    {
        const int node_id = result.node_ids[i];
        const std::string ip = graph.getIpById(static_cast<std::size_t>(node_id));
        out << "    {\"node_id\": " << node_id
            << ", \"ip\": \"" << escape_json(ip) << "\""
            << ", \"in_degree\": " << in_degree[static_cast<std::size_t>(node_id)]
            << ", \"out_degree\": " << out_degree[static_cast<std::size_t>(node_id)]
            << ", \"degree\": "
            << (in_degree[static_cast<std::size_t>(node_id)] + out_degree[static_cast<std::size_t>(node_id)])
            << "}";
        if (i + 1 < result.node_ids.size())
        {
            out << ",";
        }
        out << "\n";
    }
    out << "  ],\n";

    out << "  \"edges\": [\n";
    for (std::size_t i = 0; i < result.edges.size(); ++i)
    {
        const SubgraphEdge &edge = result.edges[i];
        const std::string src_ip = graph.getIpById(static_cast<std::size_t>(edge.from_id));
        const std::string dst_ip = graph.getIpById(static_cast<std::size_t>(edge.to_id));
        out << "    {\"source_id\": " << edge.from_id
            << ", \"source_ip\": \"" << escape_json(src_ip) << "\""
            << ", \"destination_id\": " << edge.to_id
            << ", \"destination_ip\": \"" << escape_json(dst_ip) << "\""
            << ", \"protocol\": " << static_cast<int>(edge.flow.protocol)
            << ", \"src_port\": " << edge.flow.src_port
            << ", \"dst_port\": " << edge.flow.dst_port
            << ", \"data_size\": " << edge.flow.data_size
            << ", \"duration\": " << edge.flow.duration
            << "}";
        if (i + 1 < result.edges.size())
        {
            out << ",";
        }
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";

    return true;
}

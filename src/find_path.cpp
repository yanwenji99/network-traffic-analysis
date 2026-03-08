#include "find_path.h"

#include <algorithm>
#include <queue>

const double INF = std::numeric_limits<double>::max();

PathResult BFS(const CSRGraph &graph, const char *src_ip, const char *dst_ip)
{
    PathResult result;

    // 输入参数有效性检查
    const std::size_t node_count = graph.getNodeCount();
    if (node_count == 0)
    {
        return result;
    }

    if (src_ip == NULL || dst_ip == NULL)
    {
        return result;
    }

    const int src_id = graph.getIdByIp(src_ip);
    const int dst_id = graph.getIdByIp(dst_ip);

    // 检查IP是否存在于图中
    if (src_id < 0)
    {
        return result;
    }

    if (dst_id < 0)
    {
        return result;
    }

    // 获取图的CSR表示
    const std::vector<int> &offset = graph.getOffset();
    const std::vector<Edge> &edges = graph.getEdges();

    // BFS初始化
    std::vector<bool> visited(node_count, false); // 访问标记数组
    std::vector<int> parent(node_count, -1);      // 父节点数组，用于重建路径
    std::queue<int> bfs_queue;                    // BFS队列

    // 从源节点开始BFS
    visited[src_id] = true;
    parent[src_id] = src_id;
    bfs_queue.push(src_id);

    // BFS主循环
    while (!bfs_queue.empty())
    {
        int current = bfs_queue.front();
        bfs_queue.pop();

        if (current == dst_id)
        {
            break;
        }

        // 遍历当前节点的所有邻居
        // offset[current]到offset[current+1]的范围是当前节点的所有邻接边
        for (int idx = offset[current]; idx < offset[current + 1]; ++idx)
        {
            int next = edges[idx].to; // 获取邻居节点ID
            if (!visited[next])
            {
                visited[next] = true;
                parent[next] = current;
                bfs_queue.push(next);
            }
        }
    }

    if (!visited[dst_id])
    {
        return result; // 未找到路径，返回空结果
    }

    std::vector<int> reversed_path;
    // 从目标节点开始，通过parent数组回溯到源节点
    for (int node = dst_id; node != parent[node]; node = parent[node])
    {
        reversed_path.push_back(node);
    }
    reversed_path.push_back(src_id);                          // 添加源节点
    std::reverse(reversed_path.begin(), reversed_path.end()); // 反转路径，使其从源节点到目标节点
    result.node_ids = reversed_path;

    // 将路径中的节点ID转换为IP地址
    result.node_ips.reserve(result.node_ids.size());
    for (int node_id : result.node_ids)
    {
        const std::string ip = graph.getIpById(static_cast<std::size_t>(node_id));
        result.node_ips.push_back(ip.empty() ? "UNKNOWN" : ip);
    }

    // 计算路径的统计信息（总持续时间和总数据大小）
    for (std::size_t i = 0; i + 1 < result.node_ids.size(); ++i)
    {
        int from = result.node_ids[i];
        int to = result.node_ids[i + 1];

        // 在边的邻接表中查找从from到to的边
        for (int idx = offset[from]; idx < offset[from + 1]; ++idx)
        {
            if (edges[idx].to == to)
            {
                result.total_duration += edges[idx].flow.duration;
                result.total_data_size += edges[idx].flow.data_size;
                break;
            }
        }
    }

    result.found = true;
    return result;
}

PathResult Dejkstra(const CSRGraph &graph, const char *src_ip, const char *dst_ip)
{
    PathResult result;

    // 输入参数有效性检查
    const std::size_t node_count = graph.getNodeCount();
    if (node_count == 0)
    {
        return result;
    }

    if (src_ip == NULL || dst_ip == NULL)
    {
        return result;
    }

    const int src_id = graph.getIdByIp(src_ip);
    const int dst_id = graph.getIdByIp(dst_ip);

    // 检查IP是否存在于图中
    if (src_id < 0)
    {
        return result;
    }

    if (dst_id < 0)
    {
        return result;
    }

    // 获取图的CSR表示
    const std::vector<int> &offset = graph.getOffset();
    const std::vector<Edge> &edges = graph.getEdges();

    // Dijkstra初始化
    std::vector<double> distance(node_count, INF);                                               // 距离数组，初始值为无穷大
    std::vector<int> parent(node_count, -1);                                                     // 父节点数组，用于重建路径
    std::priority_queue<DijkstraNode, std::vector<DijkstraNode>, std::greater<DijkstraNode>> pq; // 最小堆优先队列

    // 从源节点开始Dijkstra
    distance[src_id] = 0.0;
    parent[src_id] = src_id;
    pq.push(DijkstraNode(src_id, 0.0));

    while (!pq.empty())
    {
        DijkstraNode current = pq.top();
        pq.pop();

        // 如果当前节点的距离大于已记录的最短距离，跳过（优化）
        if (current.distance > distance[current.node_id])
        {
            continue;
        }

        if (current.node_id == dst_id)
        {
            break; // 找到目标节点，退出循环
        }

        // 遍历当前节点的所有邻居
        for (int idx = offset[current.node_id]; idx < offset[current.node_id + 1]; ++idx)
        {
            int next = edges[idx].to;                                                                        // 获取邻居节点ID
            double new_distance = current.distance + edges[idx].flow.data_size / (edges[idx].flow.duration); // 计算新距离

            if (new_distance < distance[next])
            {
                distance[next] = new_distance;
                parent[next] = current.node_id;
                pq.push(DijkstraNode(next, new_distance)); // 将更新后的节点加入优先队列
            }
        }
    }

    // 检查是否找到路径
    if (distance[dst_id] == INF || parent[dst_id] == -1)
    {
        return result; // 未找到路径，返回空结果
    }

    // 路径重建：从目标节点回溯到源节点
    std::vector<int> reversed_path;
    for (int node = dst_id; node != parent[node]; node = parent[node])
    {
        reversed_path.push_back(node);
    }
    reversed_path.push_back(src_id);                          // 添加源节点
    std::reverse(reversed_path.begin(), reversed_path.end()); // 反转路径，使其从源节点到目标节点
    result.node_ids = reversed_path;

    // 将路径中的节点ID转换为IP地址
    result.node_ips.reserve(result.node_ids.size());
    for (int node_id : result.node_ids)
    {
        const std::string ip = graph.getIpById(static_cast<std::size_t>(node_id));
        result.node_ips.push_back(ip.empty() ? "UNKNOWN" : ip);
    }

    // 计算路径的统计信息（总持续时间和总数据大小）
    for (std::size_t i = 0; i + 1 < result.node_ids.size(); ++i)
    {
        int from = result.node_ids[i];
        int to = result.node_ids[i + 1];

        // 在边的邻接表中查找从from到to的边
        for (int idx = offset[from]; idx < offset[from + 1]; ++idx)
        {
            if (edges[idx].to == to)
            {
                result.total_duration += edges[idx].flow.duration;
                result.total_data_size += edges[idx].flow.data_size;
                break;
            }
        }
    }

    result.found = true;
    return result;
}

void printf_path(const PathResult result)
{
    if (!result.found)
    {
        std::cout << "Path not found!" << std::endl;
        return;
    }

    std::cout << "\n========== Path Finding Result ==========" << std::endl;
    std::cout << "Path Length: " << result.node_ids.size() << " nodes" << std::endl;
    std::cout << "\nPath Details:" << std::endl;

    // 显示详细的路径信息
    for (std::size_t i = 0; i < result.node_ids.size(); ++i)
    {
        std::cout << "  [" << std::setw(2) << (i + 1) << "] "
                  << "Node ID: " << std::setw(4) << result.node_ids[i]
                  << " -> IP: " << std::setw(15) << std::left << result.node_ips[i] << std::right;

        if (i == 0)
        {
            std::cout << " (Start)";
        }
        else if (i == result.node_ids.size() - 1)
        {
            std::cout << " (End)";
        }
        std::cout << std::endl;
    }
    std::cout << "===========================================" << std::endl;
}

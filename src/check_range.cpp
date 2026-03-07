#include "check_range.h"

std::vector<Flow> check_illegal_flows(const CSRGraph &graph, const char *src_ip, const char *start_ip, const char *end_ip)
{
    std::vector<Flow> illegal_flows;

    int src_id = graph.getIdByIp(src_ip);
    int start_id = graph.getIdByIp(start_ip);
    int end_id = graph.getIdByIp(end_ip);

    if (src_id < 0 || start_id < 0 || end_id < 0)
    {
        return illegal_flows;
    }

    const std::vector<int> &offset = graph.getOffset();
    const std::vector<Edge> &edges = graph.getEdges();

    int lower_id = std::min(start_id, end_id);
    int upper_id = std::max(start_id, end_id);

    for (int i = offset[src_id]; i < offset[src_id + 1]; ++i)
    {
        int to_id = edges[i].to;
        if (to_id >= lower_id && to_id <= upper_id)
        {
            illegal_flows.push_back(edges[i].flow);
        }
    }
    return illegal_flows;
}

void print_illegal_flows(const std::vector<Flow> &illegal_flows)
{
    if (illegal_flows.empty())
    {
        std::cout << "No illegal flows found." << std::endl;
        return;
    }

    std::cout << "Illegal flows:" << std::endl;
    for (const auto &flow : illegal_flows)
    {
        std::cout << "Source IP: " << flow.source_ip
                  << ", Destination IP: " << flow.destination_ip
                  << ", Protocol: " << static_cast<int>(flow.protocol)
                  << ", Source Port: " << flow.src_port
                  << ", Destination Port: " << flow.dst_port
                  << ", Data Size: " << flow.data_size
                  << ", Duration: " << flow.duration
                  << std::endl;
    }
}   
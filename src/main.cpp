#include "graph.h"
#include "read_to_flow.h"
#include "sorting.h"
#include "find_path.h"
#include "find_graph.h"
#include "check_star.h"
#include "check_scan.h"
#include "check_range.h"
#include <map>

namespace
{
    struct CliOptions
    {
        std::string input_file = "./data/network_data.csv";
        std::string json_output;
        std::string path_source_ip;
        std::string path_destination_ip;
        std::string path_json_output;
        std::string range_source_ip;
        std::string range_start_ip;
        std::string range_end_ip;
        bool batch_mode = false;
        bool path_compare_mode = false;
    };

    struct BatchNodeStat
    {
        std::size_t node_id = 0;
        uint64_t total_data_size = 0;
        uint64_t out_data_size = 0;
        double out_ratio = 0.0;
    };

    bool parse_cli_options(int argc, char *argv[], CliOptions &options)
    {
        bool has_input_file = false;
        for (int i = 1; i < argc; ++i)
        {
            std::string arg = argv[i];
            if (arg == "--json-out")
            {
                if (i + 1 >= argc)
                {
                    std::cerr << "Missing value for --json-out" << std::endl;
                    return false;
                }
                options.json_output = argv[++i];
                options.batch_mode = true;
            }
            else if (arg == "--path-source")
            {
                if (i + 1 >= argc)
                {
                    std::cerr << "Missing value for --path-source" << std::endl;
                    return false;
                }
                options.path_source_ip = argv[++i];
            }
            else if (arg == "--path-destination")
            {
                if (i + 1 >= argc)
                {
                    std::cerr << "Missing value for --path-destination" << std::endl;
                    return false;
                }
                options.path_destination_ip = argv[++i];
            }
            else if (arg == "--path-json-out")
            {
                if (i + 1 >= argc)
                {
                    std::cerr << "Missing value for --path-json-out" << std::endl;
                    return false;
                }
                options.path_json_output = argv[++i];
                options.path_compare_mode = true;
            }
            else if (arg == "--range-source")
            {
                if (i + 1 >= argc)
                {
                    std::cerr << "Missing value for --range-source" << std::endl;
                    return false;
                }
                options.range_source_ip = argv[++i];
            }
            else if (arg == "--range-start")
            {
                if (i + 1 >= argc)
                {
                    std::cerr << "Missing value for --range-start" << std::endl;
                    return false;
                }
                options.range_start_ip = argv[++i];
            }
            else if (arg == "--range-end")
            {
                if (i + 1 >= argc)
                {
                    std::cerr << "Missing value for --range-end" << std::endl;
                    return false;
                }
                options.range_end_ip = argv[++i];
            }
            else if (arg.rfind("--", 0) == 0)
            {
                std::cerr << "Unknown option: " << arg << std::endl;
                return false;
            }
            else
            {
                if (has_input_file)
                {
                    std::cerr << "Multiple input files provided. Only one CSV path is allowed." << std::endl;
                    return false;
                }
                options.input_file = arg;
                has_input_file = true;
            }
        }

        if (options.batch_mode && options.json_output.empty())
        {
            std::cerr << "Batch mode requires --json-out <file>." << std::endl;
            return false;
        }

        if (options.batch_mode && options.path_compare_mode)
        {
            std::cerr << "--json-out and --path-json-out cannot be used together." << std::endl;
            return false;
        }

        if (options.path_compare_mode)
        {
            if (options.path_source_ip.empty() || options.path_destination_ip.empty() || options.path_json_output.empty())
            {
                std::cerr << "Path compare mode requires --path-source --path-destination --path-json-out." << std::endl;
                return false;
            }
        }
        else
        {
            if (!options.path_source_ip.empty() || !options.path_destination_ip.empty())
            {
                std::cerr << "--path-source and --path-destination must be used with --path-json-out." << std::endl;
                return false;
            }
        }

        const bool has_range_source = !options.range_source_ip.empty();
        const bool has_range_start = !options.range_start_ip.empty();
        const bool has_range_end = !options.range_end_ip.empty();
        const int provided_range_args = static_cast<int>(has_range_source) + static_cast<int>(has_range_start) + static_cast<int>(has_range_end);
        if (provided_range_args != 0 && provided_range_args != 3)
        {
            std::cerr << "Range check options must provide all of: --range-source --range-start --range-end" << std::endl;
            return false;
        }

        return true;
    }

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

    std::vector<BatchNodeStat> build_node_stats(const CSRGraph &graph, const std::vector<Flow> &all_flows, bool https_only)
    {
        std::vector<BatchNodeStat> stats(graph.getNodeCount());
        for (std::size_t i = 0; i < stats.size(); ++i)
        {
            stats[i].node_id = i;
        }

        for (const auto &flow : all_flows)
        {
            if (https_only)
            {
                const bool is_https = flow.protocol == TCP_PROTOCOL && (flow.src_port == HTTPS_PORT || flow.dst_port == HTTPS_PORT);
                if (!is_https)
                {
                    continue;
                }
            }

            int src_id = graph.getIdByIp(flow.source_ip);
            int dst_id = graph.getIdByIp(flow.destination_ip);
            if (src_id >= 0)
            {
                stats[static_cast<std::size_t>(src_id)].total_data_size += flow.data_size;
                stats[static_cast<std::size_t>(src_id)].out_data_size += flow.data_size;
            }
            if (dst_id >= 0)
            {
                stats[static_cast<std::size_t>(dst_id)].total_data_size += flow.data_size;
            }
        }

        for (auto &item : stats)
        {
            if (item.total_data_size > 0)
            {
                item.out_ratio = static_cast<double>(item.out_data_size) / item.total_data_size;
            }
        }

        return stats;
    }

    void write_uint64_map_json(
        std::ofstream &out,
        const std::map<unsigned int, uint64_t> &data,
        const std::string &field_name,
        bool trailing_comma)
    {
        out << "  \"" << field_name << "\": {\n";
        std::size_t index = 0;
        for (const auto &item : data)
        {
            out << "    \"" << item.first << "\": " << item.second;
            if (index + 1 < data.size())
            {
                out << ",";
            }
            out << "\n";
            ++index;
        }
        out << "  }";
        if (trailing_comma)
        {
            out << ",";
        }
        out << "\n";
    }

    void sort_by_total_desc(std::vector<BatchNodeStat> &stats)
    {
        std::sort(stats.begin(), stats.end(), [](const BatchNodeStat &a, const BatchNodeStat &b)
                  {
                      if (a.total_data_size == b.total_data_size)
                      {
                          return a.node_id < b.node_id;
                      }
                      return a.total_data_size > b.total_data_size; });
    }

    void write_path_result_json(std::ofstream &out, const std::string &field_name, const PathResult &result, bool trailing_comma)
    {
        out << "  \"" << field_name << "\": {\n";
        out << "    \"found\": " << (result.found ? "true" : "false") << ",\n";

        const int hops = result.found ? static_cast<int>(result.node_ids.size()) - 1 : -1;
        out << "    \"hops\": " << hops << ",\n";
        out << "    \"congestion\": " << std::fixed << std::setprecision(6) << result.jamb_score << ",\n";
        out << "    \"total_data_size\": " << result.total_data_size << ",\n";
        out << "    \"total_duration\": " << std::fixed << std::setprecision(6) << result.total_duration << ",\n";

        out << "    \"node_ips\": [";
        for (std::size_t i = 0; i < result.node_ips.size(); ++i)
        {
            out << "\"" << escape_json(result.node_ips[i]) << "\"";
            if (i + 1 < result.node_ips.size())
            {
                out << ", ";
            }
        }
        out << "]\n";
        out << "  }";
        if (trailing_comma)
        {
            out << ",";
        }
        out << "\n";
    }

    bool write_path_compare_json(
        const CSRGraph &graph,
        const std::string &input_file,
        const std::string &src_ip,
        const std::string &dst_ip,
        const std::string &json_path)
    {
        std::ofstream out(json_path);
        if (!out.is_open())
        {
            std::cerr << "Failed to open path json output file: " << json_path << std::endl;
            return false;
        }

        PathResult bfs_result = BFS(graph, src_ip.c_str(), dst_ip.c_str());
        PathResult dijkstra_result = Dejkstra(graph, src_ip.c_str(), dst_ip.c_str());

        out << "{\n";
        out << "  \"input_file\": \"" << escape_json(input_file) << "\",\n";
        out << "  \"source_ip\": \"" << escape_json(src_ip) << "\",\n";
        out << "  \"destination_ip\": \"" << escape_json(dst_ip) << "\",\n";
        write_path_result_json(out, "bfs", bfs_result, true);
        write_path_result_json(out, "dijkstra", dijkstra_result, false);
        out << "}\n";

        return true;
    }

    bool write_batch_json(
        const CSRGraph &graph,
        const std::vector<Flow> &all_flows,
        const std::string &input_file,
        const std::string &json_path,
        const CliOptions &options)
    {
        std::ofstream out(json_path);
        if (!out.is_open())
        {
            std::cerr << "Failed to open json output file: " << json_path << std::endl;
            return false;
        }

        uint64_t total_data_size = 0;
        double total_duration = 0.0;
        std::map<unsigned int, uint64_t> protocol_data_size;
        std::map<unsigned int, uint64_t> protocol_flow_count;

        for (const auto &flow : all_flows)
        {
            total_data_size += flow.data_size;
            total_duration += flow.duration;

            const unsigned int protocol = static_cast<unsigned int>(flow.protocol);
            protocol_data_size[protocol] += flow.data_size;
            protocol_flow_count[protocol] += 1;
        }

        std::vector<BatchNodeStat> all_stats = build_node_stats(graph, all_flows, false);
        sort_by_total_desc(all_stats);

        std::vector<BatchNodeStat> https_stats = build_node_stats(graph, all_flows, true);
        sort_by_total_desc(https_stats);

        std::vector<BatchNodeStat> one_way_heavy;
        one_way_heavy.reserve(all_stats.size());
        for (const auto &item : all_stats)
        {
            if (item.total_data_size > 0 && item.out_ratio > RATIO_THRESHOLD)
            {
                one_way_heavy.push_back(item);
            }
        }
        sort_by_total_desc(one_way_heavy);

        std::vector<StarNode> star_nodes = check_star(graph);
        std::vector<int> scan_nodes = check_scan(graph);
        const std::string default_range_source_ip = "119.97.181.245";
        const std::string default_range_start_ip = "115.156.141.129";
        const std::string default_range_end_ip = "183.95.73.29";

        const std::string range_source_ip = options.range_source_ip.empty() ? default_range_source_ip : options.range_source_ip;
        const std::string range_start_ip = options.range_start_ip.empty() ? default_range_start_ip : options.range_start_ip;
        const std::string range_end_ip = options.range_end_ip.empty() ? default_range_end_ip : options.range_end_ip;
        std::vector<Flow> range_flows = check_illegal_flows(graph, range_source_ip.c_str(), range_start_ip.c_str(), range_end_ip.c_str());

        out << "{\n";
        out << "  \"input_file\": \"" << escape_json(input_file) << "\",\n";
        out << "  \"flow_count\": " << all_flows.size() << ",\n";
        out << "  \"node_count\": " << graph.getNodeCount() << ",\n";
        out << "  \"total_data_size\": " << total_data_size << ",\n";
        out << "  \"total_duration\": " << std::fixed << std::setprecision(6) << total_duration << ",\n";

        write_uint64_map_json(out, protocol_data_size, "protocol_data_size", true);
        write_uint64_map_json(out, protocol_flow_count, "protocol_flow_count", true);

        const std::size_t top_limit = 10;

        out << "  \"all_nodes_by_traffic\": [\n";
        std::vector<BatchNodeStat> top_all_nodes;
        top_all_nodes.reserve(top_limit);
        for (const auto &item : all_stats)
        {
            if (item.total_data_size == 0)
            {
                continue;
            }
            top_all_nodes.push_back(item);
            if (top_all_nodes.size() >= top_limit)
            {
                break;
            }
        }
        for (std::size_t i = 0; i < top_all_nodes.size(); ++i)
        {
            const auto &item = top_all_nodes[i];
            const std::string ip = graph.getIpById(item.node_id);
            out << "    {\"node\": \"" << escape_json(ip) << "\", \"total_traffic\": " << item.total_data_size << "}";
            if (i + 1 < top_all_nodes.size())
            {
                out << ",";
            }
            out << "\n";
        }
        out << "  ],\n";

        out << "  \"https_nodes_by_traffic\": [\n";
        std::size_t https_written = 0;
        for (const auto &item : https_stats)
        {
            if (item.total_data_size == 0)
            {
                continue;
            }
            if (https_written >= top_limit)
            {
                break;
            }
            const std::string ip = graph.getIpById(item.node_id);
            out << "    {\"node\": \"" << escape_json(ip) << "\", \"total_traffic\": " << item.total_data_size << "}";
            ++https_written;
            if (https_written < top_limit)
            {
                bool has_more = false;
                for (std::size_t k = https_written; k < https_stats.size(); ++k)
                {
                    if (https_stats[k].total_data_size > 0)
                    {
                        has_more = true;
                        break;
                    }
                }
                if (has_more)
                {
                    out << ",";
                }
            }
            out << "\n";
        }
        out << "  ],\n";

        out << "  \"one_way_heavy_nodes_by_traffic\": [\n";
        const std::size_t one_way_count = std::min(top_limit, one_way_heavy.size());
        for (std::size_t i = 0; i < one_way_count; ++i)
        {
            const auto &item = one_way_heavy[i];
            const std::string ip = graph.getIpById(item.node_id);
            out << "    {\"node\": \"" << escape_json(ip) << "\", \"total_traffic\": " << item.total_data_size
                << ", \"outgoing_traffic\": " << item.out_data_size << ", \"outgoing_ratio\": "
                << std::fixed << std::setprecision(6) << item.out_ratio << "}";
            if (i + 1 < one_way_count)
            {
                out << ",";
            }
            out << "\n";
        }
        out << "  ],\n";

        out << "  \"star_nodes\": [\n";
        for (std::size_t i = 0; i < star_nodes.size(); ++i)
        {
            const auto &node = star_nodes[i];
            out << "    {\"center_node\": \""
                << escape_json(graph.getIpById(static_cast<std::size_t>(node.node_id)))
                << "\", \"leaf_count\": " << node.connected_nodes.size() << ", \"leaf_nodes\": [";

            for (std::size_t j = 0; j < node.connected_nodes.size(); ++j)
            {
                const std::string leaf_ip = graph.getIpById(static_cast<std::size_t>(node.connected_nodes[j]));
                out << "\"" << escape_json(leaf_ip) << "\"";
                if (j + 1 < node.connected_nodes.size())
                {
                    out << ", ";
                }
            }
            out << "]}";
            if (i + 1 < star_nodes.size())
            {
                out << ",";
            }
            out << "\n";
        }
        out << "  ],\n";

        out << "  \"range_check_config\": {\"source_ip\": \"" << escape_json(range_source_ip)
            << "\", \"start_ip\": \"" << escape_json(range_start_ip)
            << "\", \"end_ip\": \"" << escape_json(range_end_ip) << "\"},\n";

        out << "  \"range_flows\": [\n";
        for (std::size_t i = 0; i < range_flows.size(); ++i)
        {
            const auto &flow = range_flows[i];
            out << "    {\"source_ip\": \"" << escape_json(std::string(flow.source_ip))
                << "\", \"destination_ip\": \"" << escape_json(std::string(flow.destination_ip))
                << "\", \"protocol\": " << static_cast<unsigned int>(flow.protocol)
                << ", \"src_port\": " << flow.src_port
                << ", \"dst_port\": " << flow.dst_port
                << ", \"data_size\": " << flow.data_size
                << ", \"duration\": " << std::fixed << std::setprecision(6) << flow.duration << "}";
            if (i + 1 < range_flows.size())
            {
                out << ",";
            }
            out << "\n";
        }
        out << "  ],\n";

        out << "  \"scan_nodes\": [\n";
        for (std::size_t i = 0; i < scan_nodes.size(); ++i)
        {
            const std::size_t node_id = static_cast<std::size_t>(scan_nodes[i]);
            out << "    {\"node\": \"" << escape_json(graph.getIpById(node_id))
                << "\", \"node_id\": " << node_id << "}";
            if (i + 1 < scan_nodes.size())
            {
                out << ",";
            }
            out << "\n";
        }
        out << "  ]\n";
        out << "}\n";

        return true;
    }
} // namespace

#define RATIO_SORT 0
#define HTTPS_SORT 1
#define ALL_SORT 0
#define BFS_PATH 1
#define DEJKSTRA_PATH 0
#define CHECK_STAR 0
#define CHECK_SCAN 0
#define CHECK_RANGE 1

int main(int argc, char *argv[])
{
    CliOptions options;
    if (!parse_cli_options(argc, argv, options))
    {
        return 1;
    }

    flows.clear();
    readfile(options.input_file, flows);
    if (flows.empty())
    {
        std::cerr << "No valid flow data was loaded from: " << options.input_file << std::endl;
        return 1;
    }

    CSRGraph graph;
    for (const auto &flow : flows)
    {
        graph.addFlow(flow);
    }
    graph.buildCSR();

    if (options.batch_mode)
    {
        if (!write_batch_json(graph, flows, options.input_file, options.json_output, options))
        {
            return 1;
        }
        std::cout << "Batch analysis exported to: " << options.json_output << std::endl;
        return 0;
    }

    if (options.path_compare_mode)
    {
        if (!write_path_compare_json(
                graph,
                options.input_file,
                options.path_source_ip,
                options.path_destination_ip,
                options.path_json_output))
        {
            return 1;
        }
        std::cout << "Path comparison exported to: " << options.path_json_output << std::endl;
        return 0;
    }

    std::string func;
    do
    {
        std::cout << "Enter operation:(sort path subgraph subgraph_json read check exit) ";
        std::cin >> func;
        if (func == "sort")
        {
            std::vector<NodeFlow> result;
#if RATIO_SORT
            std::cout << "Sorting nodes by out_ratio > 0.8..." << std::endl;
            result = sort_ratio_flow(graph, flows);
#elif HTTPS_SORT
            std::cout << "Sorting nodes by HTTPS flow..." << std::endl;
            result = sort_HTTPS_flow(graph, flows);
#else
            std::cout << "Sorting nodes by total flow..." << std::endl;
            result = sort_all_flow(graph, flows);
#endif
            printf_sort_result(result);
        }
        else if (func == "path")
        {
            std::cout << "Enter source IP: ";
            std::string src_ip;
            std::cin >> src_ip;
            std::cout << "Enter destination IP: ";
            std::string dst_ip;
            std::cin >> dst_ip;
#if BFS_PATH
            PathResult result = BFS(graph, src_ip.c_str(), dst_ip.c_str());
#else
            PathResult result = Dejkstra(graph, src_ip.c_str(), dst_ip.c_str());
#endif
            printf_path(result);
        }
        else if (func == "subgraph")
        {
            std::cout << "Enter target IP: ";
            std::string target_ip;
            std::cin >> target_ip;
            SubgraphResult result = find_subgraph_by_ip(graph, target_ip.c_str());
            printf_subgraph_result(graph, result);
        }
        else if (func == "subgraph_json")
        {
            std::cout << "Enter target IP: ";
            std::string target_ip;
            std::cin >> target_ip;

            const std::string output_json_path = "./data/output/subgraph.json";

            SubgraphResult result = find_subgraph_by_ip(graph, target_ip.c_str());
            printf_subgraph_result(graph, result);
            if (result.found)
            {
                if (export_subgraph_json(graph, result, output_json_path))
                {
                    std::cout << "Subgraph JSON exported to: " << output_json_path << std::endl;
                }
                else
                {
                    std::cout << "Subgraph JSON export failed." << std::endl;
                }
            }
        }
        else if (func == "read")
        {
            std::cout << "Please input the number of flows to display: ";
            int num;
            std::cin >> num;
            print_flows(flows, num);
        }
        else if (func == "check")
        {
#if CHECK_STAR
            std::vector<StarNode> star_nodes = check_star(graph);
            printf_star_result(graph, star_nodes);
#elif CHECK_SCAN
            std::vector<int> scan_nodes = check_scan(graph);
            printf_scan_result(graph, scan_nodes);
#else
            std::cout << "Please input source IP for range check: ";
            std::string src_ip;
            std::cin >> src_ip;
            std::cout << "Please input start IP for range check: ";
            std::string start_ip;
            std::cin >> start_ip;
            std::cout << "Please input end IP for range check: ";
            std::string end_ip;
            std::cin >> end_ip;
            std::vector<Flow> illegal_flows = check_illegal_flows(graph, src_ip.c_str(), start_ip.c_str(), end_ip.c_str());
            print_illegal_flows(illegal_flows);
#endif
        }
        else if (func != "exit")
        {
            std::cout << "Invalid operation. Please enter 'sort', 'path', 'subgraph', 'subgraph_json', 'read', 'check', or 'exit'" << std::endl;
        }
    } while (func != "exit");

    return 0;
}
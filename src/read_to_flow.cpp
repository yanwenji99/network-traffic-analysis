#include "read_to_flow.h"
#include "graph.h"

void readfile(const std::string &filename, std::vector<Flow> &flows)
{
    std::ifstream infile(filename);
    if (!infile.is_open())
    {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }
    std::string line;
    bool is_first_line = true;

    while (std::getline(infile, line))
    {
        if (line.empty())
        {
            continue;
        }

        if (is_first_line)
        {
            is_first_line = false;
            // rfind(..., 0) 表示从位置0开始查找，用于判断字符串是否以指定内容开头
            if (line.rfind("Source,Destination,Protocol,SrcPort,DstPort,DataSize,Duration", 0) == 0)
            {
                continue;
            }
        }

        std::istringstream iss(line); // 使用字符串流解析当前行
        std::vector<std::string> fields;
        std::string field;
        // 按逗号分隔解析每一行
        while (std::getline(iss, field, ','))
        {
            fields.push_back(field);
        }
        if (fields.size() != 7)
        {
            std::cerr << "Failed to parse line (wrong number of fields): " << line << std::endl;
            continue;
        }

        Flow flow{}; // 创建Flow对象并填充数据，初始化为0或空字符串
        std::strncpy(flow.source_ip, fields[0].c_str(), sizeof(flow.source_ip) - 1);
        flow.source_ip[sizeof(flow.source_ip) - 1] = '\0'; // 确保字符串以null结尾
        std::strncpy(flow.destination_ip, fields[1].c_str(), sizeof(flow.destination_ip) - 1);
        flow.destination_ip[sizeof(flow.destination_ip) - 1] = '\0'; // 确保字符串以null结尾

        // 使用try-catch处理数值转换可能出现的异常
        try
        {
            flow.protocol = static_cast<uint8_t>(std::stoul(fields[2]));
            flow.src_port = fields[3].empty() ? 0 : static_cast<uint16_t>(std::stoul(fields[3]));
            flow.dst_port = fields[4].empty() ? 0 : static_cast<uint16_t>(std::stoul(fields[4]));
            flow.data_size = std::stoull(fields[5]); // 使用stoull转换为uint64_t
            flow.duration = std::stod(fields[6]); // 使用stod转换为double
        }
        catch (const std::exception &)
        {
            std::cerr << "Failed to parse line (field type error): " << line << std::endl;
            continue;
        }

        flows.push_back(flow);
    }
    infile.close();
}
void print_flows(const std::vector<Flow> &flows, int num)
{
    if (num <= 0)
    {
        return;
    }

    int shown = 0;
    for (const auto &flow : flows)
    {
        if (shown >= num)
        {
            break;
        }

        std::cout << "Source IP: " << flow.source_ip
                  << ", Destination IP: " << flow.destination_ip
                  << ", Protocol: " << static_cast<int>(flow.protocol)
                  << ", Src Port: " << flow.src_port
                  << ", Dst Port: " << flow.dst_port
                  << ", Data Size: " << flow.data_size
                  << ", Duration: " << flow.duration
                  << std::endl;
        ++shown;
    }
}
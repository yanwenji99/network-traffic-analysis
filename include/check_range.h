#pragma once

#include <algorithm>
#include "graph.h"

std::vector<Flow> check_illegal_flows(const CSRGraph &graph, const char *src_ip, const char *start_ip, const char *end_ip);
void print_illegal_flows(const std::vector<Flow> &illegal_flows);
#pragma once

#include "graph.h"

std::vector<int> check_scan(const CSRGraph &graph);
void printf_scan_result(const CSRGraph &graph, const std::vector<int> &suspicious_nodes);
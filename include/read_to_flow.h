#pragma once

#include <fstream>
#include <sstream>
#include <cstring>
#include "graph.h"

void readfile(const std::string &filename, std::vector<Flow> &flows);
void print_flows(const std::vector<Flow> &flows, int num);

# 网络流量分析与异常检测系统

本项目采用 **C++ 分析核心 + Python 图形界面** 的方式，实现从网络流量数据读取、图建模、异常检测到可视化交互的完整流程。

## 1. 功能总览

- 从 `CSV` 读取会话流量数据并构建 IP 通信图（CSR 结构）
- 节点流量分析与排序（总流量、外发占比、HTTPS 相关）
- 两点路径后端对比查询（BFS / Dijkstra）
- 异常检测：
  - 星型结构节点检测
  - 扫描行为节点检测（高出度 + 小包特征）
  - 区间会话范围检测（可配置源 IP / 起始 IP / 结束 IP）
- 批处理模式导出 `JSON` 分析结果（`--json-out`）
- 路径对比模式导出 `JSON`（`--path-source` / `--path-destination` / `--path-json-out`）
- Tkinter UI：
  - 数据获取与总览
  - 排序分析（总量 / HTTPS / 单向）
  - 异常识别（星型 / 扫描 / 叶子详情）
  - 范围检测（参数输入 + 结果表）
  - 路径查找（后端路径对比）
  - 子图可视化（networkx + DSU）
  - 运行日志
- 支持 `pcap -> csv` 提取脚本（Scapy）

## 2. 项目结构

```text
网络流量分析与异常检测系统/
├─ include/
│  ├─ flow.h
│  ├─ graph.h
│  ├─ read_to_flow.h
│  ├─ sorting.h
│  ├─ find_path.h
│  ├─ check_star.h
│  ├─ check_scan.h
│  └─ check_range.h
├─ src/
│  ├─ main.cpp
│  ├─ graph.cpp
│  ├─ read_to_flow.cpp
│  ├─ sorting.cpp
│  ├─ find_path.cpp
│  ├─ check_star.cpp
│  ├─ check_scan.cpp
│  └─ check_range.cpp
├─ python/
│  └─ ui_gui.py
├─ scripts/
│  └─ pcap_to_csv.py
├─ data/
│  ├─ network_data.csv
│  └─ output/
├─ makefile
└─ requirements.txt
```

## 3. 环境要求

- Windows + PowerShell
- MinGW-w64（`g++`）
- `mingw32-make`
- Python 3.10+
- 推荐使用项目内虚拟环境：`.venv`

`makefile` 默认编译器命令为：`g++`。
如有需要可覆盖为 MinGW 的绝对路径：

```powershell
mingw32-make -f makefile CXX=D:/mingw64/bin/g++.exe
```

`makefile` 的 Python 默认解释器为：`python`。
如果你使用 `.venv`，建议在涉及 Python 的目标中覆盖 `PYTHON` 变量。

## 4. 快速开始

```powershell
Set-Location "<项目目录>"

# 1) 创建并激活虚拟环境
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2) 安装 Python 依赖（UI/pcap/子图可视化）
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 3) 编译 C++
mingw32-make -f makefile

# 4) 批处理导出 JSON
mingw32-make -f makefile batch

# 5) 启动 UI（指定 venv 解释器给 make 目标）
mingw32-make -f makefile ui PYTHON=./.venv/Scripts/python.exe
```

如果已经激活 `.venv`，也可以直接执行：

```powershell
python .\python\ui_gui.py
```

## 5. Make 目标说明

- `mingw32-make -f makefile`：编译项目
- `mingw32-make -f makefile run`：交互模式运行（读取 `DATA`）
- `mingw32-make -f makefile batch`：批处理运行并导出 JSON
- `mingw32-make -f makefile deps`：安装 Python 依赖（建议加 `PYTHON=./.venv/Scripts/python.exe`）
- `mingw32-make -f makefile ui`：启动 Tkinter UI
- `mingw32-make -f makefile pcap2csv`：执行 PCAP 提取 CSV
- `mingw32-make -f makefile batch_pcap`：先提取 CSV，再批处理导出 JSON
- `mingw32-make -f makefile clean`：清理构建产物
- `mingw32-make -f makefile rebuild`：清理并重建

常用可覆盖变量：

- `DATA`：输入 CSV，默认 `./data/network_data.csv`
- `JSON_OUT`：输出 JSON，默认 `./data/output/results.json`
- `PYTHON`：Python 解释器路径，默认 `python`
- `PCAP_IN` / `PCAP_OUT`：PCAP 输入与 CSV 输出路径

示例：

```powershell
mingw32-make -f makefile deps PYTHON=./.venv/Scripts/python.exe
mingw32-make -f makefile ui PYTHON=./.venv/Scripts/python.exe
mingw32-make -f makefile batch DATA=./data/network_data.csv JSON_OUT=./data/output/custom_results.json
mingw32-make -f makefile pcap2csv PCAP_IN=./data/catch_data.pcap PCAP_OUT=./data/network_data.csv
mingw32-make -f makefile batch_pcap PCAP_IN=./data/catch_data.pcap JSON_OUT=./data/output/results.json
```

## 6. 数据准备

### 6.1 CSV 输入格式

首行表头：

```text
Source,Destination,Protocol,SrcPort,DstPort,DataSize,Duration
```

字段说明：

- `Source`：源 IP
- `Destination`：目的 IP
- `Protocol`：协议号
- `SrcPort`：源端口
- `DstPort`：目的端口
- `DataSize`：会话数据量（字节）
- `Duration`：会话持续时间（秒）

### 6.2 从 PCAP 提取 CSV

脚本：`scripts/pcap_to_csv.py`

```powershell
.\.venv\Scripts\python.exe .\scripts\pcap_to_csv.py --input .\data\catch_data.pcap --output .\data\network_data.csv
```

## 7. 运行模式

### 7.1 交互模式

```powershell
.\build\bin\main.exe .\data\network_data.csv
```

交互命令：

- `sort`：排序分析
- `path`：路径查询
- `subgraph`：按目标 IP 查询其弱连通子图（忽略边方向）
- `subgraph_json`：查询并导出子图 JSON（默认 `./data/output/subgraph.json`）
- `read`：查看前 N 条流
- `check`：异常检测（星型 + 扫描，受宏开关控制）
- `exit`：退出

### 7.2 批处理模式

```powershell
.\build\bin\main.exe .\data\network_data.csv --json-out .\data\output\results.json
```

- 传入 `--json-out` 时，不进入交互循环，直接输出 JSON。
- 不传 `--json-out` 时，进入交互模式。

### 7.3 路径对比 JSON 模式（后端）

```powershell
.\build\bin\main.exe .\data\network_data.csv --path-source 183.94.22.88 --path-destination 116.153.60.140 --path-json-out .\data\output\path_compare.json
```

- 该模式不会进入交互循环，直接调用后端 BFS 与 Dijkstra 并输出 JSON。
- 参数说明：
  - `--path-source`：源 IP
  - `--path-destination`：目的 IP
  - `--path-json-out`：路径结果 JSON 输出文件
- 约束：`--json-out` 与 `--path-json-out` 不能同时使用。

## 8. JSON 输出字段

批处理输出文件默认：`data/output/results.json`

主要字段：

- `input_file`：输入数据路径
- `flow_count`：会话总数
- `node_count`：节点总数
- `total_data_size`：总流量
- `total_duration`：总持续时长
- `protocol_data_size`：各协议号总流量（动态）
- `protocol_flow_count`：各协议号会话数（动态）
- `all_nodes_by_traffic`：总量节点 Top10
- `https_nodes_by_traffic`：HTTPS 相关节点 Top10
- `one_way_heavy_nodes_by_traffic`：单向高占比节点 Top10
- `star_nodes`：星型结构节点列表
- `scan_nodes`：扫描可疑节点列表（含 `node`、`node_id`）
- `range_check_config`：范围检测参数（`source_ip` / `start_ip` / `end_ip`）
- `range_flows`：范围检测命中的会话列表

路径对比输出文件（默认由 UI 使用）：`data/output/path_compare.json`

主要字段：

- `input_file`：输入数据路径
- `source_ip` / `destination_ip`：路径查询起止 IP
- `bfs`：BFS 路径结果（`found` / `hops` / `congestion` / `total_data_size` / `total_duration` / `node_ips`）
- `dijkstra`：Dijkstra 路径结果（同上）

## 9. UI 使用说明

入口：`python/ui_gui.py`

```powershell
.\.venv\Scripts\python.exe .\python\ui_gui.py
```

### 9.1 数据获取与总览

- 配置路径：`Input CSV`
- 可选执行 `PCAP -> CSV`
- 一键运行批处理并加载 JSON（内部使用默认 `main.exe` 与输出 JSON 路径）
- 展示统计摘要与协议流量表（协议号动态识别）

### 9.2 排序分析

- 左侧：`总量节点 Top10`
- 中间：`HTTPS 节点 Top10`
- 右侧：`单向高占比节点 Top10`

说明：

- 优先读取 JSON 中的 `all_nodes_by_traffic`。
- 若 JSON 为旧版本且缺少该字段，UI 会基于当前 CSV 自动回退计算 Top10。

### 9.3 异常识别

- 第 1 行：`星型结构节点` + `扫描可疑节点`
- 第 2 行：`叶子节点详情`

### 9.4 范围检测

- 独立页签输入：`源 IP`、`起始 IP`、`结束 IP`
- 点击“应用参数并重新分析”后，UI 会调用批处理并刷新范围检测结果表
- 结果数据来自 `range_flows`

### 9.5 子图可视化（networkx + DSU）

流程：

1. 基于 CSV 构图
2. 输入目标 IP 查询其连通子图
3. 查看节点/边统计与列表
4. 导出子图 HTML

### 9.6 路径查找（后端）

在“路径查找”页可进行：

- 后端 BFS 路径结果
- 后端 Dijkstra 路径结果
- 路径对比（跳数、拥塞值、总时延）

使用步骤：

1. 输入源 IP 与目的 IP
2. 点击“路径对比查询”
3. UI 调用后端程序生成 `data/output/path_compare.json` 并刷新结果

### 9.7 运行日志

显示提取、分析、加载、导出等操作日志。

## 10. 可配置项

### 10.1 `src/main.cpp` 宏开关

- 排序模式：`RATIO_SORT` / `HTTPS_SORT` / `ALL_SORT`
- 路径算法：`BFS_PATH` / `DEJKSTRA_PATH`
- 检测开关：`CHECK_STAR` / `CHECK_SCAN` / `CHECK_RANGE`

建议同一组只启用一个模式宏。

### 10.2 阈值配置

- `include/sorting.h`
  - `RATIO_THRESHOLD`
  - `HTTPS_PORT`
- `src/check_scan.cpp`
  - `SCAN_OUT_DEGREE_THRESHOLD`
  - `SCAN_DATA_SIZE_THRESHOLD`
- `src/check_star.cpp`
  - `STAR_OUT_DEGREE_THRESHOLD`

## 11. 常见问题

- `No valid flow data was loaded...`
  - 检查 CSV 路径是否正确、文件是否为空、字段数是否为 7。
- JSON 加载编码报错（UTF-8/GBK）
  - UI 已做多编码兼容（`utf-8` / `utf-8-sig` / `gbk` / `cp936`）。
- UI 启动失败或子图页不可用
  - 先确认已激活 `.venv` 并执行：`python -m pip install -r requirements.txt`
  - 或执行：`mingw32-make -f makefile deps PYTHON=./.venv/Scripts/python.exe`
- 导出子图时报错 `No module named 'numpy'`
  - 导出布局依赖 `numpy`，请在当前 UI 所用解释器中安装依赖：`python -m pip install -r requirements.txt`
  - 若通过 make 启动 UI，建议显式指定：`mingw32-make -f makefile ui PYTHON=./.venv/Scripts/python.exe`
- 路径页两种算法结果经常相同
  - 已改为后端调用，不再使用 UI 本地算法。
  - 如果源/目的节点之间存在直连边，或最少跳数路径同时也是最小拥塞路径，两者结果本身就可能一致。
- 终端中文乱码
  - 通常是终端编码问题，不影响分析逻辑。

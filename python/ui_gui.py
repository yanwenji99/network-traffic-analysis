from __future__ import annotations

import csv
import html
import json
import math
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import networkx as nx
except ImportError:
    nx = None


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXE = REPO_ROOT / "build" / "bin" / "main.exe"
DEFAULT_INPUT_CSV = REPO_ROOT / "data" / "network_data.csv"
DEFAULT_OUTPUT_JSON = REPO_ROOT / "data" / "output" / "results.json"
DEFAULT_INPUT_PCAP = REPO_ROOT / "data" / "catch_data.pcap"
DEFAULT_PCAP_SCRIPT = REPO_ROOT / "scripts" / "pcap_to_csv.py"

PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}


class DSU:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}

    def add(self, node: str) -> None:
        if node not in self.parent:
            self.parent[node] = node
            self.rank[node] = 0

    def find(self, node: str) -> str:
        parent = self.parent[node]
        if parent != node:
            self.parent[node] = self.find(parent)
        return self.parent[node]

    def union(self, node_a: str, node_b: str) -> None:
        root_a = self.find(node_a)
        root_b = self.find(node_b)
        if root_a == root_b:
            return

        rank_a = self.rank[root_a]
        rank_b = self.rank[root_b]
        if rank_a < rank_b:
            self.parent[root_a] = root_b
        elif rank_a > rank_b:
            self.parent[root_b] = root_a
        else:
            self.parent[root_b] = root_a
            self.rank[root_a] += 1


class TrafficAnalyzerGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("网络流量分析与异常检测系统")
        self.geometry("1220x800")

        self.exe_var = tk.StringVar(value=str(DEFAULT_EXE))
        self.csv_var = tk.StringVar(value=str(DEFAULT_INPUT_CSV))
        self.json_var = tk.StringVar(value=str(DEFAULT_OUTPUT_JSON))
        self.pcap_var = tk.StringVar(value=str(DEFAULT_INPUT_PCAP))
        self.pcap_csv_var = tk.StringVar(value=str(DEFAULT_INPUT_CSV))
        self.status_var = tk.StringVar(value="就绪")
        self.subgraph_target_ip_var = tk.StringVar(value="")
        self.enforce_node_spacing_var = tk.BooleanVar(value=False)
        self.path_source_var = tk.StringVar(value="")
        self.path_destination_var = tk.StringVar(value="")
        self.path_compare_var = tk.StringVar(value="请输入源 IP 与目的 IP 后查询路径对比")

        self.summary_vars = {
            "flow_count": tk.StringVar(value="-"),
            "node_count": tk.StringVar(value="-"),
            "total_data_size": tk.StringVar(value="-"),
            "total_duration": tk.StringVar(value="-"),
        }
        self.subgraph_info_vars = {
            "component_root": tk.StringVar(value="-"),
            "node_count": tk.StringVar(value="-"),
            "edge_count": tk.StringVar(value="-"),
        }
        self.path_hops_vars = {
            "found": tk.StringVar(value="-"),
            "hops": tk.StringVar(value="-"),
            "congestion": tk.StringVar(value="-"),
            "duration": tk.StringVar(value="-"),
        }
        self.path_congestion_vars = {
            "found": tk.StringVar(value="-"),
            "hops": tk.StringVar(value="-"),
            "congestion": tk.StringVar(value="-"),
            "duration": tk.StringVar(value="-"),
        }

        self.star_leaf_map: dict[str, list[str]] = {}
        self.full_graph = None
        self.dsu = DSU()
        self.current_subgraph_nodes: list[str] = []

        self._build_layout()

    def _build_layout(self) -> None:
        root = ttk.Frame(self, padding=10)
        root.pack(fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        self.page_data = ttk.Frame(self.notebook, padding=10)
        self.page_abnormal = ttk.Frame(self.notebook, padding=10)
        self.page_path = ttk.Frame(self.notebook, padding=10)
        self.page_subgraph = ttk.Frame(self.notebook, padding=10)
        self.page_log = ttk.Frame(self.notebook, padding=10)

        self.notebook.add(self.page_data, text="数据获取与总览")
        self.notebook.add(self.page_abnormal, text="异常识别")
        self.notebook.add(self.page_path, text="路径查找")
        self.notebook.add(self.page_subgraph, text="子图可视化")
        self.notebook.add(self.page_log, text="运行日志")

        self._build_data_page()
        self._build_abnormal_page()
        self._build_path_page()
        self._build_subgraph_page()
        self._build_log_page()

        status = ttk.Label(root, textvariable=self.status_var, anchor=tk.W)
        status.pack(fill=tk.X, pady=(8, 0))

    def _build_data_page(self) -> None:
        path_box = ttk.LabelFrame(self.page_data, text="运行路径", padding=10)
        path_box.pack(fill=tk.X)
        self._path_row(path_box, "C++ EXE", self.exe_var, self._pick_exe)
        self._path_row(path_box, "Input CSV", self.csv_var, self._pick_csv)
        self._path_row(path_box, "Output JSON", self.json_var, self._pick_json)

        pcap_box = ttk.LabelFrame(self.page_data, text="PCAP 提取（可选）", padding=10)
        pcap_box.pack(fill=tk.X, pady=(8, 0))
        self._path_row(pcap_box, "Input PCAP", self.pcap_var, self._pick_pcap)
        self._path_row(pcap_box, "Output CSV", self.pcap_csv_var, self._pick_pcap_csv)

        action_box = ttk.Frame(self.page_data)
        action_box.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(action_box, text="从 PCAP 提取 CSV", command=self.extract_pcap).pack(side=tk.LEFT)
        ttk.Button(action_box, text="运行批处理分析", command=self.run_batch).pack(side=tk.LEFT, padx=8)
        ttk.Button(action_box, text="加载 JSON 结果", command=self.load_json).pack(side=tk.LEFT)

        self._build_summary_page(self.page_data)

    def _build_summary_page(self, parent: ttk.Frame) -> None:
        summary_box = ttk.LabelFrame(parent, text="统计摘要", padding=10)
        summary_box.pack(fill=tk.X, pady=(12, 0))

        row = 0
        for key, label in (
            ("flow_count", "flow_count"),
            ("node_count", "node_count"),
            ("total_data_size", "total_data_size"),
            ("total_duration", "total_duration"),
        ):
            ttk.Label(summary_box, text=f"{label}:", width=16).grid(row=row, column=0, sticky=tk.W, pady=2)
            ttk.Label(summary_box, textvariable=self.summary_vars[key]).grid(row=row, column=1, sticky=tk.W, pady=2)
            row += 1

        protocol_box = ttk.LabelFrame(parent, text="协议流量", padding=10)
        protocol_box.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        self.protocol_tree = ttk.Treeview(
            protocol_box,
            columns=("protocol", "name", "traffic", "flow_count"),
            show="headings",
            height=10,
        )
        self.protocol_tree.heading("protocol", text="协议号")
        self.protocol_tree.heading("name", text="协议名")
        self.protocol_tree.heading("traffic", text="总流量")
        self.protocol_tree.heading("flow_count", text="会话数")
        self.protocol_tree.column("protocol", width=120, anchor=tk.CENTER)
        self.protocol_tree.column("name", width=160, anchor=tk.W)
        self.protocol_tree.column("traffic", width=180, anchor=tk.E)
        self.protocol_tree.column("flow_count", width=120, anchor=tk.E)
        self.protocol_tree.pack(fill=tk.BOTH, expand=True)

    def _build_abnormal_page(self) -> None:
        grid_root = ttk.Frame(self.page_abnormal)
        grid_root.pack(fill=tk.BOTH, expand=True)
        for row in range(3):
            grid_root.rowconfigure(row, weight=1, uniform="abn_row")
        for col in range(2):
            grid_root.columnconfigure(col, weight=1, uniform="abn_col")

        left = ttk.LabelFrame(grid_root, text="HTTPS 节点 Top10", padding=10)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 6))

        self.https_tree = ttk.Treeview(left, columns=("node", "traffic"), show="headings", height=12)
        self.https_tree.heading("node", text="节点 IP")
        self.https_tree.heading("traffic", text="总流量")
        self.https_tree.column("node", width=220)
        self.https_tree.column("traffic", width=120, anchor=tk.E)
        self.https_tree.pack(fill=tk.BOTH, expand=True)

        right = ttk.LabelFrame(grid_root, text="单向高占比节点 Top10", padding=10)
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 6))

        self.one_way_tree = ttk.Treeview(
            right,
            columns=("node", "total", "outgoing", "ratio"),
            show="headings",
            height=12,
        )
        self.one_way_tree.heading("node", text="节点 IP")
        self.one_way_tree.heading("total", text="总流量")
        self.one_way_tree.heading("outgoing", text="外发流量")
        self.one_way_tree.heading("ratio", text="外发占比")
        self.one_way_tree.column("node", width=210)
        self.one_way_tree.column("total", width=110, anchor=tk.E)
        self.one_way_tree.column("outgoing", width=110, anchor=tk.E)
        self.one_way_tree.column("ratio", width=90, anchor=tk.E)
        self.one_way_tree.pack(fill=tk.BOTH, expand=True)

        star_box = ttk.LabelFrame(grid_root, text="星型结构节点", padding=10)
        star_box.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(6, 6))

        self.star_tree = ttk.Treeview(star_box, columns=("center", "leaf_count"), show="headings", height=10)
        self.star_tree.heading("center", text="中心节点 IP")
        self.star_tree.heading("leaf_count", text="叶子数量")
        self.star_tree.column("center", width=260)
        self.star_tree.column("leaf_count", width=100, anchor=tk.E)
        self.star_tree.pack(fill=tk.BOTH, expand=True)
        self.star_tree.bind("<<TreeviewSelect>>", self._on_star_select)

        scan_box = ttk.LabelFrame(grid_root, text="扫描可疑节点", padding=10)
        scan_box.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(6, 6))

        self.scan_tree = ttk.Treeview(scan_box, columns=("node",), show="headings", height=10)
        self.scan_tree.heading("node", text="节点 IP")
        self.scan_tree.column("node", width=320)
        self.scan_tree.pack(fill=tk.BOTH, expand=True)

        leaf_box = ttk.LabelFrame(grid_root, text="叶子节点详情", padding=10)
        leaf_box.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(6, 0))

        self.leaf_text = tk.Text(leaf_box, wrap=tk.WORD)
        self.leaf_text.pack(fill=tk.BOTH, expand=True)
        self.leaf_text.configure(state=tk.DISABLED)

    def _build_path_page(self) -> None:
        controls = ttk.LabelFrame(self.page_path, text="路径查询参数", padding=10)
        controls.pack(fill=tk.X)

        ttk.Label(controls, text="源 IP", width=10).grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(controls, textvariable=self.path_source_var, width=24).grid(row=0, column=1, sticky=tk.W, padx=(6, 14))

        ttk.Label(controls, text="目的 IP", width=10).grid(row=0, column=2, sticky=tk.W)
        ttk.Entry(controls, textvariable=self.path_destination_var, width=24).grid(row=0, column=3, sticky=tk.W, padx=(6, 14))

        ttk.Button(controls, text="基于 CSV 构图", command=self.build_graph_for_subgraph).grid(row=0, column=4, padx=(6, 8), sticky=tk.W)
        ttk.Button(controls, text="路径对比查询", command=self.query_path_comparison).grid(row=0, column=5, padx=(0, 8), sticky=tk.W)

        result = ttk.Frame(self.page_path)
        result.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        result.columnconfigure(0, weight=1)
        result.columnconfigure(1, weight=1)

        hops_box = ttk.LabelFrame(result, text="最小跳数路径（BFS）", padding=10)
        hops_box.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self._build_path_result_box(hops_box, self.path_hops_vars, panel_type="hops")

        congestion_box = ttk.LabelFrame(result, text="最小拥塞路径（Dijkstra）", padding=10)
        congestion_box.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        self._build_path_result_box(congestion_box, self.path_congestion_vars, panel_type="congestion")

        compare_box = ttk.LabelFrame(self.page_path, text="路径对比结论", padding=10)
        compare_box.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(compare_box, textvariable=self.path_compare_var, wraplength=1120, justify=tk.LEFT).pack(anchor=tk.W)

    def _build_path_result_box(self, parent: ttk.LabelFrame, var_map: dict[str, tk.StringVar], panel_type: str) -> None:
        ttk.Label(parent, text="是否找到:", width=10).grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Label(parent, textvariable=var_map["found"]).grid(row=0, column=1, sticky=tk.W, pady=2)
        ttk.Label(parent, text="跳数:", width=10).grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Label(parent, textvariable=var_map["hops"]).grid(row=1, column=1, sticky=tk.W, pady=2)
        ttk.Label(parent, text="拥塞值:", width=10).grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Label(parent, textvariable=var_map["congestion"]).grid(row=2, column=1, sticky=tk.W, pady=2)
        ttk.Label(parent, text="总时延:", width=10).grid(row=3, column=0, sticky=tk.W, pady=2)
        ttk.Label(parent, textvariable=var_map["duration"]).grid(row=3, column=1, sticky=tk.W, pady=2)

        route_box = ttk.LabelFrame(parent, text="路径节点序列", padding=8)
        route_box.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
        parent.rowconfigure(4, weight=1)
        parent.columnconfigure(1, weight=1)

        text_widget = tk.Text(route_box, wrap=tk.WORD, height=16)
        text_widget.pack(fill=tk.BOTH, expand=True)
        text_widget.configure(state=tk.DISABLED)

        if panel_type == "hops":
            self.path_hops_text = text_widget
        else:
            self.path_congestion_text = text_widget

    def _build_subgraph_page(self) -> None:
        controls = ttk.LabelFrame(self.page_subgraph, text="子图查询", padding=10)
        controls.pack(fill=tk.X)

        ttk.Label(controls, text="目标 IP", width=12).grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(controls, textvariable=self.subgraph_target_ip_var, width=28).grid(row=0, column=1, sticky=tk.W, padx=(6, 10))

        self.btn_build_graph = ttk.Button(controls, text="基于 CSV 构图", command=self.build_graph_for_subgraph)
        self.btn_build_graph.grid(row=0, column=2, padx=(0, 8), sticky=tk.W)

        self.btn_query_subgraph = ttk.Button(controls, text="查询该 IP 子图", command=self.query_subgraph_by_ip)
        self.btn_query_subgraph.grid(row=0, column=3, padx=(0, 8), sticky=tk.W)

        self.btn_export_subgraph = ttk.Button(controls, text="导出子图 HTML", command=self.export_subgraph_html)
        self.btn_export_subgraph.grid(row=0, column=4, sticky=tk.W)

        ttk.Checkbutton(
            controls,
            text="强制节点最小间距",
            variable=self.enforce_node_spacing_var,
        ).grid(row=0, column=5, sticky=tk.W, padx=(10, 0))

        if nx is None:
            warn = ttk.Label(
                controls,
                text="未安装 networkx，请执行: python -m pip install -r requirements.txt",
            )
            warn.grid(row=1, column=0, columnspan=6, sticky=tk.W, pady=(8, 0))
            self.btn_build_graph.configure(state=tk.DISABLED)
            self.btn_query_subgraph.configure(state=tk.DISABLED)
            self.btn_export_subgraph.configure(state=tk.DISABLED)

        info_box = ttk.LabelFrame(self.page_subgraph, text="连通子图信息（DSU）", padding=10)
        info_box.pack(fill=tk.X, pady=(10, 0))

        ttk.Label(info_box, text="连通分量根:", width=16).grid(row=0, column=0, sticky=tk.W)
        ttk.Label(info_box, textvariable=self.subgraph_info_vars["component_root"]).grid(row=0, column=1, sticky=tk.W)
        ttk.Label(info_box, text="节点数:", width=10).grid(row=0, column=2, sticky=tk.W, padx=(20, 0))
        ttk.Label(info_box, textvariable=self.subgraph_info_vars["node_count"]).grid(row=0, column=3, sticky=tk.W)
        ttk.Label(info_box, text="边数:", width=8).grid(row=0, column=4, sticky=tk.W, padx=(20, 0))
        ttk.Label(info_box, textvariable=self.subgraph_info_vars["edge_count"]).grid(row=0, column=5, sticky=tk.W)

        table_box = ttk.Frame(self.page_subgraph)
        table_box.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        nodes_box = ttk.LabelFrame(table_box, text="子图节点", padding=10)
        nodes_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.subgraph_node_tree = ttk.Treeview(
            nodes_box,
            columns=("node", "in_degree", "out_degree", "degree"),
            show="headings",
            height=14,
        )
        self.subgraph_node_tree.heading("node", text="节点 IP")
        self.subgraph_node_tree.heading("in_degree", text="入度")
        self.subgraph_node_tree.heading("out_degree", text="出度")
        self.subgraph_node_tree.heading("degree", text="总度")
        self.subgraph_node_tree.column("node", width=230)
        self.subgraph_node_tree.column("in_degree", width=70, anchor=tk.E)
        self.subgraph_node_tree.column("out_degree", width=70, anchor=tk.E)
        self.subgraph_node_tree.column("degree", width=70, anchor=tk.E)
        self.subgraph_node_tree.pack(fill=tk.BOTH, expand=True)

        edges_box = ttk.LabelFrame(table_box, text="子图边（按权重降序）", padding=10)
        edges_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        self.subgraph_edge_tree = ttk.Treeview(
            edges_box,
            columns=("source", "destination", "weight", "count"),
            show="headings",
            height=14,
        )
        self.subgraph_edge_tree.heading("source", text="源 IP")
        self.subgraph_edge_tree.heading("destination", text="目的 IP")
        self.subgraph_edge_tree.heading("weight", text="总流量")
        self.subgraph_edge_tree.heading("count", text="会话数")
        self.subgraph_edge_tree.column("source", width=180)
        self.subgraph_edge_tree.column("destination", width=180)
        self.subgraph_edge_tree.column("weight", width=90, anchor=tk.E)
        self.subgraph_edge_tree.column("count", width=80, anchor=tk.E)
        self.subgraph_edge_tree.pack(fill=tk.BOTH, expand=True)

    def _build_log_page(self) -> None:
        self.log_text = tk.Text(self.page_log, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.configure(state=tk.DISABLED)

    def _path_row(self, parent: ttk.Frame, title: str, variable: tk.StringVar, pick_cmd) -> None:
        row = ttk.Frame(parent)
        row.pack(fill=tk.X, pady=2)
        ttk.Label(row, text=title, width=12).pack(side=tk.LEFT)
        ttk.Entry(row, textvariable=variable).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        ttk.Button(row, text="...", width=3, command=pick_cmd).pack(side=tk.LEFT)

    def _pick_exe(self) -> None:
        selected = filedialog.askopenfilename(filetypes=[("Executable", "*.exe"), ("All", "*.*")])
        if selected:
            self.exe_var.set(selected)

    def _pick_csv(self) -> None:
        selected = filedialog.askopenfilename(filetypes=[("CSV", "*.csv"), ("All", "*.*")])
        if selected:
            self.csv_var.set(selected)
            self.pcap_csv_var.set(selected)

    def _pick_json(self) -> None:
        selected = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if selected:
            self.json_var.set(selected)

    def _pick_pcap(self) -> None:
        selected = filedialog.askopenfilename(filetypes=[("PCAP", "*.pcap"), ("All", "*.*")])
        if selected:
            self.pcap_var.set(selected)

    def _pick_pcap_csv(self) -> None:
        selected = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if selected:
            self.pcap_csv_var.set(selected)
            self.csv_var.set(selected)

    def append_log(self, text: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def extract_pcap(self) -> None:
        pcap_path = Path(self.pcap_var.get())
        csv_path = Path(self.pcap_csv_var.get())

        if not pcap_path.exists():
            messagebox.showerror("提取失败", f"PCAP 文件不存在: {pcap_path}")
            return
        if not DEFAULT_PCAP_SCRIPT.exists():
            messagebox.showerror("提取失败", f"脚本不存在: {DEFAULT_PCAP_SCRIPT}")
            return

        self.status_var.set("正在提取 PCAP...")
        self.update_idletasks()

        command = [
            sys.executable,
            str(DEFAULT_PCAP_SCRIPT),
            "--input",
            str(pcap_path),
            "--output",
            str(csv_path),
        ]
        completed = subprocess.run(command, cwd=str(REPO_ROOT), capture_output=True, text=True)

        self.append_log("[PCAP 提取] " + " ".join(command))
        if completed.stdout:
            self.append_log(completed.stdout.strip())
        if completed.stderr:
            self.append_log(completed.stderr.strip())

        if completed.returncode != 0:
            self.status_var.set("PCAP 提取失败")
            messagebox.showerror("提取失败", completed.stderr.strip() or f"exit code: {completed.returncode}")
            return

        self.csv_var.set(str(csv_path))
        self.status_var.set("PCAP 提取完成")
        messagebox.showinfo("提取成功", f"CSV 已生成:\n{csv_path}")

    def run_batch(self) -> None:
        exe_path = Path(self.exe_var.get())
        csv_path = Path(self.csv_var.get())
        json_path = Path(self.json_var.get())

        if not exe_path.exists():
            messagebox.showerror("运行失败", f"可执行文件不存在: {exe_path}")
            return
        if not csv_path.exists():
            messagebox.showerror("运行失败", f"输入 CSV 不存在: {csv_path}")
            return

        json_path.parent.mkdir(parents=True, exist_ok=True)

        self.status_var.set("正在执行批处理分析...")
        self.update_idletasks()

        command = [str(exe_path), str(csv_path), "--json-out", str(json_path)]
        completed = subprocess.run(command, cwd=str(REPO_ROOT), capture_output=True, text=True)

        self.append_log("[批处理分析] " + " ".join(command))
        if completed.stdout:
            self.append_log(completed.stdout.strip())
        if completed.stderr:
            self.append_log(completed.stderr.strip())

        if completed.returncode != 0:
            self.status_var.set("批处理分析失败")
            messagebox.showerror("运行失败", completed.stderr.strip() or f"exit code: {completed.returncode}")
            return

        self.status_var.set("批处理分析完成，正在加载结果...")
        self.load_json()

    def load_json(self) -> None:
        json_path = Path(self.json_var.get())
        if not json_path.exists():
            messagebox.showerror("加载失败", f"结果文件不存在: {json_path}")
            return

        try:
            result, used_encoding = self._read_json_with_fallback(json_path)
        except Exception as exc:
            self.status_var.set("加载失败")
            messagebox.showerror("加载失败", str(exc))
            return

        self.append_log(f"[加载 JSON] 使用编码: {used_encoding}")

        self.summary_vars["flow_count"].set(str(result.get("flow_count", "-")))
        self.summary_vars["node_count"].set(str(result.get("node_count", "-")))
        self.summary_vars["total_data_size"].set(str(result.get("total_data_size", "-")))
        self.summary_vars["total_duration"].set(str(result.get("total_duration", "-")))

        self._refresh_protocol(
            result.get("protocol_data_size", {}),
            result.get("protocol_flow_count", {}),
        )
        self._refresh_https(result.get("https_nodes_by_traffic", []))
        self._refresh_one_way(result.get("one_way_heavy_nodes_by_traffic", []))
        self._refresh_star(result.get("star_nodes", []))
        self._refresh_scan(result.get("scan_nodes", []))

        self.status_var.set("结果已加载")

    def _build_full_graph_from_csv(self) -> tuple[object, DSU, int, str]:
        if nx is None:
            raise ValueError("未安装 networkx，请先安装 requirements.txt 依赖")

        csv_path = Path(self.csv_var.get())
        if not csv_path.exists():
            raise FileNotFoundError(f"输入 CSV 不存在: {csv_path}")

        rows, used_encoding = self._read_csv_rows_with_fallback(csv_path)

        graph = nx.DiGraph()
        dsu = DSU()
        valid_row_count = 0

        for row in rows:
            src = str(row.get("Source", "")).strip()
            dst = str(row.get("Destination", "")).strip()
            if not src or not dst:
                continue

            try:
                weight = int(float(row.get("DataSize", 0) or 0))
            except (TypeError, ValueError):
                weight = 0

            try:
                duration = float(row.get("Duration", 0.0) or 0.0)
            except (TypeError, ValueError):
                duration = 0.0

            dsu.add(src)
            dsu.add(dst)
            dsu.union(src, dst)

            if graph.has_edge(src, dst):
                graph[src][dst]["weight"] += weight
                graph[src][dst]["count"] += 1
                graph[src][dst]["duration_sum"] += duration
            else:
                graph.add_edge(src, dst, weight=weight, count=1, duration_sum=duration)

            valid_row_count += 1

        return graph, dsu, valid_row_count, used_encoding

    def _ensure_full_graph_ready(self) -> bool:
        if self.full_graph is not None and self.full_graph.number_of_nodes() > 0:
            return True

        try:
            graph, dsu, valid_row_count, used_encoding = self._build_full_graph_from_csv()
        except Exception as exc:
            messagebox.showerror("构图失败", str(exc))
            return False

        self.full_graph = graph
        self.dsu = dsu
        self.append_log(f"[全图构建] 编码: {used_encoding}，有效记录: {valid_row_count}")
        self.append_log(f"[全图构建] 图规模: nodes={graph.number_of_nodes()}, edges={graph.number_of_edges()}")
        return True

    def build_graph_for_subgraph(self) -> None:
        self.status_var.set("正在基于 CSV 构图...")
        self.update_idletasks()

        try:
            graph, dsu, valid_row_count, used_encoding = self._build_full_graph_from_csv()
        except Exception as exc:
            self.status_var.set("构图失败")
            messagebox.showerror("构图失败", str(exc))
            return

        self.full_graph = graph
        self.dsu = dsu
        self.current_subgraph_nodes = []
        self.subgraph_info_vars["component_root"].set("-")
        self.subgraph_info_vars["node_count"].set("-")
        self.subgraph_info_vars["edge_count"].set("-")

        for item in self.subgraph_node_tree.get_children():
            self.subgraph_node_tree.delete(item)
        for item in self.subgraph_edge_tree.get_children():
            self.subgraph_edge_tree.delete(item)

        self.append_log(f"[子图构图] 编码: {used_encoding}，有效记录: {valid_row_count}")
        self.append_log(f"[子图构图] 图规模: nodes={graph.number_of_nodes()}, edges={graph.number_of_edges()}")
        self.status_var.set("构图完成，可输入 IP 查询子图")

        target_ip = self.subgraph_target_ip_var.get().strip()
        if target_ip:
            self.query_subgraph_by_ip()

    def query_path_comparison(self) -> None:
        if nx is None:
            messagebox.showerror("查询失败", "未安装 networkx")
            return

        src_ip = self.path_source_var.get().strip()
        dst_ip = self.path_destination_var.get().strip()
        if not src_ip or not dst_ip:
            messagebox.showinfo("提示", "请输入源 IP 和目的 IP")
            return

        if not self._ensure_full_graph_ready():
            self.status_var.set("路径查询失败")
            return

        graph = self.full_graph
        if src_ip not in graph.nodes:
            messagebox.showerror("查询失败", f"源 IP 不在图中: {src_ip}")
            return
        if dst_ip not in graph.nodes:
            messagebox.showerror("查询失败", f"目的 IP 不在图中: {dst_ip}")
            return

        hop_path: list[str] | None = None
        congestion_path: list[str] | None = None

        try:
            hop_path = nx.shortest_path(graph, source=src_ip, target=dst_ip)
        except Exception:
            hop_path = None

        try:
            congestion_path = nx.dijkstra_path(
                graph,
                source=src_ip,
                target=dst_ip,
                weight=lambda _u, _v, data: float(data.get("weight", 0.0)) + 1e-9,
            )
        except Exception:
            congestion_path = None

        self._update_path_result_panel(self.path_hops_vars, self.path_hops_text, hop_path)
        self._update_path_result_panel(self.path_congestion_vars, self.path_congestion_text, congestion_path)
        self._update_path_compare_summary(src_ip, dst_ip, hop_path, congestion_path)

        self.append_log(
            f"[路径对比] src={src_ip}, dst={dst_ip}, hops_found={hop_path is not None}, congestion_found={congestion_path is not None}"
        )
        self.status_var.set("路径对比查询完成")

    def _update_path_result_panel(
        self,
        var_map: dict[str, tk.StringVar],
        text_widget: tk.Text,
        path_nodes: list[str] | None,
    ) -> None:
        if not path_nodes or len(path_nodes) == 0:
            var_map["found"].set("False")
            var_map["hops"].set("-")
            var_map["congestion"].set("-")
            var_map["duration"].set("-")
            route_text = "未找到路径"
        else:
            hops, congestion, duration = self._calculate_path_metrics(path_nodes)
            var_map["found"].set("True")
            var_map["hops"].set(str(hops))
            var_map["congestion"].set(str(congestion))
            var_map["duration"].set(f"{duration:.6f}")
            route_text = " -> ".join(path_nodes)

        text_widget.configure(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)
        text_widget.insert("1.0", route_text)
        text_widget.configure(state=tk.DISABLED)

    def _calculate_path_metrics(self, path_nodes: list[str]) -> tuple[int, int, float]:
        if not path_nodes or len(path_nodes) < 2:
            return 0, 0, 0.0

        total_congestion = 0
        total_duration = 0.0
        for i in range(len(path_nodes) - 1):
            src = path_nodes[i]
            dst = path_nodes[i + 1]
            edge_data = self.full_graph[src][dst]
            total_congestion += int(edge_data.get("weight", 0))
            total_duration += float(edge_data.get("duration_sum", 0.0))

        return len(path_nodes) - 1, total_congestion, total_duration

    def _update_path_compare_summary(
        self,
        src_ip: str,
        dst_ip: str,
        hop_path: list[str] | None,
        congestion_path: list[str] | None,
    ) -> None:
        if not hop_path and not congestion_path:
            self.path_compare_var.set(f"从 {src_ip} 到 {dst_ip} 未找到可达路径。")
            return

        if hop_path and not congestion_path:
            self.path_compare_var.set("仅找到最小跳数路径，未找到最小拥塞路径（请检查图连通性）。")
            return

        if congestion_path and not hop_path:
            self.path_compare_var.set("仅找到最小拥塞路径，未找到最小跳数路径（请检查图连通性）。")
            return

        hop_hops, hop_congestion, hop_duration = self._calculate_path_metrics(hop_path or [])
        cong_hops, cong_congestion, cong_duration = self._calculate_path_metrics(congestion_path or [])

        if hop_path == congestion_path:
            self.path_compare_var.set(
                f"两种算法路径一致：跳数={hop_hops}，拥塞值={hop_congestion}，总时延={hop_duration:.6f}。"
            )
            return

        better_hops = "最小跳数路径" if hop_hops <= cong_hops else "最小拥塞路径"
        better_congestion = "最小拥塞路径" if cong_congestion <= hop_congestion else "最小跳数路径"
        self.path_compare_var.set(
            f"路径不同：{better_hops}在跳数上更优（{hop_hops} vs {cong_hops}），"
            f"{better_congestion}在拥塞值上更优（{hop_congestion} vs {cong_congestion}），"
            f"对应总时延分别为 {hop_duration:.6f} 和 {cong_duration:.6f}。"
        )

    def query_subgraph_by_ip(self) -> None:
        if nx is None:
            messagebox.showerror("查询失败", "未安装 networkx")
            return
        if self.full_graph is None:
            messagebox.showinfo("提示", "请先点击“基于 CSV 构图”")
            return

        target_ip = self.subgraph_target_ip_var.get().strip()
        if not target_ip:
            messagebox.showinfo("提示", "请输入目标 IP")
            return
        if target_ip not in self.dsu.parent:
            messagebox.showerror("查询失败", f"在当前图中未找到 IP: {target_ip}")
            return

        root = self.dsu.find(target_ip)
        component_nodes = sorted(node for node in self.dsu.parent.keys() if self.dsu.find(node) == root)
        self.current_subgraph_nodes = component_nodes

        subgraph = self.full_graph.subgraph(component_nodes).copy()
        self.subgraph_info_vars["component_root"].set(root)
        self.subgraph_info_vars["node_count"].set(str(subgraph.number_of_nodes()))
        self.subgraph_info_vars["edge_count"].set(str(subgraph.number_of_edges()))

        for item in self.subgraph_node_tree.get_children():
            self.subgraph_node_tree.delete(item)
        for item in self.subgraph_edge_tree.get_children():
            self.subgraph_edge_tree.delete(item)

        for node in component_nodes:
            in_degree = subgraph.in_degree(node)
            out_degree = subgraph.out_degree(node)
            self.subgraph_node_tree.insert(
                "",
                tk.END,
                values=(node, in_degree, out_degree, in_degree + out_degree),
            )

        edges = sorted(
            subgraph.edges(data=True),
            key=lambda item: item[2].get("weight", 0),
            reverse=True,
        )
        for src, dst, data in edges[:500]:
            self.subgraph_edge_tree.insert(
                "",
                tk.END,
                values=(src, dst, data.get("weight", 0), data.get("count", 0)),
            )

        self.append_log(
            f"[子图查询] target={target_ip}, root={root}, nodes={subgraph.number_of_nodes()}, edges={subgraph.number_of_edges()}"
        )
        self.status_var.set("子图查询完成")

    def export_subgraph_html(self) -> None:
        if nx is None:
            messagebox.showerror("导出失败", "未安装 networkx")
            return
        if self.full_graph is None or not self.current_subgraph_nodes:
            messagebox.showinfo("提示", "请先构图并查询目标 IP 的子图")
            return

        target_ip = self.subgraph_target_ip_var.get().strip() or "subgraph"
        default_name = f"subgraph_{target_ip.replace(':', '_').replace('.', '_')}.html"
        output_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            initialfile=default_name,
            filetypes=[("HTML", "*.html")],
        )
        if not output_path:
            return

        subgraph = self.full_graph.subgraph(self.current_subgraph_nodes).copy()
        try:
            html_text = self._build_subgraph_html(
                subgraph,
                target_ip,
                enforce_min_distance=bool(self.enforce_node_spacing_var.get()),
            )
            Path(output_path).write_text(html_text, encoding="utf-8")
        except Exception as exc:
            messagebox.showerror("导出失败", str(exc))
            return

        self.append_log(f"[子图导出] {output_path}")
        self.status_var.set("子图 HTML 导出成功")
        messagebox.showinfo("导出成功", f"已导出: {output_path}")

    def _normalize_positions_to_canvas(
        self,
        positions: dict[str, tuple[float, float]],
        width: float,
        height: float,
        margin: float,
    ) -> dict[str, tuple[float, float]]:
        if not positions:
            return {}

        xs = [float(pos[0]) for pos in positions.values()]
        ys = [float(pos[1]) for pos in positions.values()]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        span_x = max(max_x - min_x, 1e-9)
        span_y = max(max_y - min_y, 1e-9)

        canvas_positions: dict[str, tuple[float, float]] = {}
        for node, (x, y) in positions.items():
            px = margin + (float(x) - min_x) / span_x * (width - 2 * margin)
            py = margin + (float(y) - min_y) / span_y * (height - 2 * margin)
            canvas_positions[str(node)] = (px, py)

        return canvas_positions

    def _resolve_node_overlaps(
        self,
        positions: dict[str, tuple[float, float]],
        node_radius: dict[str, float],
        width: float,
        height: float,
        margin: float,
        target_ip: str,
        out_degree_map: dict[str, int],
    ) -> dict[str, tuple[float, float]]:
        if len(positions) <= 1:
            return positions

        left = margin
        right = width - margin
        top = margin
        bottom = height - margin
        # Increase the spacing standard so clustered nodes are pushed further apart.
        min_padding = 8.0
        max_iterations = 120

        resolved: dict[str, tuple[float, float]] = {
            node: (float(pos[0]), float(pos[1])) for node, pos in positions.items()
        }

        max_radius = max(node_radius.values(), default=8.0)
        cell_size = max(14.0, 2.0 * max_radius + min_padding)
        node_order = sorted(resolved.keys(), key=lambda node: (node != target_ip, node))
        node_index = {node: index for index, node in enumerate(node_order)}

        max_out_degree = max(out_degree_map.values(), default=1)
        if max_out_degree <= 0:
            max_out_degree = 1
        repulsion_strength: dict[str, float] = {}
        for node in node_order:
            out_degree = max(0, int(out_degree_map.get(node, 0)))
            out_ratio = out_degree / float(max_out_degree)
            repulsion_strength[node] = 1.0 + 1.9 * (out_ratio ** 0.8)

        center_x = (left + right) / 2.0
        center_y = (top + bottom) / 2.0

        for _ in range(max_iterations):
            moved = False

            buckets: dict[tuple[int, int], list[str]] = {}
            for node in node_order:
                x, y = resolved[node]
                cell_x = int((x - left) / cell_size)
                cell_y = int((y - top) / cell_size)
                buckets.setdefault((cell_x, cell_y), []).append(node)

            for node in node_order:
                i = node_index[node]
                xi, yi = resolved[node]
                ri = float(node_radius.get(node, 8.0))

                base_cell_x = int((xi - left) / cell_size)
                base_cell_y = int((yi - top) / cell_size)

                for offset_x in (-1, 0, 1):
                    for offset_y in (-1, 0, 1):
                        candidates = buckets.get((base_cell_x + offset_x, base_cell_y + offset_y), [])
                        for other in candidates:
                            if node_index[other] <= i:
                                continue

                            xj, yj = resolved[other]
                            rj = float(node_radius.get(other, 8.0))
                            min_dist = ri + rj + min_padding
                            dx = xj - xi
                            dy = yj - yi
                            dist_sq = dx * dx + dy * dy

                            if dist_sq >= min_dist * min_dist:
                                continue

                            if dist_sq < 1e-9:
                                phase = (i * 0.7548776662 + node_index[other] * 0.569840291) * math.pi
                                ux = math.cos(phase)
                                uy = math.sin(phase)
                                dist = 1.0
                            else:
                                dist = dist_sq ** 0.5
                                ux = dx / dist
                                uy = dy / dist

                            overlap = min_dist - dist
                            strength_i = repulsion_strength.get(node, 1.0)
                            strength_j = repulsion_strength.get(other, 1.0)
                            strength_scale = (strength_i + strength_j) / 2.0
                            shift = overlap * 0.66 * strength_scale

                            total_strength = max(strength_i + strength_j, 1e-9)
                            move_i = strength_j / total_strength
                            move_j = strength_i / total_strength

                            # Keep the queried node more stable while still allowing repulsion.
                            if node == target_ip:
                                move_i *= 0.6
                                move_j = 1.0 - move_i
                            elif other == target_ip:
                                move_j *= 0.6
                                move_i = 1.0 - move_j

                            xi -= ux * shift * move_i
                            yi -= uy * shift * move_i
                            xj += ux * shift * move_j
                            yj += uy * shift * move_j

                            xi = min(max(xi, left + ri), right - ri)
                            yi = min(max(yi, top + ri), bottom - ri)
                            xj = min(max(xj, left + rj), right - rj)
                            yj = min(max(yj, top + rj), bottom - rj)

                            resolved[node] = (xi, yi)
                            resolved[other] = (xj, yj)
                            moved = True

            # Add a small center gravity after collision pushing to keep the graph compact.
            for node in node_order:
                if node == target_ip:
                    continue
                x, y = resolved[node]
                r = float(node_radius.get(node, 8.0))
                x += (center_x - x) * 0.008
                y += (center_y - y) * 0.008
                x = min(max(x, left + r), right - r)
                y = min(max(y, top + r), bottom - r)
                resolved[node] = (x, y)

            if not moved:
                break

        return resolved

    def _build_subgraph_html(self, subgraph, target_ip: str, enforce_min_distance: bool = False) -> str:
        node_count = subgraph.number_of_nodes()
        edge_count = subgraph.number_of_edges()
        if node_count == 0:
            raise ValueError("子图为空，无法导出")

        undirected = subgraph.to_undirected()
        try:
            if node_count == 1:
                only_node = next(iter(subgraph.nodes()))
                positions = {only_node: (0.0, 0.0)}
            elif node_count <= 80:
                positions = nx.kamada_kawai_layout(undirected)
            else:
                k_value = max(0.18, min(0.9, 2.6 / (node_count ** 0.5)))
                positions = nx.spring_layout(undirected, seed=42, k=k_value, iterations=300)
        except ModuleNotFoundError as exc:
            missing_name = str(getattr(exc, "name", "") or "")
            if missing_name == "numpy" or "numpy" in str(exc).lower():
                raise RuntimeError(
                    "导出子图失败：当前 Python 环境缺少 numpy。"
                    "请先执行：python -m pip install -r requirements.txt，"
                    "并确认 UI 使用的是同一个解释器。"
                ) from exc
            raise

        if node_count > 180:
            width = 1800.0
            height = 1180.0
        elif node_count > 90:
            width = 1540.0
            height = 980.0
        else:
            width = 1300.0
            height = 860.0
        margin = 70.0

        degree_map = {
            node: int(subgraph.in_degree(node) + subgraph.out_degree(node))
            for node in subgraph.nodes()
        }
        out_degree_map = {
            node: int(subgraph.out_degree(node))
            for node in subgraph.nodes()
        }
        max_degree = max(degree_map.values(), default=1)
        node_radius: dict[str, float] = {}
        for node, degree in degree_map.items():
            degree_ratio = (degree / max_degree) ** 0.65 if max_degree > 0 else 0.0
            node_radius[node] = 5.5 + 10.0 * degree_ratio

        canvas_positions = self._normalize_positions_to_canvas(positions, width, height, margin)
        if enforce_min_distance:
            canvas_positions = self._resolve_node_overlaps(
                canvas_positions,
                node_radius,
                width,
                height,
                margin,
                target_ip,
                out_degree_map,
            )

        sorted_degrees = sorted(degree_map.values())
        hub_threshold = sorted_degrees[int(0.75 * (len(sorted_degrees) - 1))] if sorted_degrees else 0

        edges_sorted = sorted(
            subgraph.edges(data=True),
            key=lambda item: int(item[2].get("weight", 0)),
            reverse=True,
        )
        max_weight = max((int(data.get("weight", 0)) for _, _, data in edges_sorted), default=1)

        if node_count <= 40:
            label_nodes = set(subgraph.nodes())
        else:
            max_top_nodes = 10 if node_count > 120 else 14
            neighbor_limit = 4 if node_count > 120 else 6
            top_degree_nodes = sorted(
                degree_map.items(),
                key=lambda item: item[1],
                reverse=True,
            )[:max_top_nodes]
            label_nodes = {node for node, _ in top_degree_nodes}
            if target_ip in subgraph.nodes():
                label_nodes.add(target_ip)
                for neighbor in list(subgraph.predecessors(target_ip))[:neighbor_limit]:
                    label_nodes.add(neighbor)
                for neighbor in list(subgraph.successors(target_ip))[:neighbor_limit]:
                    label_nodes.add(neighbor)

        edge_parts: list[str] = []
        edge_label_parts: list[str] = []
        label_edge_limit = 40
        for index, (src, dst, data) in enumerate(edges_sorted):
            x1, y1 = canvas_positions[str(src)]
            x2, y2 = canvas_positions[str(dst)]
            weight = int(data.get("weight", 0))
            count = int(data.get("count", 0))

            ratio = (weight / max_weight) ** 0.6 if max_weight > 0 else 0.0
            stroke_width = 0.9 + 3.4 * ratio
            stroke_opacity = 0.25 + 0.55 * ratio

            dx, dy = x2 - x1, y2 - y1
            length = max((dx * dx + dy * dy) ** 0.5, 1e-9)
            normal_x, normal_y = -dy / length, dx / length
            has_reverse = src != dst and subgraph.has_edge(dst, src)
            curve = 18.0 if has_reverse and str(src) < str(dst) else (-18.0 if has_reverse else 0.0)
            cx = (x1 + x2) / 2.0 + normal_x * curve
            cy = (y1 + y2) / 2.0 + normal_y * curve

            path_data = f"M {x1:.2f},{y1:.2f} Q {cx:.2f},{cy:.2f} {x2:.2f},{y2:.2f}"
            edge_parts.append(
                f'<path d="{path_data}" stroke="#64748b" stroke-width="{stroke_width:.2f}" '
                f'stroke-opacity="{stroke_opacity:.2f}" fill="none" >'
                f'<title>{html.escape(str(src))} → {html.escape(str(dst))} | weight={weight}, count={count}</title></path>'
            )

            if index < label_edge_limit:
                lx = (x1 + 2.0 * cx + x2) / 4.0
                ly = (y1 + 2.0 * cy + y2) / 4.0
                edge_label_parts.append(
                    f'<text x="{lx:.2f}" y="{ly:.2f}" font-size="9.5" fill="#475569" '
                    f'text-anchor="middle" dominant-baseline="middle">{weight}</text>'
                )

        node_parts: list[str] = []
        label_parts: list[str] = []
        for node in subgraph.nodes():
            x, y = canvas_positions[str(node)]
            degree = degree_map.get(node, 0)
            radius = node_radius.get(node, 5.5)

            if str(node) == target_ip:
                fill = "#f59e0b"
                stroke = "#92400e"
                stroke_w = "2.2"
            elif degree >= hub_threshold and degree > 1:
                fill = "#2563eb"
                stroke = "#1e3a8a"
                stroke_w = "1.6"
            else:
                fill = "#0ea5a4"
                stroke = "#0f766e"
                stroke_w = "1.2"

            safe_node = html.escape(str(node))
            node_parts.append(
                f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{radius:.2f}" fill="{fill}" stroke="{stroke}" '
                f'stroke-width="{stroke_w}"><title>{safe_node} | degree={degree}</title></circle>'
            )

            if node in label_nodes:
                label_x = x + radius + 4.0
                label_y = y - radius - 4.0
                label_w = min(230.0, max(52.0, float(len(str(node)) * 7 + 10)))
                label_parts.append(
                    f'<rect x="{label_x - 3.0:.2f}" y="{label_y - 10.5:.2f}" width="{label_w:.2f}" height="15.0" '
                    f'rx="3" ry="3" fill="#ffffff" fill-opacity="0.82" stroke="#cbd5e1" stroke-width="0.8" />'
                )
                label_parts.append(
                    f'<text x="{label_x:.2f}" y="{label_y:.2f}" font-size="10.5" fill="#0f172a">{safe_node}</text>'
                )

        safe_target = html.escape(target_ip)
        return f"""<!doctype html>
<html lang=\"zh-CN\">
<head>
  <meta charset=\"utf-8\" />
  <title>子图可视化 - {safe_target}</title>
  <style>
    body {{ font-family: Arial, "Microsoft YaHei", sans-serif; margin: 14px; color: #0f172a; }}
    .meta {{ margin-bottom: 10px; color: #334155; }}
    .legend {{ display: flex; gap: 14px; align-items: center; margin: 8px 0 12px 0; font-size: 13px; }}
    .dot {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; margin-right: 6px; }}
    .canvas {{ border: 1px solid #cbd5e1; background: #f8fafc; }}
  </style>
</head>
<body>
  <h2>目标 IP 子图可视化：{safe_target}</h2>
    <div class=\"meta\">节点数: {node_count}，边数: {edge_count}。节点越大表示度越高；边越粗表示通信权重越大。当前导出模式: {'强制最小间距' if enforce_min_distance else '自然布局（不强制最小间距）'}。</div>
  <div class=\"legend\">
    <span><span class=\"dot\" style=\"background:#f59e0b;border:1px solid #92400e\"></span>目标节点</span>
    <span><span class=\"dot\" style=\"background:#2563eb;border:1px solid #1e3a8a\"></span>高连接节点</span>
    <span><span class=\"dot\" style=\"background:#0ea5a4;border:1px solid #0f766e\"></span>普通节点</span>
  </div>
  <svg width=\"{int(width)}\" height=\"{int(height)}\" class=\"canvas\" viewBox=\"0 0 {int(width)} {int(height)}\">
    {''.join(edge_parts)}
    {''.join(edge_label_parts)}
    {''.join(node_parts)}
    {''.join(label_parts)}
  </svg>
</body>
</html>
"""

    def _read_csv_rows_with_fallback(self, csv_path: Path) -> tuple[list[dict], str]:
        encodings = ("utf-8", "utf-8-sig", "gbk", "cp936")
        last_error: Exception | None = None
        for encoding in encodings:
            try:
                with csv_path.open("r", encoding=encoding, newline="") as file:
                    rows = list(csv.DictReader(file))
                return rows, encoding
            except Exception as exc:
                last_error = exc

        raise ValueError(
            "无法读取 CSV，请确认编码为 UTF-8/GBK，且包含 Source,Destination,DataSize 等字段。"
            + (f" 最后一次错误: {last_error}" if last_error else "")
        )

    def _read_json_with_fallback(self, json_path: Path) -> tuple[dict, str]:
        raw = json_path.read_bytes()
        encodings = ("utf-8", "utf-8-sig", "gbk", "cp936")
        last_error: Exception | None = None

        for encoding in encodings:
            try:
                text = raw.decode(encoding)
                data = json.loads(text)
                if not isinstance(data, dict):
                    raise ValueError("JSON 根节点必须是对象")
                return data, encoding
            except Exception as exc:
                last_error = exc

        raise ValueError(
            "无法解析 JSON 文件，请确认文件内容有效且编码为 UTF-8/GBK。"
            + (f" 最后一次错误: {last_error}" if last_error else "")
        )

    def _refresh_protocol(self, protocol_map: dict, protocol_flow_count_map: dict) -> None:
        for item in self.protocol_tree.get_children():
            self.protocol_tree.delete(item)

        rows: list[tuple[int, int, int]] = []
        for key, value in protocol_map.items():
            try:
                protocol_id = int(key)
                traffic = int(value)
            except (TypeError, ValueError):
                continue

            flow_count_raw = protocol_flow_count_map.get(str(protocol_id), protocol_flow_count_map.get(protocol_id, 0))
            try:
                flow_count = int(flow_count_raw)
            except (TypeError, ValueError):
                flow_count = 0

            rows.append((protocol_id, traffic, flow_count))

        rows.sort(key=lambda item: item[1], reverse=True)
        if not rows:
            self.protocol_tree.insert("", tk.END, values=("-", "-", 0, 0))
            return

        for protocol_id, traffic, flow_count in rows:
            protocol_name = PROTOCOL_NAMES.get(protocol_id, "Unknown")
            self.protocol_tree.insert(
                "",
                tk.END,
                values=(protocol_id, protocol_name, traffic, flow_count),
            )

    def _refresh_https(self, rows: list[dict]) -> None:
        for item in self.https_tree.get_children():
            self.https_tree.delete(item)

        for row in rows[:10]:
            self.https_tree.insert(
                "",
                tk.END,
                values=(
                    row.get("node", "-"),
                    row.get("total_traffic", 0),
                ),
            )

    def _refresh_one_way(self, rows: list[dict]) -> None:
        for item in self.one_way_tree.get_children():
            self.one_way_tree.delete(item)

        for row in rows[:10]:
            ratio = float(row.get("outgoing_ratio", 0.0))
            self.one_way_tree.insert(
                "",
                tk.END,
                values=(
                    row.get("node", "-"),
                    row.get("total_traffic", 0),
                    row.get("outgoing_traffic", 0),
                    f"{ratio:.6f}",
                ),
            )

    def _refresh_star(self, rows: list[dict]) -> None:
        for item in self.star_tree.get_children():
            self.star_tree.delete(item)

        self.star_leaf_map.clear()
        for row in rows:
            center = str(row.get("center_node", "-"))
            leaf_nodes = [str(item) for item in row.get("leaf_nodes", [])]
            self.star_leaf_map[center] = leaf_nodes
            self.star_tree.insert(
                "",
                tk.END,
                values=(center, row.get("leaf_count", len(leaf_nodes))),
            )

        self._show_leaf_nodes([])

    def _refresh_scan(self, rows: list[dict]) -> None:
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)

        for row in rows:
            self.scan_tree.insert(
                "",
                tk.END,
                values=(row.get("node", "-"),),
            )

    def _on_star_select(self, _event: object) -> None:
        selected = self.star_tree.selection()
        if not selected:
            self._show_leaf_nodes([])
            return

        values = self.star_tree.item(selected[0], "values")
        if not values:
            self._show_leaf_nodes([])
            return

        center = str(values[0])
        self._show_leaf_nodes(self.star_leaf_map.get(center, []))

    def _show_leaf_nodes(self, leaf_nodes: list[str]) -> None:
        text = "\n".join(leaf_nodes) if leaf_nodes else "请选择左侧星型节点查看叶子节点列表"
        self.leaf_text.configure(state=tk.NORMAL)
        self.leaf_text.delete("1.0", tk.END)
        self.leaf_text.insert("1.0", text)
        self.leaf_text.configure(state=tk.DISABLED)


def main() -> None:
    app = TrafficAnalyzerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()

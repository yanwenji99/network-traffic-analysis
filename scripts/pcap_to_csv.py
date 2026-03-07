#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

try:
    from scapy.all import IP, TCP, UDP, rdpcap
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "Scapy 未安装，请先执行: py -m pip install -r requirements.txt"
    ) from exc


FlowKey = Tuple[str, str, int, int, int]


@dataclass
class FlowAgg:
    first_ts: float
    last_ts: float
    total_size: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="从 pcap 中提取五元组会话并导出为课程项目 CSV 格式"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="输入 pcap 文件路径",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="输出 csv 文件路径",
    )
    return parser.parse_args()


def aggregate_flows(pcap_path: Path) -> Dict[FlowKey, FlowAgg]:
    packets = rdpcap(str(pcap_path))
    flow_map: Dict[FlowKey, FlowAgg] = {}

    for packet in packets:
        if IP not in packet:
            continue

        ip_layer = packet[IP]
        src = str(ip_layer.src)
        dst = str(ip_layer.dst)
        protocol = int(ip_layer.proto)
        src_port = 0
        dst_port = 0

        if TCP in packet:
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)

        timestamp = float(packet.time)
        data_size = int(len(packet))
        key: FlowKey = (src, dst, protocol, src_port, dst_port)

        if key not in flow_map:
            flow_map[key] = FlowAgg(first_ts=timestamp, last_ts=timestamp, total_size=data_size)
            continue

        agg = flow_map[key]
        if timestamp < agg.first_ts:
            agg.first_ts = timestamp
        if timestamp > agg.last_ts:
            agg.last_ts = timestamp
        agg.total_size += data_size

    return flow_map


def write_csv(flow_map: Dict[FlowKey, FlowAgg], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    sorted_rows = sorted(
        flow_map.items(),
        key=lambda item: item[1].first_ts,
    )

    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Source", "Destination", "Protocol", "SrcPort", "DstPort", "DataSize", "Duration"])

        for (src, dst, protocol, src_port, dst_port), agg in sorted_rows:
            duration = max(0.0, agg.last_ts - agg.first_ts)
            writer.writerow([
                src,
                dst,
                protocol,
                src_port,
                dst_port,
                agg.total_size,
                f"{duration:.6f}",
            ])


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"输入文件不存在: {input_path}")
        return 1

    flow_map = aggregate_flows(input_path)
    write_csv(flow_map, output_path)

    print(f"提取完成: {input_path}")
    print(f"五元组会话数: {len(flow_map)}")
    print(f"输出文件: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

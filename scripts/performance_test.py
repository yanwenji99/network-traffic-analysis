import subprocess
import time
import json
import os
from pathlib import Path

class PerformanceTester:
    def __init__(self, exe_path="./build/bin/main.exe"):
        self.exe_path = exe_path
        self.results = {
            "batch_processing": [],
            "path_finding": [],
            "anomaly_detection": []
        }
    
    def run_batch_test(self, input_file, output_file, description):
        """
        测试批处理模式的性能
        """
        print(f"\n{'='*60}")
        print(f"测试: {description}")
        print(f"输入文件: {input_file}")
        print(f"{'='*60}")
        
        # 确保输出目录存在
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                [self.exe_path, input_file, "--json-out", output_file],
                capture_output=True,
                text=True,
                timeout=300  # 5分钟超时
            )
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            if result.returncode == 0:
                # 读取输出文件获取统计信息
                if os.path.exists(output_file):
                    with open(output_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    test_result = {
                        "description": description,
                        "input_file": input_file,
                        "output_file": output_file,
                        "flow_count": data.get("flow_count", 0),
                        "node_count": data.get("node_count", 0),
                        "total_data_size": data.get("total_data_size", 0),
                        "execution_time": execution_time,
                        "success": True,
                        "throughput_flows_per_sec": data.get("flow_count", 0) / execution_time if execution_time > 0 else 0
                    }
                    
                    self.results["batch_processing"].append(test_result)
                    
                    print(f"✓ 成功完成")
                    print(f"  流记录数: {test_result['flow_count']}")
                    print(f"  节点数: {test_result['node_count']}")
                    print(f"  总数据量: {test_result['total_data_size']:,} 字节")
                    print(f"  执行时间: {execution_time:.3f} 秒")
                    print(f"  吞吐量: {test_result['throughput_flows_per_sec']:.2f} 流/秒")
                else:
                    print(f"✗ 输出文件未生成: {output_file}")
            else:
                print(f"✗ 执行失败，返回码: {result.returncode}")
                print(f"错误输出: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"✗ 执行超时（超过5分钟）")
            end_time = time.time()
            execution_time = end_time - start_time
            
            test_result = {
                "description": description,
                "input_file": input_file,
                "execution_time": execution_time,
                "success": False,
                "error": "Timeout"
            }
            self.results["batch_processing"].append(test_result)
            
        except Exception as e:
            print(f"✗ 执行异常: {str(e)}")
            end_time = time.time()
            execution_time = end_time - start_time
            
            test_result = {
                "description": description,
                "input_file": input_file,
                "execution_time": execution_time,
                "success": False,
                "error": str(e)
            }
            self.results["batch_processing"].append(test_result)
    
    def run_path_finding_test(self, input_file, src_ip, dst_ip, output_file, description):
        """
        测试路径查找算法的性能
        """
        print(f"\n{'='*60}")
        print(f"测试: {description}")
        print(f"源IP: {src_ip}, 目的IP: {dst_ip}")
        print(f"{'='*60}")
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                [self.exe_path, input_file, "--path-source", src_ip, "--path-destination", dst_ip, "--path-json-out", output_file],
                capture_output=True,
                text=True,
                timeout=120  # 2分钟超时
            )
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            if result.returncode == 0 and os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                bfs_result = data.get("bfs", {})
                dijkstra_result = data.get("dijkstra", {})
                
                test_result = {
                    "description": description,
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "execution_time": execution_time,
                    "success": True,
                    "bfs": {
                        "found": bfs_result.get("found", False),
                        "hops": bfs_result.get("hops", -1),
                        "congestion": bfs_result.get("congestion", 0)
                    },
                    "dijkstra": {
                        "found": dijkstra_result.get("found", False),
                        "hops": dijkstra_result.get("hops", -1),
                        "congestion": dijkstra_result.get("congestion", 0)
                    }
                }
                
                self.results["path_finding"].append(test_result)
                
                print(f"✓ 成功完成")
                print(f"  执行时间: {execution_time:.3f} 秒")
                print(f"  BFS: 找到={test_result['bfs']['found']}, 跳数={test_result['bfs']['hops']}, 拥塞={test_result['bfs']['congestion']:.2f}")
                print(f"  Dijkstra: 找到={test_result['dijkstra']['found']}, 跳数={test_result['dijkstra']['hops']}, 拥塞={test_result['dijkstra']['congestion']:.2f}")
            else:
                print(f"✗ 执行失败")
                
        except subprocess.TimeoutExpired:
            print(f"✗ 执行超时")
            
        except Exception as e:
            print(f"✗ 执行异常: {str(e)}")
    
    def run_anomaly_detection_test(self, input_file, output_file, description):
        """
        测试异常检测模块的性能
        """
        print(f"\n{'='*60}")
        print(f"测试: {description}")
        print(f"{'='*60}")
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                [self.exe_path, input_file, "--json-out", output_file],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            if result.returncode == 0 and os.path.exists(output_file):
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                test_result = {
                    "description": description,
                    "input_file": input_file,
                    "execution_time": execution_time,
                    "success": True,
                    "star_nodes_count": len(data.get("star_nodes", [])),
                    "scan_nodes_count": len(data.get("scan_nodes", [])),
                    "range_flows_count": len(data.get("range_flows", []))
                }
                
                self.results["anomaly_detection"].append(test_result)
                
                print(f"✓ 成功完成")
                print(f"  执行时间: {execution_time:.3f} 秒")
                print(f"  星型节点数: {test_result['star_nodes_count']}")
                print(f"  扫描节点数: {test_result['scan_nodes_count']}")
                print(f"  范围流数: {test_result['range_flows_count']}")
            else:
                print(f"✗ 执行失败")
                
        except Exception as e:
            print(f"✗ 执行异常: {str(e)}")
    
    def generate_report(self, output_file="data/output/performance_report.json"):
        """
        生成性能测试报告
        """
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        report = {
            "test_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": self.results,
            "summary": {
                "batch_processing": {
                    "total_tests": len(self.results["batch_processing"]),
                    "successful_tests": sum(1 for r in self.results["batch_processing"] if r.get("success", False)),
                    "avg_execution_time": sum(r.get("execution_time", 0) for r in self.results["batch_processing"]) / len(self.results["batch_processing"]) if self.results["batch_processing"] else 0
                },
                "path_finding": {
                    "total_tests": len(self.results["path_finding"]),
                    "successful_tests": sum(1 for r in self.results["path_finding"] if r.get("success", False)),
                    "avg_execution_time": sum(r.get("execution_time", 0) for r in self.results["path_finding"]) / len(self.results["path_finding"]) if self.results["path_finding"] else 0
                },
                "anomaly_detection": {
                    "total_tests": len(self.results["anomaly_detection"]),
                    "successful_tests": sum(1 for r in self.results["anomaly_detection"] if r.get("success", False)),
                    "avg_execution_time": sum(r.get("execution_time", 0) for r in self.results["anomaly_detection"]) / len(self.results["anomaly_detection"]) if self.results["anomaly_detection"] else 0
                }
            }
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n{'='*60}")
        print(f"性能测试报告已生成: {output_file}")
        print(f"{'='*60}")
        
        # 打印摘要
        print("\n性能测试摘要:")
        print(f"\n批处理测试:")
        print(f"  总测试数: {report['summary']['batch_processing']['total_tests']}")
        print(f"  成功数: {report['summary']['batch_processing']['successful_tests']}")
        print(f"  平均执行时间: {report['summary']['batch_processing']['avg_execution_time']:.3f} 秒")
        
        print(f"\n路径查找测试:")
        print(f"  总测试数: {report['summary']['path_finding']['total_tests']}")
        print(f"  成功数: {report['summary']['path_finding']['successful_tests']}")
        print(f"  平均执行时间: {report['summary']['path_finding']['avg_execution_time']:.3f} 秒")
        
        print(f"\n异常检测测试:")
        print(f"  总测试数: {report['summary']['anomaly_detection']['total_tests']}")
        print(f"  成功数: {report['summary']['anomaly_detection']['successful_tests']}")
        print(f"  平均执行时间: {report['summary']['anomaly_detection']['avg_execution_time']:.3f} 秒")

def main():
    tester = PerformanceTester()
    
    print("网络流量分析与异常检测系统 - 性能测试")
    print("="*60)
    
    # 批处理性能测试
    print("\n【批处理性能测试】")
    tester.run_batch_test(
        "data/test_data_small.csv",
        "data/output/test_small_results.json",
        "小规模数据测试 (1000流)"
    )
    
    tester.run_batch_test(
        "data/test_data_medium.csv",
        "data/output/test_medium_results.json",
        "中等规模数据测试 (10000流)"
    )
    
    tester.run_batch_test(
        "data/test_data_large.csv",
        "data/output/test_large_results.json",
        "大规模数据测试 (50000流)"
    )
    
    # 路径查找性能测试
    print("\n【路径查找性能测试】")
    tester.run_path_finding_test(
        "data/test_data_medium.csv",
        "192.168.1.1",
        "192.168.50.50",
        "data/output/test_path_1.json",
        "中等规模数据路径查找测试1"
    )
    
    tester.run_path_finding_test(
        "data/test_data_large.csv",
        "192.168.1.1",
        "192.168.100.100",
        "data/output/test_path_2.json",
        "大规模数据路径查找测试2"
    )
    
    # 异常检测性能测试
    print("\n【异常检测性能测试】")
    tester.run_anomaly_detection_test(
        "data/test_data_with_patterns.csv",
        "data/output/test_anomaly_results.json",
        "异常模式检测测试"
    )
    
    # 生成报告
    tester.generate_report()

if __name__ == "__main__":
    main()

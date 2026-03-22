import random
import csv

def generate_test_data(filename, num_flows=10000):
    """
    生成测试用的网络流量数据
    
    参数:
        filename: 输出文件名
        num_flows: 流记录数量
    """
    # 生成IP地址池
    ip_pool = []
    for i in range(1, 101):
        for j in range(1, 101):
            ip_pool.append(f"192.168.{i}.{j}")
    
    # 生成一些外部IP
    external_ips = []
    for i in range(1, 51):
        external_ips.append(f"8.8.8.{i}")
        external_ips.append(f"1.1.1.{i}")
    
    all_ips = ip_pool + external_ips
    
    # 常用端口
    common_ports = [80, 443, 22, 23, 53, 21, 25, 110, 143, 993, 995, 3306, 5432, 6379, 27017]
    
    # 协议号
    protocols = [6, 17, 1]  # TCP, UDP, ICMP
    
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Source', 'Destination', 'Protocol', 'SrcPort', 'DstPort', 'DataSize', 'Duration'])
        
        for _ in range(num_flows):
            src_ip = random.choice(all_ips)
            dst_ip = random.choice(all_ips)
            
            while dst_ip == src_ip:
                dst_ip = random.choice(all_ips)
            
            protocol = random.choice(protocols)
            src_port = random.choice(common_ports)
            dst_port = random.choice(common_ports)
            
            # 数据大小: 100字节到10MB
            data_size = random.randint(100, 10 * 1024 * 1024)
            
            # 持续时间: 0.1秒到300秒
            duration = random.uniform(0.1, 300.0)
            
            writer.writerow([src_ip, dst_ip, protocol, src_port, dst_port, data_size, duration])
    
    print(f"已生成 {num_flows} 条流记录到 {filename}")

def generate_test_data_with_patterns(filename, num_flows=10000):
    """
    生成包含特定模式的测试数据（用于测试异常检测）
    """
    ip_pool = []
    for i in range(1, 101):
        for j in range(1, 101):
            ip_pool.append(f"192.168.{i}.{j}")
    
    external_ips = []
    for i in range(1, 51):
        external_ips.append(f"8.8.8.{i}")
        external_ips.append(f"1.1.1.{i}")
    
    all_ips = ip_pool + external_ips
    common_ports = [80, 443, 22, 23, 53, 21, 25, 110, 143, 993, 995, 3306, 5432, 6379, 27017]
    protocols = [6, 17, 1]
    
    # 创建一个星型结构节点
    star_node = ip_pool[0]
    star_leafs = ip_pool[1:21]  # 20个叶子节点
    
    # 创建一个扫描节点
    scan_node = ip_pool[50]
    
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Source', 'Destination', 'Protocol', 'SrcPort', 'DstPort', 'DataSize', 'Duration'])
        
        # 生成星型结构流量
        for leaf in star_leafs:
            src_ip = leaf
            dst_ip = star_node
            protocol = random.choice(protocols)
            src_port = random.choice(common_ports)
            dst_port = random.choice(common_ports)
            data_size = random.randint(1000, 100000)
            duration = random.uniform(1.0, 60.0)
            writer.writerow([src_ip, dst_ip, protocol, src_port, dst_port, data_size, duration])
        
        # 生成扫描行为流量
        for target in ip_pool[51:151]:
            src_ip = scan_node
            dst_ip = target
            protocol = random.choice(protocols)
            src_port = random.choice(common_ports)
            dst_port = random.choice(common_ports)
            data_size = random.randint(100, 1000)  # 小包
            duration = random.uniform(0.1, 1.0)  # 短时间
            writer.writerow([src_ip, dst_ip, protocol, src_port, dst_port, data_size, duration])
        
        # 生成普通流量
        normal_count = num_flows - len(star_leafs) - 100
        for _ in range(normal_count):
            src_ip = random.choice(all_ips)
            dst_ip = random.choice(all_ips)
            
            while dst_ip == src_ip:
                dst_ip = random.choice(all_ips)
            
            protocol = random.choice(protocols)
            src_port = random.choice(common_ports)
            dst_port = random.choice(common_ports)
            data_size = random.randint(100, 10 * 1024 * 1024)
            duration = random.uniform(0.1, 300.0)
            writer.writerow([src_ip, dst_ip, protocol, src_port, dst_port, data_size, duration])
    
    print(f"已生成 {num_flows} 条流记录到 {filename} (包含星型结构和扫描模式)")

if __name__ == '__main__':
    # 生成小规模测试数据
    generate_test_data('data/test_data_small.csv', num_flows=1000)
    
    # 生成中等规模测试数据
    generate_test_data('data/test_data_medium.csv', num_flows=10000)
    
    # 生成大规模测试数据
    generate_test_data('data/test_data_large.csv', num_flows=50000)
    
    # 生成包含异常模式的测试数据
    generate_test_data_with_patterns('data/test_data_with_patterns.csv', num_flows=10000)

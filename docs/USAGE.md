# QianKunQuan - 使用说明

## 基本用法

### 1. 快速扫描（常见端口）
```bash
# 扫描目标主机的常见端口（默认）
./QianKunQuan -target "example.com"

# 扫描IP地址的常见端口
./QianKunQuan -target "192.168.1.1"
```

### 2. 指定端口范围
```bash
# 扫描单个端口
./QianKunQuan -target "example.com" -ports 80

# 扫描多个端口
./QianKunQuan -target "example.com" -ports "80,443,8080"

# 扫描端口范围
./QianKunQuan -target "example.com" -ports "1-1000"

# 扫描所有端口（1-65535）
./QianKunQuan -target "example.com" -ports "all"

# 组合使用
./QianKunQuan -target "example.com" -ports "22,80,443,8000-9000"
```

### 3. 高级选项
```bash
# 调整超时时间（秒）
./QianKunQuan -target "example.com" -timeout 5

# 调整并发线程数
./QianKunQuan -target "example.com" -threads 200

# 详细模式，显示扫描过程
./QianKunQuan -target "example.com" -verbose

# 更新CVE数据库
./QianKunQuan -update
```

### 4. 输出格式
```bash
# 文本格式（默认）
./QianKunQuan -target "example.com" -format text

# JSON格式
./QianKunQuan -target "example.com" -format json

# CSV格式
./QianKunQuan -target "example.com" -format csv

# 保存到文件
./QianKunQuan -target "example.com" -output "scan_result.json" -format json
./QianKunQuan -target "example.com" -output "scan_result.txt" -format text
```

## 参数详解

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `-target` | 无 | 目标IP地址或域名（必填） | 无 |
| `-ports` | 无 | 端口范围（如: 1-1000,80,443） | 常见端口列表 |
| `-timeout` | 无 | 连接超时时间（秒） | 2 |
| `-threads` | 无 | 并发扫描线程数 | 100 |
| `-output` | 无 | 输出文件路径 | 无（输出到控制台） |
| `-format` | 无 | 输出格式：text, json, csv | text |
| `-update` | 无 | 更新CVE漏洞数据库 | false |
| `-verbose` | 无 | 显示详细扫描过程 | false |
| `-help` | 无 | 显示帮助信息 | 无 |

## 常见端口说明

默认扫描的常见端口包括：
- **Web服务**: 80, 443, 8080, 8443, 3000, 5000
- **数据库**: 3306, 5432, 6379, 27017, 9200
- **远程访问**: 22, 23, 3389
- **邮件服务**: 25, 110, 143, 465, 587, 993, 995
- **文件传输**: 21, 139, 445
- **其他服务**: 53, 111, 135, 1433, 1521, 5984, 11211

## 使用示例

### 示例1：快速安全评估
```bash
# 扫描网站并保存JSON报告
./QianKunQuan -target "zuscoffee.com" -output "zuscoffee_scan.json" -format json
```

### 示例2：内部网络扫描
```bash
# 扫描内部服务器，详细模式
./QianKunQuan -target "192.168.1.100" -ports "1-10000" -verbose
```

### 示例3：批量扫描
```bash
# 可以结合脚本进行批量扫描
for host in host1.com host2.com host3.com; do
    ./QianKunQuan -target "$host" -output "${host}_scan.txt"
done
```

### 示例4：持续监控
```bash
# 定期扫描并更新数据库
./QianKunQuan -update
./QianKunQuan -target "example.com" -ports "common" -output "daily_scan_$(date +%Y%m%d).json" -format json
```

## 端口范围语法

| 语法 | 示例 | 说明 |
|------|------|------|
| 单个端口 | `80` | 扫描端口80 |
| 多个端口 | `80,443,8080` | 扫描端口80、443和8080 |
| 端口范围 | `1-1000` | 扫描端口1到1000 |
| 混合使用 | `22,80,443,8000-9000` | 扫描22、80、443和8000-9000端口 |
| 关键字 | `all` | 扫描所有端口（1-65535） |
| 关键字 | `common` 或 `default` | 扫描常见端口（默认） |

## 输出示例

### 文本输出示例：
```
扫描结果: example.com
主机状态: 在线
扫描时间: 5.23s

开放端口:
----------------------------------------------------------------------------------------------------
端口    协议    服务        版本        状态    风险等级    CVE数量
80      tcp     HTTP        nginx/1.18  open    中         2
443     tcp     HTTPS       -           open    低         0
3306    tcp     MySQL       5.7.32     open    高         5
```

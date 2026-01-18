# 乾坤圈 (QianKunQuan)

<div align="center">

![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-lightgrey?style=flat-square)

**基于 Go 语言开发的高性能端口扫描与 CVE 漏洞检测工具**

</div>

## 项目简介

**乾坤圈 (QianKunQuan)** 是一款功能强大的网络安全扫描工具，专为渗透测试人员、安全研究人员和系统管理员设计。它结合了**高效端口扫描**、**服务识别**、**版本检测**和**CVE漏洞关联**等核心功能，帮助您快速评估目标系统的安全状况。

### 核心特性


- **高性能扫描**：采用 Goroutine 并发模型，支持数千并发连接
- **智能服务识别**：自动识别 100+ 常见网络服务
- **版本信息提取**：从服务横幅中提取精确的版本信息（HTTP/SSH/FTP/Apache/Nginx 等）
- **CVE 漏洞检测**：内置 CVE 数据库，自动关联已识别服务的已知漏洞
- **IPv6 支持**：完全兼容 IPv4/IPv6 双协议栈
- **多格式输出**：支持 Text、JSON、CSV 等多种输出格式
- **美观的终端输出**：使用表格化展示扫描结果，清晰易读
- **实时数据库更新**：一键更新 CVE 漏洞数据库

## 快速开始

### 安装方法

#### 方法一：从源码编译（推荐）

```bash
# 克隆项目
git clone https://github.com/ctkqiang/QianKunQuan.git
cd QianKunQuan

# 编译项目
go build -o qiankunquan cmd/main.go

# 验证安装
./qiankunquan -help
```

#### 方法二：使用 Go 安装

```bash
go install github.com/your-username/QianKunQuan@latest
```

#### 方法三：下载预编译二进制文件

访问 [Releases 页面](https://github.com/your-username/QianKunQuan/releases) 下载对应平台的二进制文件。

### 第一个扫描示例

```bash
# 扫描目标网站的常见端口
./qiankunquan -target "example.com"

# 扫描特定端口范围
./qiankunquan -target "192.168.1.1" -ports "22,80,443,8080"

# 保存扫描结果到 JSON 文件
./qiankunquan -target "example.com" -output "result.json" -format json
```

## 详细使用说明

### 基本用法

#### 1. 快速扫描（常见端口）
```bash
# 扫描目标主机的常见端口（默认）
./qiankunquan -target "example.com"

# 扫描IP地址的常见端口
./qiankunquan -target "192.168.1.1"
```

#### 2. 指定端口范围
```bash
# 扫描单个端口
./qiankunquan -target "example.com" -ports 80

# 扫描多个端口
./qiankunquan -target "example.com" -ports "80,443,8080"

# 扫描端口范围
./qiankunquan -target "example.com" -ports "1-1000"

# 扫描所有端口（1-65535）
./qiankunquan -target "example.com" -ports "all"

# 组合使用
./qiankunquan -target "example.com" -ports "22,80,443,8000-9000"
```

#### 3. 高级选项
```bash
# 调整超时时间（秒）
./qiankunquan -target "example.com" -timeout 5

# 调整并发线程数
./qiankunquan -target "example.com" -threads 200

# 详细模式，显示扫描过程
./qiankunquan -target "example.com" -verbose

# 更新CVE数据库
./qiankunquan -update
```

#### 4. 输出格式
```bash
# 文本格式（默认）
./qiankunquan -target "example.com" -format text

# JSON格式
./qiankunquan -target "example.com" -format json

# CSV格式
./qiankunquan -target "example.com" -format csv

# 保存到文件
./qiankunquan -target "example.com" -output "scan_result.json" -format json
./qiankunquan -target "example.com" -output "scan_result.txt" -format text
```

### 参数详解

| 参数 | 说明 | 默认值 | 示例 |
|------|------|--------|------|
| `-target` | **目标IP地址或域名（必填）** | 无 | `-target "192.168.1.1"` |
| `-ports` | 端口范围（如: 1-1000,80,443） | 常见端口列表 | `-ports "22,80,443"` |
| `-timeout` | 连接超时时间（秒） | 2 | `-timeout 5` |
| `-threads` | 并发扫描线程数 | 100 | `-threads 200` |
| `-output` | 输出文件路径 | 无（输出到控制台） | `-output "result.json"` |
| `-format` | 输出格式：text, json, csv | text | `-format json` |
| `-update` | 更新CVE漏洞数据库 | false | `-update` |
| `-verbose` | 显示详细扫描过程 | false | `-verbose` |
| `-help` | 显示帮助信息 | 无 | `-help` |

### 常见端口说明

默认扫描的常见端口包括：
- **Web服务**: 80, 443, 8080, 8443, 3000, 5000
- **数据库**: 3306, 5432, 6379, 27017, 9200
- **远程访问**: 22, 23, 3389
- **邮件服务**: 25, 110, 143, 465, 587, 993, 995
- **文件传输**: 21, 139, 445
- **其他服务**: 53, 111, 135, 1433, 1521, 5984, 11211

## 输出示例

### 文本格式输出

```
乾坤圈 - Go语言端口扫描与CVE检测工具
==================================================
目标: example.com (93.184.216.34)
开始时间: 2024-01-01 10:30:00
==================================================

端口    状态    服务        版本      产品               CVE数量
----    ------  --------    -------   -------           -------
22      open    ssh         8.2p1     OpenSSH           3
80      open    http        1.1       nginx             5
443     open    https       2.0       nginx             7
21      open    ftp         1.3.5a    ProFTPD           2
3306    open    mysql       8.0.32    MySQL             12
5432    open    postgresql  14.5      PostgreSQL        8

==================================================
扫描完成！共发现 6 个开放端口
总耗时: 2.45 秒
```

### JSON 格式输出示例

```json
{
  "target": "example.com",
  "ip": "93.184.216.34",
  "start_time": "2024-01-01T10:30:00Z",
  "scan_results": [
    {
      "port": 22,
      "state": "open",
      "service": "ssh",
      "version": "8.2p1",
      "product": "OpenSSH",
      "cves": [
        "CVE-2023-38408",
        "CVE-2022-41323",
        "CVE-2021-41617"
      ]
    },
    {
      "port": 80,
      "state": "open",
      "service": "http",
      "version": "1.1",
      "product": "nginx",
      "cves": [
        "CVE-2023-44487",
        "CVE-2022-41741",
        "CVE-2021-3618"
      ]
    }
  ],
  "summary": {
    "total_ports": 1000,
    "open_ports": 6,
    "scan_duration": "2.45s"
  }
}
```

## 技术架构

### 核心模块

```
QianKunQuan/
├── cmd/main.go                 # 程序入口点
├── internal/
│   ├── scanner/               # 扫描器核心
│   │   ├── port_scanner.go    # 端口扫描逻辑
│   │   └── cve_scanner.go     # CVE检测逻辑
│   ├── model/                 # 数据模型
│   │   ├── scan_result.go     # 扫描结果结构
│   │   └── port_services.go   # 端口服务映射
│   ├── cvedb/                 # CVE数据库管理
│   │   ├── downloader.go      # 数据库下载
│   │   └── matcher.go         # 漏洞匹配
│   └── utils/                 # 工具函数
├── pkg/
│   ├── cli/                   # CLI界面
│   │   ├── parser.go          # 参数解析
│   │   └── output_formatter.go # 输出格式化
│   └── logger/                # 日志系统
└── docs/                      # 文档
    └── USAGE.md               # 使用说明
```

### 版本检测算法

乾坤圈使用智能的版本提取算法，支持多种服务类型：

1. **HTTP/HTTPS 服务**：从 HTTP 响应头中提取协议版本和服务器版本
2. **SSH 服务**：解析 SSH 协议横幅，提取 OpenSSH 等版本信息
3. **FTP 服务**：分析 FTP 欢迎消息，识别 ProFTPD、vsftpd 等
4. **Web 服务器**：识别 Nginx、Apache、IIS 等服务器版本
5. **数据库服务**：提取 MySQL、PostgreSQL、Redis 等版本信息

版本提取使用正则表达式模式匹配，支持：
- 标准版本格式：`X.Y.Z`
- 带字母后缀：`X.Y.Za`、`X.YpZ`
- 前缀格式：`vX.Y.Z`、`version X.Y.Z`
- 复杂版本字符串：`OpenSSH_8.2p1 Ubuntu-4ubuntu0.3`

## 开发指南

### 环境要求

- Go 1.25 或更高版本
- Git
- SQLite3（用于 CVE 数据库）

### 构建与测试

```bash
# 克隆项目
git clone https://github.com/ctkqiang/QianKunQuan.git
cd QianKunQuan

# 安装依赖
go mod download

# 运行测试
go test ./...

# 静态代码分析
go vet ./...

# 构建二进制文件
go build -o qiankunquan cmd/main.go
```

### 添加新的服务识别

要添加新的服务识别，请修改以下文件：

1. `internal/model/port_services.go` - 添加端口到服务的映射
2. `internal/scanner/port_scanner.go` - 在 `extractVersionFromBanner` 函数中添加新的正则表达式模式

示例：添加对新 FTP 服务器的支持
```go
// 在 port_services.go 中添加
var PortServices = map[int]string{
    2121: "ftp",  // 新增 FTP 端口
}

// 在 port_scanner.go 中添加版本提取模式
patterns = append(patterns, `(?i)newftpd.*?(\d+\.\d+(?:\.\d+[a-z]?)?)`)
```

## 常见问题解答

### Q1: 扫描速度太慢怎么办？
**A**: 调整 `-threads` 参数增加并发数，同时确保 `-timeout` 设置合理（通常 2-5 秒）。

### Q2: 为什么有些服务的版本无法识别？
**A**: 某些服务可能不返回版本信息，或者使用了非标准的版本格式。您可以通过 `-verbose` 模式查看原始横幅信息。

### Q3: CVE 数据库如何更新？
**A**: 运行 `./qiankunquan -update` 即可自动下载最新的 CVE 数据库。

### Q4: 支持扫描 IPv6 地址吗？
**A**: 完全支持！可以直接使用 IPv6 地址作为 target 参数。

### Q5: 如何自定义扫描端口列表？
**A**: 修改 `internal/model/port_services.go` 中的 `CommonPorts` 切片，然后重新编译。

## 贡献指南

我们欢迎各种形式的贡献！

1. **报告问题**：在 GitHub Issues 中报告 bug 或提出建议
2. **提交代码**：Fork 项目，创建功能分支，提交 Pull Request
3. **改进文档**：帮助完善文档，包括翻译、示例等
4. **分享用例**：分享您使用乾坤圈的实际案例

### 开发规范

- 遵循 Go 代码规范（使用 `gofmt`）
- 添加适当的测试用例
- 更新相关文档
- 保持向后兼容性


<div align="center">

**如果这个项目对你有帮助，请给它一个 ⭐️ 星标！**

</div>

--- 

### 🌐 全球捐赠通道

#### 国内用户

<div align="center" style="margin: 40px 0">

<div align="center">
<table>
<tr>
<td align="center" width="300">
<img src="https://github.com/ctkqiang/ctkqiang/blob/main/assets/IMG_9863.jpg?raw=true" width="200" />
<br />
<strong>🔵 支付宝</strong>（小企鹅在收金币哟~）
</td>
<td align="center" width="300">
<img src="https://github.com/ctkqiang/ctkqiang/blob/main/assets/IMG_9859.JPG?raw=true" width="200" />
<br />
<strong>🟢 微信支付</strong>（小绿龙在收金币哟~）
</td>
</tr>
</table>
</div>
</div>

#### 国际用户

<div align="center" style="margin: 40px 0">
  <a href="https://qr.alipay.com/fkx19369scgxdrkv8mxso92" target="_blank">
    <img src="https://img.shields.io/badge/Alipay-全球支付-00A1E9?style=flat-square&logo=alipay&logoColor=white&labelColor=008CD7">
  </a>
  
  <a href="https://ko-fi.com/F1F5VCZJU" target="_blank">
    <img src="https://img.shields.io/badge/Ko--fi-买杯咖啡-FF5E5B?style=flat-square&logo=ko-fi&logoColor=white">
  </a>
  
  <a href="https://www.paypal.com/paypalme/ctkqiang" target="_blank">
    <img src="https://img.shields.io/badge/PayPal-安全支付-00457C?style=flat-square&logo=paypal&logoColor=white">
  </a>
  
  <a href="https://donate.stripe.com/00gg2nefu6TK1LqeUY" target="_blank">
    <img src="https://img.shields.io/badge/Stripe-企业级支付-626CD9?style=flat-square&logo=stripe&logoColor=white">
  </a>
</div>

---

### 📌 开发者社交图谱

#### 技术交流

<div align="center" style="margin: 20px 0">
  <a href="https://github.com/ctkqiang" target="_blank">
    <img src="https://img.shields.io/badge/GitHub-开源仓库-181717?style=for-the-badge&logo=github">
  </a>
  
  <a href="https://stackoverflow.com/users/10758321/%e9%92%9f%e6%99%ba%e5%bc%ba" target="_blank">
    <img src="https://img.shields.io/badge/Stack_Overflow-技术问答-F58025?style=for-the-badge&logo=stackoverflow">
  </a>
  
  <a href="https://www.linkedin.com/in/ctkqiang/" target="_blank">
    <img src="https://img.shields.io/badge/LinkedIn-职业网络-0A66C2?style=for-the-badge&logo=linkedin">
  </a>
</div>

#### 社交互动

<div align="center" style="margin: 20px 0">
  <a href="https://www.instagram.com/ctkqiang" target="_blank">
    <img src="https://img.shields.io/badge/Instagram-生活瞬间-E4405F?style=for-the-badge&logo=instagram">
  </a>
  
  <a href="https://twitch.tv/ctkqiang" target="_blank">
    <img src="https://img.shields.io/badge/Twitch-技术直播-9146FF?style=for-the-badge&logo=twitch">
  </a>
  
  <a href="https://github.com/ctkqiang/ctkqiang/blob/main/assets/IMG_9245.JPG?raw=true" target="_blank">
    <img src="https://img.shields.io/badge/微信公众号-钟智强-07C160?style=for-the-badge&logo=wechat">
  </a>
</div>
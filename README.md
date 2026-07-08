# 乾坤圈 QianKunQuan

<div align="center">

![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go)
![Version](https://img.shields.io/badge/Version-2.0.0--redteam-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux%20|%20Windows-lightgrey?style=flat-square)
![China](https://img.shields.io/badge/Made%20with-❤️%20in%20China-red?style=flat-square)

**🔴 红队侦察作战平台 | Red Team Reconnaissance Framework**

*为中国红队/安全研究人员打造的轻量级、一体化、简单直接的侦察与漏洞利用工具*

</div>

---

## ⚠️ 法律声明

> **本工具仅供安全研究人员在获得书面授权的情况下进行安全评估、红蓝对抗、CTF竞赛使用。**
> **未经授权对他人系统进行扫描/攻击属违法行为，使用者需自行承担一切法律责任。**
> **开发者在任何情况下不对使用者的违法行为负责。**

---

## 🎯 项目定位

乾坤圈是一款**面向中国红队**的轻量级侦察作战平台，覆盖红队评估全流程：

```
侦察收集 → 漏洞发现 → 攻击路径推荐 → 报告输出
```

### 与其他工具的区别

| 特性 | 乾坤圈 | Nmap | Masscan | Xray |
|:---|:---:|:---:|:---:|:---:|
| 中国本土化（CNVD/CMS） | ✅ | ❌ | ❌ | 部分 |
| 攻击路径推荐 | ✅ | ❌ | ❌ | ❌ |
| 漏洞利用索引（POC/EXP） | ✅ | ❌ | ❌ | 部分 |
| 一键全量侦察 | ✅ | ❌ | ❌ | ❌ |
| 红队报告生成 | ✅ | ❌ | ❌ | 部分 |
| 单文件部署 | ✅ | ❌ | ✅ | ❌ |
| 中文界面 | ✅ | ❌ | ❌ | ❌ |

---

## ✨ 核心功能

### 🔍 侦察模块
- **端口扫描**：高并发TCP扫描，自动识别服务+版本+CVE
- **Web侦察**：目录爆破（300+敏感路径）+ CMS识别 + WAF检测 + 技术栈识别
- **子域名枚举**：DNS爆破 + HTTP存活探测（200+常见前缀字典）
- **全量侦察**：一键执行 子域名→端口→Web→漏洞→攻击路径→报告

### 💣 漏洞利用索引
- **服务漏洞库**：SSH/FTP/SMB/MySQL/Redis/MongoDB/ES/Docker/K8s 等 25+ 服务
- **CMS漏洞库**：织梦/ThinkPHP/WordPress/Discuz/PHPCMS/ECShop/若依 等 15+ 国内CMS
- **CNVD适配**：内置CNVD编号映射，对接国家信息安全漏洞共享平台
- **POC/EXP命令**：每条漏洞附带可直接复制的验证命令和利用命令
- **ATT&CK映射**：每条漏洞关联MITRE ATT&CK战术链

### ⚔️ 攻击路径推荐
- 基于扫描结果**自动生成**攻击向量建议
- 按**攻击阶段**分类（侦察→初始访问→执行→权限提升→横向移动）
- 每条路径包含**详细步骤**、**推荐工具**、**风险评级**
- 覆盖常见红队场景：弱口令、未授权访问、RCE、配置错误

### 📊 红队报告
- **HTML报告**：暗色主题、交互式、含ATT&CK矩阵、风险统计图表
- **Markdown报告**：便于编辑和二次加工
- **JSON格式**：支持管道传递给其他工具
- 自动生成**整改建议**（按优先级：立即/24小时/一周/一个月）

---

## 🚀 快速开始

### 安装

```bash
# 从源码编译（推荐）
git clone https://github.com/ctkqiang/QianKunQuan.git
cd QianKunQuan
go build -o qiankunquan cmd/main.go

# 验证安装
./qiankunquan
```

### 一键全量侦察（最常用）

```bash
# 对目标执行全量红队侦察，自动生成HTML报告
./qiankunquan full -t example.com

# 指定输出格式和文件名
./qiankunquan full -t target.com -o report.html -f html
```

### 端口扫描

```bash
# 扫描常见端口
./qiankunquan scan -t 192.168.1.1

# 扫描Top1000端口，快速模式
./qiankunquan scan -t example.com -p top1000 -m fast

# 输出JSON格式
./qiankunquan scan -t target.com -o result.json -f json
```

### Web应用侦察

```bash
# 自动识别CMS/WAF/技术栈 + 目录爆破
./qiankunquan web -u http://example.com

# 使用自定义目录字典
./qiankunquan web -u https://target.com -w wordlist.txt

# 通过Burp代理
./qiankunquan web -u http://target.com --proxy http://127.0.0.1:8080
```

### 子域名枚举

```bash
# DNS爆破 + HTTP存活探测
./qiankunquan subdomain -d example.com

# 使用自定义字典
./qiankunquan subdomain -d target.com -w subdomains.txt -o subs.json -f json
```

### 漏洞利用索引

```bash
# 按服务查询
./qiankunquan vuln -s redis
./qiankunquan vuln -s docker

# 按CMS查询
./qiankunquan vuln --cms thinkphp
./qiankunquan vuln --cms dedecms

# 按CVE/CNVD查询
./qiankunquan vuln -cve CVE-2019-0708
./qiankunquan vuln --cnvd CNVD-2017-07962
```

### 攻击路径推荐

```bash
# 对目标快速扫描并生成攻击路径
./qiankunquan attack -t example.com

# 从扫描结果文件生成
./qiankunquan attack -i scan_result.json -o attack.md -f markdown

# 只看初始访问阶段
./qiankunquan attack -t target.com --phase initial
```

### 生成红队报告

```bash
# 全量扫描后生成HTML报告
./qiankunquan report --full -t target.com --company "某某科技" -o report.html

# 从已有扫描结果生成Markdown报告
./qiankunquan report -i scan_result.json -f markdown -o report.md
```

### 更新漏洞数据库

```bash
./qiankunquan update
```

---

## 📖 命令详解

### 命令一览

| 命令 | 说明 | 示例 |
|:---|:---|:---|
| `scan` | 端口扫描与服务识别 | `qiankunquan scan -t 192.168.1.1` |
| `web` | Web应用侦察 | `qiankunquan web -u http://target.com` |
| `subdomain` | 子域名枚举 | `qiankunquan subdomain -d example.com` |
| `full` | 全量侦察（一键全开） | `qiankunquan full -t example.com` |
| `vuln` | 漏洞利用索引 | `qiankunquan vuln -s redis` |
| `attack` | 攻击路径推荐 | `qiankunquan attack -t target.com` |
| `report` | 红队报告生成 | `qiankunquan report --full -t target.com` |
| `update` | 更新漏洞数据库 | `qiankunquan update` |

### 端口预设

| 预设 | 说明 |
|:---|:---|
| `common` | 常见端口（~70个，默认） |
| `top100` | Nmap Top 100 |
| `top1000` | Nmap Top 1000 |
| `full` | 全端口 1-65535 |
| `22,80,443` | 自定义端口 |
| `1-1000` | 端口范围 |

### 扫描模式

| 模式 | 说明 |
|:---|:---|
| `default` | 默认速度 |
| `fast` | 快速模式（高并发） |
| `sneaky` | 隐蔽模式（低速率） |
| `deep` | 深度模式（含banner提取） |

---

## 🏗️ 技术架构

```
QianKunQuan/
├── cmd/
│   └── main.go                      # 主入口（子命令分发）
├── internal/
│   ├── scanner/
│   │   ├── port_scanner.go          # 端口扫描器
│   │   ├── web_scanner.go           # Web侦察（目录/CMS/WAF）
│   │   └── subdomain_scanner.go     # 子域名枚举
│   ├── exploit/
│   │   └── vuln_index.go            # 漏洞利用索引
│   ├── attackpath/
│   │   └── generator.go             # 攻击路径生成器
│   ├── report/
│   │   └── generator.go             # 红队报告生成器
│   ├── model/
│   │   ├── scan_result.go           # 数据模型
│   │   ├── exploit_db.go            # 漏洞利用数据库
│   │   ├── fingerprints.go          # CMS/WAF指纹库
│   │   └── port_services.go         # 端口服务映射
│   ├── cvedb/                       # CVE数据库
│   └── utils/                       # 工具函数
├── pkg/
│   └── cli/
│       ├── parser.go                # CLI参数解析（子命令架构）
│       └── output_formatter.go      # 输出格式化
└── config/
    └── config.yaml                  # 配置文件
```

---

## 🎨 输出示例

### 端口扫描输出

```
📡 乾坤圈端口扫描器 2.0.0-redteam
══════════════════════════════════════════════════════
目标: 192.168.1.1
状态: 在线 (192.168.1.1)

📊 端口状态统计: 开放(6) | 过滤(2) | 关闭(92)

🔍 端口扫描结果:
────────────────────────────────────────────────────────
端口      状态        服务          版本        CVE信息      风险等级
22/tcp    🟢 开放     ssh           8.2p1       -            ⚪ -
80/tcp    🟢 开放     http          1.1         -            ⚪ -
443/tcp   🟢 开放     https         2.0         -            ⚪ -
3306/tcp  🟢 开放     mysql         8.0.32      CVE-2023...  🔴 高
6379/tcp  🟢 开放     redis         -           -            ⚪ -
8080/tcp  🟢 开放     http-proxy    -           -            ⚪ -
```

### 漏洞利用索引输出

```
💣 漏洞利用索引
══════════════════════════════════════════════════════
共找到 1 个相关漏洞利用

[1] 🔥 Redis 未授权访问 - 未授权访问
  📋 描述: Redis默认无认证，可直接访问并getshell
  🎯 服务: redis
  ⚠️  严重程度: 🔥 严重
  🔧 推荐工具: redis-cli, metasploit, python
  🎮 ATT&CK战术: 初始访问 → 执行 → 持久化

  📝 POC验证命令:
    redis-cli -h target info

  💥 EXP利用命令:
    redis-cli -h target config set dir /root/.ssh
    redis-cli -h target config set dbfilename authorized_keys
    redis-cli -h target save
```

### 攻击路径推荐输出

```
⚔️  攻击路径推荐
══════════════════════════════════════════════════════
共生成 5 条攻击路径建议

🎯 阶段: 初始访问 (3条)
  [1] 🔥 Redis未授权访问
      战术: 执行 | 风险: 严重
      描述: Redis默认无认证，可直接访问并getshell
      工具: redis-cli, metasploit, python
      攻击步骤:
        1. 验证未授权访问
        2. 写SSH公钥getshell
        3. 写webshell（如果有web路径）
        4. 主从复制RCE
```

---

## 🛡️ 支持的检测项

### CMS识别（20+）
织梦CMS | ThinkPHP | WordPress | Discuz! | PHPCMS | ECShop | MetInfo | Joomla! | Drupal | Typecho | emlog | Z-Blog | FineCMS | PbootCMS | 若依RuoYi | JEECG | Tomcat | Nginx | Apache | IIS

### WAF检测（15+）
安全狗 | 阿里云盾 | 腾讯云WAF | 百度云加速 | CloudFlare | ModSecurity | 阿里云CDN | Incapsula/Imperva | Akamai | 宝塔WAF | 360网站卫士 | 知道创宇加速乐 | 网宿WAF | 华为云WAF

### 服务漏洞（25+）
SSH | FTP | SMB | MySQL | Redis | MongoDB | Elasticsearch | PostgreSQL | Oracle | RDP | Telnet | VNC | DNS | LDAP | Docker | Kubernetes | ZooKeeper | NFS | Flask | Grafana | Memcached | HTTP

---

## 🔧 开发指南

### 环境要求
- Go 1.25+
- SQLite3（CVE数据库）

### 编译与测试

```bash
# 编译
go build -o qiankunquan cmd/main.go

# 运行测试
go test ./...

# 静态检查
go vet ./...
```

### 添加新的漏洞利用

编辑 `internal/model/exploit_db.go`，在 `RedTeamExploitDB` 或 `CMSExploitDB` 中添加条目：

```go
{
    Service:     "your-service",
    Name:        "漏洞名称",
    Type:        "漏洞类型",
    Description: "漏洞描述",
    POC_CMD:     "验证命令",
    EXP_CMD:     "利用命令",
    Tools:       []string{"tool1", "tool2"},
    Tactics:     []string{"初始访问", "执行"},
    Severity:    "严重",
}
```

### 添加新的CMS指纹

编辑 `internal/model/fingerprints.go`，在 `CMSFingerprints` 中添加：

```go
{
    Name:  "YourCMS",
    Body: []string{"特征字符串1", "特征字符串2"},
    Header: map[string]string{
        "X-Powered-By": "YourCMS",
    },
}
```

---

## 📌 红队实战场景

### 场景1：快速打点

```bash
# 对一个C段快速扫描常见端口
./qiankunquan scan -t 192.168.1.0 -p common -m fast -th 500

# 发现Web服务后立即Web侦察
./qiankunquan web -u http://192.168.1.100
```

### 场景2：外网资产梳理

```bash
# 子域名枚举
./qiankunquan subdomain -d target.com -o subs.json -f json

# 对发现的子域名全量侦察
./qiankunquan full -t target.com -o recon_report.html
```

### 场景3：内网横向移动侦察

```bash
# 扫描内网存活主机和端口
./qiankunquan scan -t 10.0.0.0 -p top100 -m fast

# 发现Redis/Docker等服务后查利用方法
./qiankunquan vuln -s redis
./qiankunquan vuln -s docker
```

### 场景4：生成客户报告

```bash
# 全量扫描 + 生成带公司名的报告
./qiankunquan report --full -t target.com \
  --company "某某科技有限公司" \
  --assessor "红队A组" \
  -o 客户评估报告.html
```

---

## ❓ 常见问题

**Q: 扫描速度慢？**
A: 增加 `-th`（线程数），减小 `-T`（超时）。推荐 `-th 500 -T 2`。

**Q: CVE数据库如何更新？**
A: 运行 `./qiankunquan update`。

**Q: 支持IPv6吗？**
A: 完全支持，直接使用IPv6地址即可。

**Q: 可以穿透代理吗？**
A: Web侦察支持 `--proxy` 参数，端口扫描暂不支持。

**Q: 如何自定义扫描端口？**
A: 使用 `-p 22,80,443,8080` 或 `-p 1-1000`。

---

<div align="center">

**如果这个工具帮到了你，请给它一个 ⭐️ 星标！**

**🔴 红队利器，为国护网 🔴**

</div>
---

## 支持

如果您觉得本项目对您有帮助，欢迎请我喝杯咖啡，您的支持是我持续维护和改进的动力！

<p align="center">
  <strong>微信扫码捐赠</strong><br/>
  <img src="https://raw.gitcode.com/ctkqiang_sr/ctkqiang_sr/raw/main/mm_reward_qrcode_1778988737577.png"
       alt="微信扫码捐赠"
       width="240"
       style="border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);" />
</p>

---

<div align="center">

基于 Go 构建 · 由 MCP 驱动 · 安全设计 · ctkqiang

</div>

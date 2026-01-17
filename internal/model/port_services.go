package model

import "time"

// CommonPorts 常见端口映射
var CommonPorts = map[int]ServiceInfo{
	20:    {"FTP-DATA", "", "", "文件传输协议数据"},
	21:    {"FTP", "", "", "文件传输协议"},
	22:    {"SSH", "", "", "安全外壳协议"},
	23:    {"Telnet", "", "", "远程登录协议"},
	25:    {"SMTP", "", "", "简单邮件传输协议"},
	53:    {"DNS", "", "", "域名系统"},
	69:    {"TFTP", "", "", "简单文件传输协议"},
	80:    {"HTTP", "", "", "网页服务器"},
	110:   {"POP3", "", "", "邮局协议第3版"},
	111:   {"RPC", "", "", "远程过程调用"},
	135:   {"MSRPC", "", "", "微软远程过程调用"},
	139:   {"NetBIOS-SSN", "", "", "NetBIOS会话服务"},
	143:   {"IMAP", "", "", "互联网消息访问协议"},
	161:   {"SNMP", "", "", "简单网络管理协议"},
	389:   {"LDAP", "", "", "轻量级目录访问协议"},
	443:   {"HTTPS", "", "", "安全网页服务器"},
	445:   {"SMB", "", "", "服务器消息块"},
	514:   {"Syslog", "", "", "系统日志服务"},
	993:   {"IMAPS", "", "", "基于SSL的IMAP"},
	995:   {"POP3S", "", "", "基于SSL的POP3"},
	1433:  {"MSSQL", "", "", "微软SQL Server"},
	1521:  {"Oracle", "", "", "Oracle数据库"},
	3306:  {"MySQL", "", "", "数据库"},
	3389:  {"RDP", "", "", "远程桌面协议"},
	5432:  {"PostgreSQL", "", "", "数据库"},
	5900:  {"VNC", "", "", "虚拟网络计算"},
	6379:  {"Redis", "", "", "数据库"},
	8080:  {"HTTP-Proxy", "", "", "备用HTTP"},
	8443:  {"HTTPS-Alt", "", "", "备用HTTPS"},
	9200:  {"Elasticsearch", "", "", "搜索与分析引擎"},
	27017: {"MongoDB", "", "", "NoSQL数据库"},
}

// VulnerabilityDB 漏洞数据库配置
type VulnerabilityDB struct {
	SourceURL  string
	LocalPath  string
	LastUpdate time.Time
	IsUpdated  bool
}

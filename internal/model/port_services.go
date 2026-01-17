package model

import "time"

// CommonPorts 常见端口映射
var CommonPorts = map[int]ServiceInfo{
	// 基础服务
	21:  {"FTP", "", "", "File Transfer Protocol"},
	22:  {"SSH", "", "", "Secure Shell"},
	23:  {"Telnet", "", "", "Telnet Protocol"},
	25:  {"SMTP", "", "", "Simple Mail Transfer Protocol"},
	53:  {"DNS", "", "", "Domain Name System"},
	80:  {"HTTP", "", "", "Web Server"},
	110: {"POP3", "", "", "Post Office Protocol v3"},
	111: {"RPC", "", "", "Remote Procedure Call"},
	135: {"MSRPC", "", "", "Microsoft RPC"},
	139: {"NetBIOS", "", "", "NetBIOS Session Service"},
	143: {"IMAP", "", "", "Internet Message Access Protocol"},
	443: {"HTTPS", "", "", "Secure Web Server"},
	445: {"SMB", "", "", "Server Message Block"},
	465: {"SMTPS", "", "", "SMTP over SSL"},
	587: {"SMTP", "", "", "SMTP Submission"},
	993: {"IMAPS", "", "", "IMAP over SSL"},
	995: {"POP3S", "", "", "POP3 over SSL"},

	// 数据库
	1433:  {"MSSQL", "", "", "Microsoft SQL Server"},
	1521:  {"Oracle", "", "", "Oracle Database"},
	3306:  {"MySQL", "", "", "MySQL Database"},
	3389:  {"RDP", "", "", "Remote Desktop Protocol"},
	5432:  {"PostgreSQL", "", "", "PostgreSQL Database"},
	5984:  {"CouchDB", "", "", "CouchDB Database"},
	6379:  {"Redis", "", "", "Redis Database"},
	8080:  {"HTTP-Proxy", "", "", "Alternative HTTP"},
	8443:  {"HTTPS", "", "", "Alternative HTTPS"},
	9200:  {"Elasticsearch", "", "", "Elasticsearch"},
	9300:  {"Elasticsearch", "", "", "Elasticsearch Cluster"},
	11211: {"Memcached", "", "", "Memcached"},
	27017: {"MongoDB", "", "", "MongoDB Database"},

	// 其他常用服务
	3000:  {"Node.js", "", "", "Node.js Development"},
	3001:  {"Node.js", "", "", "Node.js Alternative"},
	5000:  {"Flask", "", "", "Python Flask"},
	5001:  {"Flask", "", "", "Python Flask Alternative"},
	5433:  {"PostgreSQL", "", "", "PostgreSQL Alternative"},
	5434:  {"PostgreSQL", "", "", "PostgreSQL Alternative"},
	8000:  {"HTTP", "", "", "Development HTTP"},
	8001:  {"HTTP", "", "", "Development HTTP"},
	8008:  {"HTTP", "", "", "Alternative HTTP"},
	8081:  {"HTTP", "", "", "HTTP Proxy"},
	8082:  {"HTTP", "", "", "HTTP Proxy"},
	8083:  {"HTTP", "", "", "HTTP Proxy"},
	8084:  {"HTTP", "", "", "HTTP Proxy"},
	8085:  {"HTTP", "", "", "HTTP Proxy"},
	8086:  {"HTTP", "", "", "HTTP Proxy"},
	8087:  {"HTTP", "", "", "HTTP Proxy"},
	8088:  {"HTTP", "", "", "HTTP Proxy"},
	8089:  {"HTTP", "", "", "HTTP Proxy"},
	8888:  {"Jupyter", "", "", "Jupyter Notebook"},
	8889:  {"HTTP", "", "", "Alternative HTTP"},
	9000:  {"PHP-FPM", "", "", "PHP FastCGI"},
	9001:  {"SonarQube", "", "", "Code Quality Tool"},
	10000: {"Webmin", "", "", "Web-based Admin"},
}

// VulnerabilityDB 漏洞数据库配置
type VulnerabilityDB struct {
	SourceURL  string
	LocalPath  string
	LastUpdate time.Time
	IsUpdated  bool
}

// CommonPortsList 返回常见端口列表（用于默认扫描）
func CommonPortsList() []int {
	ports := make([]int, 0, len(CommonPorts))
	for port := range CommonPorts {
		ports = append(ports, port)
	}
	return ports
}

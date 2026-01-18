package scanner

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"QianKunQuan/internal/model"
	"QianKunQuan/internal/utils"
)

type PortScanner struct {
	timeout time.Duration
	threads int
	results chan model.PortResult
	wg      sync.WaitGroup
	logger  *utils.Logger
	ctx     context.Context
	cancel  context.CancelFunc
	verbose bool
}

func NewPortScanner(timeoutSec int, threads int, verbose bool) *PortScanner {
	ctx, cancel := context.WithCancel(context.Background())
	return &PortScanner{
		timeout: time.Duration(timeoutSec) * time.Second,
		threads: threads,
		results: make(chan model.PortResult, 1000),
		logger:  utils.NewLogger("scanner"),
		ctx:     ctx,
		cancel:  cancel,
		verbose: verbose,
	}
}

// ParsePortRange 解析端口范围
func (ps *PortScanner) ParsePortRange(portRange string) ([]int, error) {
	if portRange == "" {
		// 扫描常见端口
		ports := model.CommonPortsList()
		ps.logger.Info("未指定端口范围，将扫描 %d 个常见端口", len(ports))
		return ports, nil
	}

	// 处理特殊关键字
	if strings.ToLower(portRange) == "all" {
		ps.logger.Info("扫描所有端口 (1-65535)")
		var allPorts []int
		for port := 1; port <= 65535; port++ {
			allPorts = append(allPorts, port)
		}
		return allPorts, nil
	}

	if strings.ToLower(portRange) == "common" || strings.ToLower(portRange) == "default" {
		ports := model.CommonPortsList()
		ps.logger.Info("扫描常见端口 (%d个)", len(ports))
		return ports, nil
	}

	var ports []int

	// 处理端口范围
	parts := strings.Split(portRange, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("无效的端口范围: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("无效的起始端口: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("无效的结束端口: %s", rangeParts[1])
			}

			if start > end {
				return nil, fmt.Errorf("起始端口不能大于结束端口: %s", part)
			}

			if start < 1 || end > 65535 {
				return nil, fmt.Errorf("端口范围必须在 1-65535 之间: %s", part)
			}

			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("无效的端口号: %s", part)
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("端口号必须在 1-65535 之间: %d", port)
			}

			ports = append(ports, port)
		}
	}

	// 去重并排序
	return ps.removeDuplicatesAndSort(ports), nil
}

// 去重并排序函数
func (ps *PortScanner) removeDuplicatesAndSort(ports []int) []int {
	if len(ports) == 0 {
		return ports
	}

	// 去重
	seen := make(map[int]bool)
	var uniquePorts []int
	for _, port := range ports {
		if !seen[port] {
			seen[port] = true
			uniquePorts = append(uniquePorts, port)
		}
	}

	// 排序
	for i := 0; i < len(uniquePorts)-1; i++ {
		for j := i + 1; j < len(uniquePorts); j++ {
			if uniquePorts[i] > uniquePorts[j] {
				uniquePorts[i], uniquePorts[j] = uniquePorts[j], uniquePorts[i]
			}
		}
	}

	return uniquePorts
}

// ScanPort 扫描单个端口 - 改进版本
func (ps *PortScanner) ScanPort(target string, port int, protocol string) model.PortResult {
	result := model.PortResult{
		Port:     port,
		Protocol: protocol,
		State:    "closed",
	}

	address := fmt.Sprintf("%s:%d", target, port)

	if ps.verbose {
		ps.logger.Debug("尝试连接: %s (端口 %d)", address, port)
	}

	// 尝试连接 - 使用更灵活的Dialer
	dialer := &net.Dialer{
		Timeout: ps.timeout,
	}

	conn, err := dialer.Dial(protocol, address)
	if err != nil {
		if ps.verbose {
			ps.logger.Debug("端口 %d 连接失败: %v", port, err)
		}

		// 根据错误类型判断端口状态
		if strings.Contains(err.Error(), "timeout") ||
			strings.Contains(err.Error(), "i/o timeout") {
			result.State = "filtered"
		} else if strings.Contains(err.Error(), "refused") ||
			strings.Contains(err.Error(), "connection refused") {
			result.State = "closed"
		} else if strings.Contains(err.Error(), "network is unreachable") ||
			strings.Contains(err.Error(), "no route to host") {
			result.State = "unreachable"
		} else if strings.Contains(err.Error(), "too many open files") {
			// 处理文件描述符过多的问题
			time.Sleep(50 * time.Millisecond)
			return ps.ScanPort(target, port, protocol)
		} else {
			result.State = "closed"
		}
		return result
	}
	defer conn.Close()

	// 端口开放
	result.State = "open"
	if ps.verbose {
		ps.logger.Info("端口 %d 开放!", port)
	}

	// 尝试获取banner
	if protocol == "tcp" {
		banner := ps.grabBanner(conn, port)
		result.Banner = banner

		// 识别服务
		serviceName := ps.detectService(port, banner)
		if serviceInfo, exists := model.CommonPorts[port]; exists {
			result.Service = serviceInfo
			// 如果banner中有版本信息，更新服务信息
			if banner != "" && serviceInfo.Version == "" {
				version := ps.extractVersionFromBanner(banner, serviceInfo.Name)
				if version != "" {
					result.Service.Version = version
					result.Service.Product = serviceInfo.Name
				}
			}
		} else {
			result.Service = model.ServiceInfo{
				Name:  serviceName,
				Extra: "自动识别",
			}
		}

		if ps.verbose && banner != "" {
			// 只显示banner的前100个字符
			displayBanner := banner
			if len(displayBanner) > 100 {
				displayBanner = displayBanner[:100] + "..."
			}
			ps.logger.Debug("端口 %d banner: %s", port, displayBanner)
		}
	}

	return result
}

// 从banner中提取版本信息
func (ps *PortScanner) extractVersionFromBanner(banner, serviceName string) string {
	// 查找版本号模式
	patterns := []string{
		`\d+\.\d+(\.\d+)*`,          // 1.2.3 或 1.2
		`v\d+\.\d+`,                 // v1.2
		`version\s*[:]?\s*\d+\.\d+`, // version 1.2 或 version:1.2
		`(?i)` + strings.ToLower(serviceName) + `[/\s]+\d+\.\d+`, // nginx/1.18
		`\d+\.\d+\.\d+\.\d+`, // IP地址格式
	}

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		matches := re.FindString(banner)
		if matches != "" {
			return matches
		}
	}

	return ""
}

// grabBanner 获取端口banner信息 - 改进版本
func (ps *PortScanner) grabBanner(conn net.Conn, port int) string {
	defer func() {
		if r := recover(); r != nil {
			ps.logger.Error("grabBanner panic recovered: %v", r)
		}
	}()

	// 设置读取超时
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	buffer := make([]byte, 2048) // 增大缓冲区
	var banner string

	// 根据不同端口发送不同的探测包
	if ps.verbose {
		ps.logger.Debug("发送探测包到端口 %d", port)
	}

	switch port {
	case 22: // SSH
		conn.Write([]byte("SSH-2.0-Client\r\n"))

	case 25, 465, 587: // SMTP
		conn.Write([]byte("EHLO example.com\r\n"))

	case 80, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8888, 8889, 9000, 9001: // HTTP
		conn.Write([]byte("GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: QianKunQuan-Scanner/1.0\r\nAccept: */*\r\n\r\n"))

	case 443, 8443: // HTTPS
		// HTTPS尝试发送HTTP请求（有些服务器会降级响应）
		conn.Write([]byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"))

	case 3306: // MySQL
		// 发送简单的MySQL握手包
		conn.Write([]byte{
			0x0a, 0x00, 0x00, 0x00, // 协议版本长度
		})
		time.Sleep(200 * time.Millisecond)

	case 5432, 5433, 5434: // PostgreSQL
		// PostgreSQL启动消息
		conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f})
		time.Sleep(200 * time.Millisecond)

	case 6379: // Redis
		conn.Write([]byte("PING\r\n"))
		time.Sleep(200 * time.Millisecond)

	case 21: // FTP
		time.Sleep(200 * time.Millisecond) // FTP通常会自动发送欢迎信息

	case 23: // Telnet
		time.Sleep(200 * time.Millisecond)

	case 110, 143: // POP3, IMAP
		time.Sleep(200 * time.Millisecond)

	default:
		// 对于其他端口，等待一小段时间后尝试读取
		time.Sleep(100 * time.Millisecond)
	}

	// 尝试读取响应
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)

	if err != nil {
		if ps.verbose && !strings.Contains(err.Error(), "timeout") {
			ps.logger.Debug("端口 %d 读取失败: %v", port, err)
		}
		return ""
	}

	if n > 0 {
		banner = string(buffer[:n])
		banner = strings.TrimSpace(banner)

		// 限制banner长度
		if len(banner) > 500 {
			banner = banner[:500] + "..."
		}

		if ps.verbose {
			ps.logger.Debug("端口 %d 收到 %d 字节响应", port, n)
		}
	}

	return banner
}

// detectService 根据端口和banner识别服务 - 改进版本
func (ps *PortScanner) detectService(port int, banner string) string {
	// 首先检查CommonPorts中的已知服务
	if serviceInfo, exists := model.CommonPorts[port]; exists {
		return serviceInfo.Name
	}

	// 如果banner为空，返回unknown
	if banner == "" {
		return fmt.Sprintf("unknown-%d", port)
	}

	// 根据banner内容识别服务
	bannerLower := strings.ToLower(banner)

	// 扩展服务识别模式
	servicePatterns := map[string][]string{
		"HTTP":          {"http/", "server:", "apache", "nginx", "iis", "tomcat", "jetty", "lighttpd"},
		"SSH":           {"ssh-", "openssh", "dropbear"},
		"FTP":           {"220", "ftp", "filezilla", "vsftpd", "proftpd"},
		"SMTP":          {"220", "smtp", "esmtp", "postfix", "exim", "sendmail", "qmail"},
		"DNS":           {"domain", "bind", "dns"},
		"RDP":           {"rdp", "remote desktop", "microsoft terminal services"},
		"MySQL":         {"mysql", "mariadb"},
		"PostgreSQL":    {"postgresql", "postgres"},
		"Redis":         {"redis", "redis server"},
		"MongoDB":       {"mongodb"},
		"Elasticsearch": {"elasticsearch", "elastic"},
		"Memcached":     {"memcached"},
		"CouchDB":       {"couchdb"},
		"Oracle":        {"oracle", "oracle database"},
		"MSSQL":         {"sql server", "microsoft sql", "ms sql"},
		"SMB":           {"samba", "smb", "microsoft-ds"},
		"Telnet":        {"telnet", "linux"},
		"VNC":           {"vnc", "tightvnc", "tigervnc", "realvnc"},
		"Proxy":         {"proxy", "squid", "haproxy"},
		"VPN":           {"openvpn", "pptp", "l2tp"},
		"LDAP":          {"ldap", "openldap"},
	}

	for service, patterns := range servicePatterns {
		for _, pattern := range patterns {
			if strings.Contains(bannerLower, pattern) {
				return service
			}
		}
	}

	// 尝试通过端口号推测常见服务
	switch port {
	case 53:
		return "DNS"
	case 67, 68:
		return "DHCP"
	case 69:
		return "TFTP"
	case 123:
		return "NTP"
	case 161, 162:
		return "SNMP"
	case 389:
		return "LDAP"
	case 636:
		return "LDAPS"
	case 993:
		return "IMAPS"
	case 995:
		return "POP3S"
	case 1433:
		return "MSSQL"
	case 1521:
		return "Oracle"
	case 1723:
		return "PPTP"
	case 1812, 1813:
		return "RADIUS"
	case 2049:
		return "NFS"
	case 3389:
		return "RDP"
	case 5060, 5061:
		return "SIP"
	case 5900, 5901:
		return "VNC"
	case 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009:
		return "HTTP"
	case 8443:
		return "HTTPS"
	case 9090:
		return "HTTP"
	case 9200, 9300:
		return "Elasticsearch"
	case 11211:
		return "Memcached"
	case 27017:
		return "MongoDB"
	}

	return fmt.Sprintf("unknown-%d", port)
}

// ConcurrentScan 并发扫描
func (ps *PortScanner) ConcurrentScan(target string, ports []int) <-chan model.PortResult {
	// 重置context
	ps.ctx, ps.cancel = context.WithCancel(context.Background())

	// 创建工作池
	portChan := make(chan int, len(ports))

	// 启动worker
	for i := 0; i < ps.threads; i++ {
		ps.wg.Add(1)
		go ps.worker(ps.ctx, target, portChan)
	}

	// 发送端口到channel
	go func() {
		for _, port := range ports {
			select {
			case portChan <- port:
			case <-ps.ctx.Done():
				break
			}
		}
		close(portChan)
		ps.wg.Wait()
		close(ps.results)
	}()

	return ps.results
}

func (ps *PortScanner) worker(ctx context.Context, target string, ports <-chan int) {
	defer ps.wg.Done()

	for port := range ports {
		select {
		case <-ctx.Done():
			return
		default:
			result := ps.ScanPort(target, port, "tcp")
			if result.State == "open" {
				ps.results <- result
			}
		}
	}
}

func (ps *PortScanner) Stop() {
	ps.cancel()
}

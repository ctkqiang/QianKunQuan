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

// 在文件顶部添加标准端口服务映射
var standardPorts = map[int]string{
	// 基础服务
	21:  "ftp",
	22:  "ssh",
	23:  "telnet",
	25:  "smtp",
	53:  "domain",
	80:  "http",
	110: "pop3",
	111: "sunrpc",
	135: "msrpc",
	139: "netbios-ssn",
	143: "imap",
	443: "https",
	445: "microsoft-ds",
	465: "smtps",
	587: "submission",
	993: "imaps",
	995: "pop3s",

	// 数据库
	1433:  "ms-sql-s",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "ms-wbt-server",
	5432:  "postgresql",
	5984:  "couchdb",
	6379:  "redis",
	8080:  "http-proxy",
	8443:  "https-alt",
	9200:  "elasticsearch",
	9300:  "elasticsearch",
	11211: "memcached",
	27017: "mongodb",

	// 其他常用服务
	3000:  "ppp",
	3001:  "nessus",
	5000:  "upnp",
	5001:  "commplex-link",
	5433:  "postgresql",
	5434:  "postgresql",
	8000:  "http-alt",
	8001:  "vcom-tunnel",
	8008:  "http",
	8081:  "sunproxyadmin",
	8082:  "blackice-alerts",
	8083:  "us-srv",
	8084:  "websnp",
	8085:  "simplifymedia",
	8086:  "d-s-n",
	8087:  "puppet",
	8088:  "radan-http",
	8089:  "sunproxyadmin",
	8888:  "sun-answerbook",
	8889:  "ddi-tcp-2",
	9000:  "cslistener",
	9001:  "etlservicemgr",
	10000: "snet-sensor-mgmt",
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

	// 简单排序
	for i := 0; i < len(uniquePorts)-1; i++ {
		for j := i + 1; j < len(uniquePorts); j++ {
			if uniquePorts[i] > uniquePorts[j] {
				uniquePorts[i], uniquePorts[j] = uniquePorts[j], uniquePorts[i]
			}
		}
	}

	return uniquePorts
}

// ScanPort 扫描单个端口 - 改进服务识别
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

	// 先设置默认服务名（根据端口）
	if serviceName, exists := standardPorts[port]; exists {
		result.Service.Name = serviceName
	} else if serviceInfo, exists := model.CommonPorts[port]; exists {
		result.Service.Name = serviceInfo.Name
	} else {
		result.Service.Name = ""
	}

	// 尝试连接
	dialer := &net.Dialer{
		Timeout: ps.timeout,
	}

	startTime := time.Now()
	conn, err := dialer.Dial(protocol, address)
	elapsed := time.Since(startTime)

	if err != nil {
		errStr := err.Error()

		if ps.verbose {
			ps.logger.Debug("端口 %d 连接失败 (耗时: %v): %v", port, elapsed, err)
		}

		// 判断端口状态
		switch {
		case strings.Contains(errStr, "timeout") ||
			strings.Contains(errStr, "i/o timeout") ||
			strings.Contains(errStr, "deadline exceeded"):
			result.State = "filtered"

		case strings.Contains(errStr, "refused") ||
			strings.Contains(errStr, "connection refused"):
			result.State = "closed"

		case strings.Contains(errStr, "network is unreachable") ||
			strings.Contains(errStr, "no route to host"):
			result.State = "unreachable"

		case strings.Contains(errStr, "too many open files"):
			time.Sleep(100 * time.Millisecond)
			if ps.verbose {
				ps.logger.Debug("端口 %d 重试...", port)
			}
			return ps.ScanPort(target, port, protocol)

		default:
			result.State = "closed"
		}

		return result
	}
	defer conn.Close()

	// 端口开放
	result.State = "open"

	if ps.verbose {
		ps.logger.Info("端口 %d 开放! (耗时: %v)", port, elapsed)
	}

	// 尝试获取banner
	if protocol == "tcp" {
		banner := ps.grabBanner(conn, port)
		result.Banner = banner

		// 识别服务
		serviceName := ps.detectService(port, banner)
		if serviceName != "" {
			result.Service.Name = serviceName
		}

		// 提取版本信息
		if banner != "" {
			version := ps.extractVersionFromBanner(banner, result.Service.Name)
			if version != "" {
				result.Service.Version = version
			}
		}

		if ps.verbose {
			if banner != "" {
				displayBanner := banner
				if len(displayBanner) > 80 {
					displayBanner = displayBanner[:80] + "..."
				}
				ps.logger.Debug("端口 %d banner: %s", port, displayBanner)
			} else {
				ps.logger.Debug("端口 %d 没有收到banner", port)
			}
		}
	}

	return result
}

// 从banner中提取版本信息
func (ps *PortScanner) extractVersionFromBanner(banner, serviceName string) string {
	if banner == "" {
		return ""
	}

	// 查找版本号模式
	patterns := []string{
		`\d+\.\d+(\.\d+)*`,          // 1.2.3 或 1.2
		`v\d+\.\d+`,                 // v1.2
		`version\s*[:]?\s*\d+\.\d+`, // version 1.2 或 version:1.2
		`(?i)` + strings.ToLower(serviceName) + `[/\s]+\d+\.\d+`, // nginx/1.18
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

	buffer := make([]byte, 4096) // 增大缓冲区
	var banner string

	if ps.verbose {
		ps.logger.Debug("尝试获取端口 %d 的banner...", port)
	}

	// 根据不同端口发送不同的探测包
	switch port {
	case 22: // SSH
		conn.Write([]byte("SSH-2.0-Client\r\n"))
		time.Sleep(100 * time.Millisecond)

	case 25, 465, 587: // SMTP
		conn.Write([]byte("EHLO example.com\r\n"))
		time.Sleep(100 * time.Millisecond)

	case 80, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
		8888, 8889, 9000, 9001: // HTTP
		conn.Write([]byte("GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: QianKunQuan-Scanner/1.0\r\nAccept: */*\r\n\r\n"))

	case 443, 8443: // HTTPS
		// HTTPS尝试发送HTTP请求（有些服务器会降级响应）
		conn.Write([]byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"))

	case 3306: // MySQL
		// MySQL握手协议 - 更完整的握手包
		if ps.verbose {
			ps.logger.Debug("发送MySQL握手包到端口 %d", port)
		}
		// MySQL protocol version 10, server version 5.7.32
		handshake := []byte{
			0x0a,                                     // Protocol version
			0x35, 0x2e, 0x37, 0x2e, 0x33, 0x32, 0x00, // Server version
			0x00, 0x00, 0x00, 0x00, // Thread ID
			0x00, 0x00, 0x00, 0x00, // Salt (part1)
			0x00,       // Filter
			0x00, 0x00, // Server capabilities (low)
			0x00,       // Server language
			0x00, 0x00, // Server status
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Extended server capabilities
			0x00,                                           // Authentication plugin length
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Salt (part2)
			0x00, // Authentication plugin
		}
		conn.Write(handshake)
		time.Sleep(200 * time.Millisecond)

	case 5432, 5433, 5434: // PostgreSQL
		conn.Write([]byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f})
		time.Sleep(200 * time.Millisecond)

	case 6379: // Redis
		conn.Write([]byte("PING\r\nINFO\r\n"))
		time.Sleep(200 * time.Millisecond)

	default:
		// 对于其他端口，等待一小段时间后尝试读取
		time.Sleep(150 * time.Millisecond)
	}

	// 尝试读取响应
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 非阻塞读取，多次尝试
	for i := 0; i < 3; i++ {
		n, err := conn.Read(buffer)
		if err != nil {
			// 如果是超时或EOF，继续尝试
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if i < 2 && ps.verbose {
					ps.logger.Debug("端口 %d 读取超时，重试 %d/2", port, i+1)
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			break
		}

		if n > 0 {
			banner = string(buffer[:n])
			banner = strings.TrimSpace(banner)

			if ps.verbose {
				ps.logger.Debug("端口 %d 收到 %d 字节响应", port, n)
			}
			break
		}
	}

	// 限制banner长度
	if len(banner) > 500 {
		banner = banner[:500] + "..."
	}

	return banner
}

// detectService 根据端口和banner识别服务
func (ps *PortScanner) detectService(port int, banner string) string {
	// 首先检查CommonPorts中的已知服务
	if serviceInfo, exists := model.CommonPorts[port]; exists {
		return strings.ToLower(serviceInfo.Name)
	}

	// 如果banner为空，根据端口号返回常见服务名
	if banner == "" {
		switch port {
		case 3306:
			return "mysql"
		case 5432:
			return "postgresql"
		case 80:
			return "http"
		case 443:
			return "https"
		case 22:
			return "ssh"
		case 21:
			return "ftp"
		case 25:
			return "smtp"
		case 23:
			return "telnet"
		case 53:
			return "dns"
		case 110:
			return "pop3"
		case 143:
			return "imap"
		case 465:
			return "smtps"
		case 587:
			return "smtp"
		case 993:
			return "imaps"
		case 995:
			return "pop3s"
		case 1433:
			return "ms-sql-s"
		case 1521:
			return "oracle"
		case 3389:
			return "ms-wbt-server"
		case 5900:
			return "vnc"
		case 6379:
			return "redis"
		case 8080:
			return "http-proxy"
		case 8443:
			return "https-alt"
		default:
			return fmt.Sprintf("unknown-%d", port)
		}
	}

	// 根据banner内容识别服务
	bannerLower := strings.ToLower(banner)

	// 映射到nmap常见的服务名
	switch {
	case strings.Contains(bannerLower, "apache") ||
		strings.Contains(bannerLower, "http/") ||
		strings.Contains(bannerLower, "server: apache"):
		return "http"

	case strings.Contains(bannerLower, "nginx"):
		return "http"

	case strings.Contains(bannerLower, "iis") ||
		strings.Contains(bannerLower, "microsoft-httpapi"):
		return "http"

	case strings.Contains(bannerLower, "ssh"):
		return "ssh"

	case strings.Contains(bannerLower, "ftp"):
		return "ftp"

	case strings.Contains(bannerLower, "smtp"):
		return "smtp"

	case strings.Contains(bannerLower, "mysql"):
		return "mysql"

	case strings.Contains(bannerLower, "postgresql") ||
		strings.Contains(bannerLower, "postgres"):
		return "postgresql"

	case strings.Contains(bannerLower, "redis"):
		return "redis"

	case strings.Contains(bannerLower, "mongodb"):
		return "mongodb"

	case strings.Contains(bannerLower, "microsoft") ||
		strings.Contains(bannerLower, "mssql"):
		return "ms-sql-s"

	case strings.Contains(bannerLower, "oracle"):
		return "oracle"

	default:
		// 尝试根据端口返回
		switch port {
		case 80, 8080, 8000, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8888, 8889, 9000, 9001:
			return "http"
		case 443, 8443:
			return "https"
		default:
			return fmt.Sprintf("unknown-%d", port)
		}
	}
}

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
			// 发送所有结果，包括closed和filtered
			ps.results <- result
		}
	}
}

func (ps *PortScanner) Stop() {
	ps.cancel()
}

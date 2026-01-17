package scanner

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
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
}

func NewPortScanner(timeoutSec int, threads int) *PortScanner {
	ctx, cancel := context.WithCancel(context.Background())
	return &PortScanner{
		timeout: time.Duration(timeoutSec) * time.Second,
		threads: threads,
		results: make(chan model.PortResult, 1000),
		logger:  utils.NewLogger("scanner"),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// ParsePortRange 解析端口范围
func (ps *PortScanner) ParsePortRange(portRange string) ([]int, error) {
	// 如果端口范围为空，返回常见端口列表
	if portRange == "" {
		ps.logger.Info("未指定端口范围，将扫描 %d 个常见端口", len(model.CommonPorts))
		ports := model.CommonPortsList()
		sort.Ints(ports) // 按端口号排序
		return ports, nil
	}

	// 如果用户指定了 "all"，扫描所有端口
	if strings.ToLower(portRange) == "all" {
		ps.logger.Info("扫描所有端口 (1-65535)")
		var allPorts []int
		for port := 1; port <= 65535; port++ {
			allPorts = append(allPorts, port)
		}
		return allPorts, nil
	}

	// 如果用户指定了 "common" 或 "default"，扫描常见端口
	if strings.ToLower(portRange) == "common" || strings.ToLower(portRange) == "default" {
		ps.logger.Info("扫描常见端口")
		ports := model.CommonPortsList()
		sort.Ints(ports)
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
			// 处理端口范围
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
	return removeDuplicatesAndSort(ports), nil
}

// 去重并排序函数
func removeDuplicatesAndSort(ports []int) []int {
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
	sort.Ints(uniquePorts)
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

	// 尝试连接
	conn, err := net.DialTimeout(protocol, address, ps.timeout)
	if err != nil {
		// 根据错误类型判断端口状态
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			result.State = "filtered"
		} else if strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), "connection refused") {
			result.State = "closed"
		} else if strings.Contains(err.Error(), "network is unreachable") {
			result.State = "unreachable"
		} else if strings.Contains(err.Error(), "no route to host") {
			result.State = "unreachable"
		} else {
			// 其他错误也标记为关闭
			result.State = "closed"
		}
		return result
	}
	defer conn.Close()

	// 端口开放
	result.State = "open"

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
	}

	return result
}

// 从banner中提取版本信息
func (ps *PortScanner) extractVersionFromBanner(banner, serviceName string) string {
	_ = strings.ToLower(banner)
	serviceLower := strings.ToLower(serviceName)

	// 查找版本号模式
	versionPatterns := []string{
		"\\d+\\.\\d+(\\.\\d+)*",             // 1.2.3 或 1.2
		"v\\d+\\.\\d+",                      // v1.2
		"version[\\s:]+\\d+",                // version 1 或 version:1
		serviceLower + "[\\s/]+\\d+\\.\\d+", // nginx/1.18
	}

	for _, pattern := range versionPatterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(banner)
		if len(matches) > 0 {
			return matches[0]
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
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// 根据不同端口使用不同的banner获取策略
	buffer := make([]byte, 1024)
	var banner string

	switch port {
	case 22: // SSH
		// 发送SSH客户端标识
		fmt.Fprintf(conn, "SSH-2.0-Client\r\n")
		time.Sleep(100 * time.Millisecond)

	case 25, 465, 587: // SMTP
		// 发送EHLO命令
		fmt.Fprintf(conn, "EHLO example.com\r\n")
		time.Sleep(100 * time.Millisecond)

	case 80, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8888, 8889, 9000, 9001: // HTTP
		// 发送HTTP请求
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: QianKunQuan-Scanner/1.0\r\n\r\n", "localhost")

	case 443, 8443: // HTTPS
		// 尝试TLS握手
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", "localhost")

	case 3306: // MySQL
		// MySQL握手协议
		time.Sleep(100 * time.Millisecond)

	case 5432, 5433, 5434: // PostgreSQL
		// PostgreSQL协议
		time.Sleep(100 * time.Millisecond)

	case 6379: // Redis
		// 发送PING命令
		fmt.Fprintf(conn, "PING\r\n")
		time.Sleep(100 * time.Millisecond)

	default:
		// 对于其他端口，等待响应但不发送特定命令
		time.Sleep(200 * time.Millisecond)
	}

	// 尝试读取banner
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		banner = string(buffer[:n])
		banner = strings.TrimSpace(banner)

		// 限制banner长度
		if len(banner) > 200 {
			banner = banner[:200] + "..."
		}
	}

	return banner
}

func (ps *PortScanner) detectService(port int, banner string) string {
	// 首先检查CommonPorts中的已知服务
	if serviceInfo, exists := model.CommonPorts[port]; exists {
		return serviceInfo.Name
	}

	// 根据banner内容识别服务
	bannerLower := strings.ToLower(banner)

	// 扩展服务识别模式
	servicePatterns := map[string][]string{
		"HTTP":          {"http/", "server:", "apache", "nginx", "iis", "tomcat", "jetty"},
		"SSH":           {"ssh-", "openssh"},
		"FTP":           {"220", "ftp", "filezilla"},
		"SMTP":          {"220", "smtp", "esmtp", "postfix", "exim", "sendmail"},
		"DNS":           {"domain", "bind"},
		"RDP":           {"rdp", "remote desktop"},
		"MySQL":         {"mysql", "mariadb"},
		"PostgreSQL":    {"postgresql", "postgres"},
		"Redis":         {"redis", "redis server"},
		"MongoDB":       {"mongodb"},
		"Elasticsearch": {"elasticsearch"},
		"Memcached":     {"memcached"},
		"CouchDB":       {"couchdb"},
		"Oracle":        {"oracle"},
		"MSSQL":         {"sql server", "microsoft sql"},
	}

	for service, patterns := range servicePatterns {
		for _, pattern := range patterns {
			if strings.Contains(bannerLower, pattern) {
				return service
			}
		}
	}

	// 如果无法识别，返回端口号
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
			}

			break
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

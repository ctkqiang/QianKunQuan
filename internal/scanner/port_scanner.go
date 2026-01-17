package scanner

import (
	"context"
	"fmt"
	"net"
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
}

func NewPortScanner(timeoutSec int, threads int) *PortScanner {
	return &PortScanner{
		timeout: time.Duration(timeoutSec) * time.Second,
		threads: threads,
		results: make(chan model.PortResult, 1000),
		logger:  utils.NewLogger("scanner"),
	}
}

// ParsePortRange 解析端口范围
func (ps *PortScanner) ParsePortRange(portRange string) ([]int, error) {
	var ports []int

	if portRange == "" {
		// 扫描常见端口
		for port := range model.CommonPorts {
			ports = append(ports, port)
		}
		return ports, nil
	}

	// 处理端口范围
	parts := strings.Split(portRange, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("无效的端口范围: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, err
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, err
			}

			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("端口范围无效: %d-%d", start, end)
			}

			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
		} else {
			port, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return nil, err
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("端口号无效: %d", port)
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}

// ScanPort 扫描单个端口
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
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(100 * time.Millisecond)
			return ps.ScanPort(target, port, protocol)
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
		} else {
			result.Service = model.ServiceInfo{
				Name:  serviceName,
				Extra: "未知服务",
			}
		}
	}

	return result
}

// grabBanner 获取端口banner信息
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

	// 对于HTTP/HTTPS服务，发送HTTP请求头
	if port == 80 || port == 8080 || port == 443 || port == 8443 {
		fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
	}

	// 尝试读取banner
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	banner := string(buffer[:n])
	banner = strings.TrimSpace(banner)

	// 限制banner长度
	if len(banner) > 200 {
		banner = banner[:200] + "..."
	}

	return banner
}

// detectService 根据端口和banner识别服务
func (ps *PortScanner) detectService(port int, banner string) string {
	// 首先检查CommonPorts中的已知服务
	if serviceInfo, exists := model.CommonPorts[port]; exists {
		return serviceInfo.Name
	}

	// 根据banner内容识别服务
	bannerLower := strings.ToLower(banner)

	switch {
	case strings.Contains(bannerLower, "http") || strings.Contains(bannerLower, "html"):
		return "HTTP"
	case strings.Contains(bannerLower, "ssh"):
		return "SSH"
	case strings.Contains(bannerLower, "ftp"):
		return "FTP"
	case strings.Contains(bannerLower, "smtp"):
		return "SMTP"
	case strings.Contains(bannerLower, "mysql"):
		return "MySQL"
	case strings.Contains(bannerLower, "postgresql"):
		return "PostgreSQL"
	case strings.Contains(bannerLower, "redis"):
		return "Redis"
	case strings.Contains(bannerLower, "mongodb"):
		return "MongoDB"
	case strings.Contains(bannerLower, "microsoft") || strings.Contains(bannerLower, "mssql"):
		return "MSSQL"
	case strings.Contains(bannerLower, "oracle"):
		return "Oracle"
	default:
		return fmt.Sprintf("unknown-%d", port)
	}
}

// ConcurrentScan 并发扫描
func (ps *PortScanner) ConcurrentScan(target string, ports []int) <-chan model.PortResult {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建工作池
	portChan := make(chan int, len(ports))

	// 启动worker
	for i := 0; i < ps.threads; i++ {
		ps.wg.Add(1)
		go ps.worker(ctx, target, portChan)
	}

	// 发送端口到channel
	go func() {
		for _, port := range ports {
			portChan <- port
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

package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"QianKunQuan/internal/cvedb"
	"QianKunQuan/internal/model"
	"QianKunQuan/internal/scanner"
	"QianKunQuan/internal/utils"
	"QianKunQuan/pkg/cli"
)

func main() {
	// 解析命令行参数
	parser := cli.NewParser()
	if err := parser.Parse(); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n\n", err)
		fmt.Fprintf(os.Stderr, "使用方法: %s -target <目标地址> [选项]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "使用 -help 查看完整帮助信息\n")
		os.Exit(1)
	}

	options := parser.Options
	logger := utils.NewLogger("main")

	logger.Info("启动乾坤圈扫描器 v1.0")

	// 处理目标地址
	target := extractHostname(options.Target)

	// 解析主机名获取IP
	var ips []string
	addrs, err := net.LookupHost(target)
	if err == nil && len(addrs) > 0 {
		ips = addrs
	}

	if options.Verbose {
		logger.Info("扫描目标: %s", target)
		if len(ips) > 0 {
			logger.Info("解析IP: %s", strings.Join(ips, ", "))
		}
	}

	if options.PortRange == "" {
		if options.Verbose {
			logger.Info("端口范围: 默认常见端口")
		}
	} else {
		if options.Verbose {
			logger.Info("端口范围: %s", options.PortRange)
		}
	}

	if options.Verbose {
		logger.Info("超时时间: %d秒, 线程数: %d",
			options.Timeout, options.Threads)
	}

	// 初始化CVE数据库
	cveDB, err := cvedb.NewCVEDatabase("database/cve_data.db")
	if err != nil {
		logger.Error("初始化CVE数据库失败: %v", err)
		os.Exit(1)
	}
	defer cveDB.Close()

	// 更新CVE数据库
	if options.UpdateDB {
		logger.Info("正在更新CVE数据库...")
		if err := updateCVEDatabase(); err != nil {
			logger.Error("更新CVE数据库失败: %v", err)
		} else {
			logger.Info("CVE数据库更新完成")
		}
	}

	// 如果没有数据，初始化测试数据
	if options.UpdateDB {
		logger.Info("初始化测试CVE数据...")

	}

	// 创建端口扫描器
	portScanner := scanner.NewPortScanner(options.Timeout, options.Threads, options.Verbose)

	// 解析端口范围
	ports, err := portScanner.ParsePortRange(options.PortRange)
	if err != nil {
		logger.Error("解析端口范围失败: %v", err)
		os.Exit(1)
	}

	if options.Verbose {
		logger.Info("开始扫描 %d 个端口...", len(ports))
	}

	// 执行扫描
	startTime := time.Now()
	resultsChan := portScanner.ConcurrentScan(target, ports)

	// 收集所有端口结果
	var allResults []model.PortResult
	var openPorts, filteredPorts, closedPorts int

	for result := range resultsChan {
		allResults = append(allResults, result)

		switch result.State {
		case "open":
			openPorts++
			if options.Verbose {
				serviceName := result.Service.Name
				if serviceName == "" {
					serviceName = "未知"
				}
				logger.Info("✅ 发现开放端口: %d (%s)", result.Port, serviceName)
			}
		case "filtered":
			filteredPorts++
			if options.Verbose {
				logger.Info("🚧 发现过滤端口: %d (可能被防火墙阻止)", result.Port)
			}
		case "closed":
			closedPorts++
		}
	}

	if options.Verbose {
		logger.Info("扫描完成，发现 %d 个开放端口, %d 个过滤端口, %d 个关闭端口",
			openPorts, filteredPorts, closedPorts)
	}

	// 查询CVE信息（只对开放端口）
	var scanResults []model.PortResult
	for i := range allResults {
		// 我们只关心开放和过滤的端口，关闭端口太多，通常不显示
		if allResults[i].State == "open" || allResults[i].State == "filtered" {
			// 设置默认风险等级
			allResults[i].RiskLevel = "低"

			// 只对开放端口查询CVE
			if allResults[i].State == "open" {
				cves, err := cveDB.LookupCVEs(allResults[i].Service)
				if err == nil && len(cves) > 0 {
					allResults[i].CVEs = cves
					allResults[i].RiskLevel = calculateRiskLevel(cves)

					if options.Verbose && len(cves) > 0 {
						logger.Info("端口 %d 发现 %d 个CVE漏洞，风险等级: %s",
							allResults[i].Port, len(cves), allResults[i].RiskLevel)
					}
				} else if err != nil {
					if options.Verbose {
						logger.Error("查询端口 %d 的CVE失败: %v",
							allResults[i].Port, err)
					}
				}
			}

			scanResults = append(scanResults, allResults[i])
		}
	}

	// 按端口号排序
	sort.Slice(scanResults, func(i, j int) bool {
		return scanResults[i].Port < scanResults[j].Port
	})

	// 准备最终结果
	hostStatus := "在线"
	if len(ips) > 0 {
		hostStatus = "在线 (" + ips[0] + ")"
	}

	finalResult := model.ScanResult{
		Target:         target,
		OriginalTarget: options.Target,
		HostStatus:     hostStatus,
		ScanTime:       time.Since(startTime).String(),
		Ports:          scanResults,
	}

	// 输出结果
	formatter := cli.NewOutputFormatter(options.OutputFormat)
	if err := formatter.PrintResult(finalResult, options.OutputFile); err != nil {
		logger.Error("输出结果失败: %v", err)
		os.Exit(1)
	}

	if options.Verbose {
		logger.Info("扫描完成，总耗时: %v", time.Since(startTime))
	}
}

// 从目标字符串中提取主机名
func extractHostname(target string) string {
	// 如果包含://，则尝试解析为URL
	if strings.Contains(target, "://") {
		parsedURL, err := url.Parse(target)
		if err == nil && parsedURL.Host != "" {
			// 移除端口号（如果有）
			hostname := parsedURL.Hostname()
			if hostname != "" {
				return hostname
			}
		}
	}

	// 否则，假设它是主机名或IP地址
	// 移除可能的路径部分
	if idx := strings.Index(target, "/"); idx != -1 {
		return target[:idx]
	}

	return target
}

func updateCVEDatabase() error {
	// 这里实现从官方源下载CVE数据的逻辑
	// 可以使用NVD的JSON feed: https://nvd.nist.gov/vuln/data-feeds
	return nil
}

func calculateRiskLevel(cves []model.CVEDetail) string {
	if len(cves) == 0 {
		return "低"
	}

	maxScore := 0.0
	for _, cve := range cves {
		if cve.Score > maxScore {
			maxScore = cve.Score
		}
	}

	switch {
	case maxScore >= 9.0:
		return "严重"
	case maxScore >= 7.0:
		return "高"
	case maxScore >= 4.0:
		return "中"
	default:
		return "低"
	}
}

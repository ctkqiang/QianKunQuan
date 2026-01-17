package main

import (
	"fmt"
	"os"
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
	logger.Info("目标: %s", options.Target)

	// 更新CVE数据库
	if options.UpdateDB {
		logger.Info("正在更新CVE数据库...")
		if err := updateCVEDatabase(); err != nil {
			logger.Error("更新CVE数据库失败: %v", err)
		} else {
			logger.Info("CVE数据库更新完成")
		}
	}

	// 初始化CVE数据库
	cveDB, err := cvedb.NewCVEDatabase("database/cve_data.db")
	if err != nil {
		logger.Error("初始化CVE数据库失败: %v", err)
		os.Exit(1)
	}
	defer cveDB.Close()

	// 创建端口扫描器
	portScanner := scanner.NewPortScanner(options.Timeout, options.Threads)

	// 解析端口范围
	ports, err := portScanner.ParsePortRange(options.PortRange)
	if err != nil {
		logger.Error("解析端口范围失败: %v", err)
		os.Exit(1)
	}

	logger.Info("开始扫描 %d 个端口...", len(ports))

	// 执行扫描
	startTime := time.Now()
	resultsChan := portScanner.ConcurrentScan(options.Target, ports)

	// 收集结果
	var scanResults []model.PortResult
	for result := range resultsChan {
		scanResults = append(scanResults, result)
		if options.Verbose {
			logger.Info("发现开放端口: %d (%s)", result.Port, result.Service.Name)
		}
	}

	// 查询CVE信息
	logger.Info("查询CVE漏洞信息...")
	for i := range scanResults {
		if scanResults[i].State == "open" {
			cves, err := cveDB.LookupCVEs(scanResults[i].Service)
			if err == nil && len(cves) > 0 {
				scanResults[i].CVEs = cves
				scanResults[i].RiskLevel = calculateRiskLevel(cves)
			}
		}
	}

	// 准备最终结果
	finalResult := model.ScanResult{
		Target:     options.Target,
		HostStatus: "在线",
		ScanTime:   time.Since(startTime).String(),
		Ports:      scanResults,
	}

	// 输出结果
	formatter := cli.NewOutputFormatter(options.OutputFormat)
	if err := formatter.PrintResult(finalResult, options.OutputFile); err != nil {
		logger.Error("输出结果失败: %v", err)
		os.Exit(1)
	}

	logger.Info("扫描完成，耗时: %v", time.Since(startTime))
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

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"QianKunQuan/internal/attackpath"
	"QianKunQuan/internal/cvedb"
	"QianKunQuan/internal/exploit"
	"QianKunQuan/internal/model"
	"QianKunQuan/internal/report"
	"QianKunQuan/internal/scanner"
	"QianKunQuan/internal/utils"
	"QianKunQuan/pkg/cli"
)

var Version = "2.0.0-redteam"

func main() {
	parser := cli.NewParser()

	parser.Register("scan", "端口扫描与服务识别", handleScan)
	parser.Register("web", "Web应用侦察", handleWeb)
	parser.Register("subdomain", "子域名枚举", handleSubdomain)
	parser.Register("full", "全量侦察", handleFull)
	parser.Register("vuln", "漏洞利用索引", handleVuln)
	parser.Register("attack", "攻击路径推荐", handleAttack)
	parser.Register("report", "红队报告生成", handleReport)
	parser.Register("update", "更新漏洞数据库", handleUpdate)

	if err := parser.Parse(); err != nil {
		os.Exit(1)
	}
}

func handleScan(args []string) error {
	parser := cli.NewParser()
	opt, err := parser.ParseScanArgs(args)
	if err != nil {
		return err
	}

	logger := utils.NewLogger("scan")
	logger.Info("启动端口扫描: %s", opt.Target)

	if opt.UpdateDB {
		logger.Info("更新CVE数据库...")
		if err := updateCVEDatabase(); err != nil {
			logger.Warn("更新CVE数据库失败: %v", err)
		}
	}

	target := extractHostname(opt.Target)
	var ips []string
	addrs, err := net.LookupHost(target)
	if err == nil && len(addrs) > 0 {
		ips = addrs
	}

	if opt.Verbose {
		logger.Info("扫描目标: %s", target)
		if len(ips) > 0 {
			logger.Info("解析IP: %s", strings.Join(ips, ", "))
		}
		logger.Info("端口范围: %s, 超时: %ds, 线程: %d", opt.PortRange, opt.Timeout, opt.Threads)
	}

	ports, err := parsePorts(opt.PortRange, opt.Threads, opt.Verbose)
	if err != nil {
		logger.Error("解析端口范围失败: %v", err)
		return err
	}

	if opt.Verbose {
		logger.Info("开始扫描 %d 个端口...", len(ports))
	}

	cveDB, err := cvedb.NewCVEDatabase("database/cve_data.db")
	if err != nil {
		logger.Warn("初始化CVE数据库失败: %v (继续扫描，跳过CVE检测)", err)
	}
	if cveDB != nil {
		defer cveDB.Close()
	}

	portScanner := scanner.NewPortScanner(opt.Timeout, opt.Threads, opt.Verbose)

	startTime := time.Now()
	resultsChan := portScanner.ConcurrentScan(target, ports)

	var allResults []model.PortResult
	var openPorts, filteredPorts, closedPorts int

	for result := range resultsChan {
		allResults = append(allResults, result)

		switch result.State {
		case "open":
			openPorts++
			if opt.Verbose {
				serviceName := result.Service.Name
				if serviceName == "" {
					serviceName = "未知"
				}
				logger.Info("[+] 发现开放端口: %d (%s)", result.Port, serviceName)
			}
		case "filtered":
			filteredPorts++
			if opt.Verbose {
				logger.Info("[!] 发现过滤端口: %d (可能被防火墙阻止)", result.Port)
			}
		case "closed":
			closedPorts++
		}
	}

	if opt.Verbose {
		logger.Info("扫描完成，发现 %d 个开放端口, %d 个过滤端口, %d 个关闭端口",
			openPorts, filteredPorts, closedPorts)
	}

	var scanResults []model.PortResult
	for i := range allResults {
		if allResults[i].State == "open" || allResults[i].State == "filtered" {
			allResults[i].RiskLevel = "低"

			if allResults[i].State == "open" && cveDB != nil {
				cves, err := cveDB.LookupCVEs(allResults[i].Service)
				if err == nil && len(cves) > 0 {
					allResults[i].CVEs = cves
					allResults[i].RiskLevel = calculateRiskLevel(cves)

					if opt.Verbose {
						logger.Info("端口 %d 发现 %d 个CVE漏洞，风险等级: %s",
							allResults[i].Port, len(cves), allResults[i].RiskLevel)
					}
				}
			}

			scanResults = append(scanResults, allResults[i])
		}
	}

	sort.Slice(scanResults, func(i, j int) bool {
		return scanResults[i].Port < scanResults[j].Port
	})

	hostStatus := "在线"
	if len(ips) > 0 {
		hostStatus = "在线 (" + ips[0] + ")"
	}

	finalResult := model.ScanResult{
		Target:         target,
		OriginalTarget: opt.Target,
		HostStatus:     hostStatus,
		ScanTime:       time.Since(startTime).String(),
		Ports:          scanResults,
	}

	formatter := cli.NewOutputFormatter(opt.OutputFormat, Version)
	if err := formatter.PrintResult(finalResult, opt.OutputFile); err != nil {
		logger.Error("输出结果失败: %v", err)
		return err
	}

	if opt.OutputFile != "" {
		logger.Info("结果已保存到: %s", opt.OutputFile)
	}

	return nil
}

func handleWeb(args []string) error {
	parser := cli.NewParser()
	opt, err := parser.ParseWebArgs(args)
	if err != nil {
		return err
	}

	logger := utils.NewLogger("web")
	logger.Info("启动Web侦察: %s", opt.URL)

	webScanner := scanner.NewWebScanner(opt.URL, opt.Threads, opt.Timeout, opt.Verbose,
		opt.Proxy, opt.UserAgent, opt.Cookie)

	result := webScanner.Scan()

	if opt.OutputFormat == "json" {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		if opt.OutputFile != "" {
			os.WriteFile(opt.OutputFile, jsonData, 0644)
			logger.Info("结果已保存到: %s", opt.OutputFile)
		} else {
			fmt.Println(string(jsonData))
		}
	} else {
		output := webScanner.PrintResult(result)
		if opt.OutputFile != "" {
			os.WriteFile(opt.OutputFile, []byte(output), 0644)
			logger.Info("结果已保存到: %s", opt.OutputFile)
		} else {
			fmt.Print(output)
		}
	}

	return nil
}

func handleSubdomain(args []string) error {
	parser := cli.NewParser()
	opt, err := parser.ParseSubdomainArgs(args)
	if err != nil {
		return err
	}

	logger := utils.NewLogger("subdomain")
	logger.Info("启动子域名枚举: %s", opt.Domain)

	var customWordlist []string
	if opt.Wordlist != "" {
		data, err := os.ReadFile(opt.Wordlist)
		if err != nil {
			logger.Error("读取字典文件失败: %v", err)
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				customWordlist = append(customWordlist, line)
			}
		}
	}

	subScanner := scanner.NewSubdomainScanner(opt.Domain, opt.Threads, opt.DNSEnum, opt.HTTPCheck, opt.Verbose)
	results := subScanner.Scan(customWordlist)

	if opt.OutputFormat == "json" {
		jsonData, _ := json.MarshalIndent(results, "", "  ")
		if opt.OutputFile != "" {
			os.WriteFile(opt.OutputFile, jsonData, 0644)
			logger.Info("结果已保存到: %s", opt.OutputFile)
		} else {
			fmt.Println(string(jsonData))
		}
	} else {
		output := subScanner.PrintResult(results)
		if opt.OutputFile != "" {
			os.WriteFile(opt.OutputFile, []byte(output), 0644)
			logger.Info("结果已保存到: %s", opt.OutputFile)
		} else {
			fmt.Print(output)
		}
	}

	return nil
}

func handleFull(args []string) error {
	parser := cli.NewParser()
	opt, err := parser.ParseFullArgs(args)
	if err != nil {
		return err
	}

	logger := utils.NewLogger("full")
	logger.Info("[启动] 全量红队侦察: %s", opt.Target)

	var portScanResult *model.ScanResult
	var webScanResult *model.WebScanResult
	var attackPaths []model.AttackPath

	target := extractHostname(opt.Target)

	if opt.Subdomain && isDomain(target) {
		logger.Info("\n=== 阶段1: 子域名枚举 ===")
		subScanner := scanner.NewSubdomainScanner(target, opt.Threads, true, true, opt.Verbose)
		subResults := subScanner.Scan(nil)
		logger.Info("发现 %d 个子域名", len(subResults))

		if len(subResults) > 0 {
			logger.Info("对发现的子域名进行端口扫描...")
		}
	}

	if opt.PortScan {
		logger.Info("\n=== 阶段2: 端口扫描 ===")
		ports, err := parsePorts(opt.PortRange, opt.Threads, opt.Verbose)
		if err != nil {
			logger.Error("解析端口范围失败: %v", err)
		} else {
			cveDB, _ := cvedb.NewCVEDatabase("database/cve_data.db")
			if cveDB != nil {
				defer cveDB.Close()
			}

			portScanner := scanner.NewPortScanner(3, opt.Threads, opt.Verbose)
			startTime := time.Now()
			resultsChan := portScanner.ConcurrentScan(target, ports)

			var scanResults []model.PortResult
			for result := range resultsChan {
				if result.State == "open" || result.State == "filtered" {
					result.RiskLevel = "低"
					if result.State == "open" && cveDB != nil {
						cves, err := cveDB.LookupCVEs(result.Service)
						if err == nil && len(cves) > 0 {
							result.CVEs = cves
							result.RiskLevel = calculateRiskLevel(cves)
						}
					}
					scanResults = append(scanResults, result)
				}
			}

			sort.Slice(scanResults, func(i, j int) bool {
				return scanResults[i].Port < scanResults[j].Port
			})

			portScanResult = &model.ScanResult{
				Target:     target,
				HostStatus: "在线",
				ScanTime:   time.Since(startTime).String(),
				Ports:      scanResults,
			}
			logger.Info("端口扫描完成，发现 %d 个开放/过滤端口", len(scanResults))
		}
	}

	if opt.WebScan {
		logger.Info("\n=== 阶段3: Web应用侦察 ===")
		webURL := "http://" + target
		for _, p := range []int{80, 443, 8080, 8443} {
			if portScanResult != nil {
				found := false
				for _, pr := range portScanResult.Ports {
					if pr.Port == p && pr.State == "open" {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
			if p == 443 || p == 8443 {
				webURL = "https://" + target
			}
			break
		}

		webScanner := scanner.NewWebScanner(webURL, 50, 5, opt.Verbose, "", "", "")
		webScanResult = webScanner.Scan()
		logger.Info("Web侦察完成")
	}

	if opt.AttackPath {
		logger.Info("\n=== 阶段4: 攻击路径分析 ===")
		gen := attackpath.NewAttackPathGenerator()
		if portScanResult != nil {
			attackPaths = append(attackPaths, gen.GenerateFromPortScan(portScanResult)...)
		}
		if webScanResult != nil {
			attackPaths = append(attackPaths, gen.GenerateFromWebScan(webScanResult)...)
		}
		logger.Info("生成 %d 条攻击路径建议", len(attackPaths))
	}

	if opt.VulnIndex && portScanResult != nil {
		logger.Info("\n=== 阶段5: 漏洞利用索引 ===")
		vi := exploit.NewVulnIndex()
		exploits := vi.QueryByPortResults(portScanResult.Ports)
		if len(exploits) > 0 {
			output := vi.FormatExploitList(exploits, true, true)
			fmt.Print(output)
		}
	}

	logger.Info("\n=== 生成报告 ===")
	reportGen := report.NewReportGenerator("红队评估报告", "", "乾坤圈红队")
	redTeamReport := reportGen.BuildReport(target, portScanResult, webScanResult, attackPaths)

	outputFile := opt.OutputFile
	if outputFile == "" {
		outputFile = "redteam_report_" + strings.ReplaceAll(target, ".", "_") + ".html"
	}

	if err := reportGen.SaveReport(redTeamReport, outputFile, opt.OutputFormat); err != nil {
		logger.Error("保存报告失败: %v", err)
		return err
	}

	logger.Info("[完成] 报告已生成: %s", outputFile)
	logger.Info("总体风险等级: %s", redTeamReport.OverallRisk)
	logger.Info("开放端口: %d | 漏洞: %d | 攻击路径: %d",
		redTeamReport.Summary.OpenPorts, redTeamReport.Summary.VulnCount, redTeamReport.Summary.AttackPaths)

	return nil
}

func handleVuln(args []string) error {
	parser := cli.NewParser()
	opt, err := parser.ParseVulnArgs(args)
	if err != nil {
		return err
	}

	logger := utils.NewLogger("vuln")
	vi := exploit.NewVulnIndex()

	var exploits []model.ExploitRef

	if opt.Service != "" {
		logger.Info("按服务查询: %s", opt.Service)
		exploits = vi.QueryByService(opt.Service)
	} else if opt.CVE != "" {
		logger.Info("按CVE查询: %s", opt.CVE)
		exploits = vi.QueryByCVE(opt.CVE)
	} else if opt.CNVD != "" {
		logger.Info("按CNVD查询: %s", opt.CNVD)
		exploits = vi.QueryByCNVD(opt.CNVD)
	} else if opt.CMS != "" {
		logger.Info("按CMS查询: %s", opt.CMS)
		exploits = vi.QueryByCMS(opt.CMS)
	}

	output := vi.FormatExploitList(exploits, opt.ShowPOC, opt.ShowEXP)

	if opt.OutputFile != "" {
		os.WriteFile(opt.OutputFile, []byte(output), 0644)
		logger.Info("结果已保存到: %s", opt.OutputFile)
	} else {
		fmt.Print(output)
	}

	return nil
}

func handleAttack(args []string) error {
	parser := cli.NewParser()
	opt, err := parser.ParseAttackArgs(args)
	if err != nil {
		return err
	}

	logger := utils.NewLogger("attack")
	gen := attackpath.NewAttackPathGenerator()

	var attackPaths []model.AttackPath

	if opt.InputFile != "" {
		logger.Info("从文件加载扫描结果: %s", opt.InputFile)
		data, err := os.ReadFile(opt.InputFile)
		if err != nil {
			logger.Error("读取文件失败: %v", err)
			return err
		}

		var scanResult model.ScanResult
		if err := json.Unmarshal(data, &scanResult); err == nil {
			attackPaths = gen.GenerateFromPortScan(&scanResult)
		} else {
			logger.Error("解析扫描结果失败: %v", err)
			return err
		}
	} else {
		logger.Info("对目标进行快速扫描: %s", opt.Target)
		target := extractHostname(opt.Target)

		portScanner := scanner.NewPortScanner(3, 200, opt.Verbose)
		ports, _ := parsePorts("top100", 200, opt.Verbose)
		resultsChan := portScanner.ConcurrentScan(target, ports)

		var scanResults []model.PortResult
		for result := range resultsChan {
			if result.State == "open" || result.State == "filtered" {
				scanResults = append(scanResults, result)
			}
		}

		scanResult := model.ScanResult{
			Target:     target,
			HostStatus: "在线",
			Ports:      scanResults,
		}
		attackPaths = gen.GenerateFromPortScan(&scanResult)
	}

	if opt.Phase != "all" {
		var filtered []model.AttackPath
		phaseMap := map[string]string{
			"recon":   "侦察",
			"initial": "初始访问",
			"lateral": "横向移动",
			"exec":    "执行",
			"privesc": "权限提升",
		}
		targetPhase, ok := phaseMap[opt.Phase]
		if ok {
			for _, ap := range attackPaths {
				if ap.Phase == targetPhase {
					filtered = append(filtered, ap)
				}
			}
			attackPaths = filtered
		}
	}

	output := gen.FormatAttackPaths(attackPaths)

	if opt.OutputFile != "" {
		os.WriteFile(opt.OutputFile, []byte(output), 0644)
		logger.Info("结果已保存到: %s", opt.OutputFile)
	} else {
		fmt.Print(output)
	}

	return nil
}

func handleReport(args []string) error {
	parser := cli.NewParser()
	opt, err := parser.ParseReportArgs(args)
	if err != nil {
		return err
	}

	logger := utils.NewLogger("report")

	var portScanResult *model.ScanResult
	var webScanResult *model.WebScanResult
	var attackPaths []model.AttackPath

	if opt.InputFile != "" {
		logger.Info("从文件加载扫描结果: %s", opt.InputFile)
		data, err := os.ReadFile(opt.InputFile)
		if err != nil {
			logger.Error("读取文件失败: %v", err)
			return err
		}

		var scanResult model.ScanResult
		if err := json.Unmarshal(data, &scanResult); err == nil {
			portScanResult = &scanResult
		}
	} else if opt.FullScan {
		logger.Info("执行全量扫描: %s", opt.Target)
		target := extractHostname(opt.Target)

		portScanner := scanner.NewPortScanner(3, 300, opt.Verbose)
		ports, _ := parsePorts("top1000", 300, opt.Verbose)
		resultsChan := portScanner.ConcurrentScan(target, ports)

		var scanResults []model.PortResult
		for result := range resultsChan {
			if result.State == "open" || result.State == "filtered" {
				scanResults = append(scanResults, result)
			}
		}

		portScanResult = &model.ScanResult{
			Target:     target,
			HostStatus: "在线",
			Ports:      scanResults,
		}

		webScanner := scanner.NewWebScanner("http://"+target, 50, 5, opt.Verbose, "", "", "")
		webScanResult = webScanner.Scan()

		gen := attackpath.NewAttackPathGenerator()
		attackPaths = gen.GenerateFromPortScan(portScanResult)
		if webScanResult != nil {
			attackPaths = append(attackPaths, gen.GenerateFromWebScan(webScanResult)...)
		}
	} else {
		logger.Error("请指定输入文件 (-i) 或使用 --full 执行全量扫描")
		return fmt.Errorf("缺少扫描数据")
	}

	reportGen := report.NewReportGenerator(opt.Title, opt.Company, opt.Assessor)
	redTeamReport := reportGen.BuildReport(opt.Target, portScanResult, webScanResult, attackPaths)

	if err := reportGen.SaveReport(redTeamReport, opt.OutputFile, opt.OutputFormat); err != nil {
		logger.Error("保存报告失败: %v", err)
		return err
	}

	logger.Info("[完成] 报告已生成: %s", opt.OutputFile)
	logger.Info("总体风险等级: %s", redTeamReport.OverallRisk)

	return nil
}

func handleUpdate(args []string) error {
	parser := cli.NewParser()
	opt, err := parser.ParseUpdateArgs(args)
	if err != nil {
		return err
	}

	logger := utils.NewLogger("update")
	logger.Info("开始更新漏洞数据库...")

	if err := updateCVEDatabase(); err != nil {
		logger.Error("更新CVE数据库失败: %v", err)
	} else {
		logger.Info("CVE数据库更新完成")
	}

	if opt.CMS {
		logger.Info("CMS指纹库已是最新（内置）")
	}
	if opt.Exploit {
		logger.Info("漏洞利用索引已是最新（内置）")
	}

	logger.Info("[完成] 所有数据库更新完成")
	return nil
}

func extractHostname(target string) string {
	if strings.Contains(target, "://") {
		parsedURL, err := url.Parse(target)
		if err == nil && parsedURL.Host != "" {
			hostname := parsedURL.Hostname()
			if hostname != "" {
				return hostname
			}
		}
	}

	if idx := strings.Index(target, "/"); idx != -1 {
		return target[:idx]
	}

	return target
}

func isDomain(target string) bool {
	if net.ParseIP(target) != nil {
		return false
	}
	return strings.Contains(target, ".")
}

func parsePorts(portRange string, threads int, verbose bool) ([]int, error) {
	portScanner := scanner.NewPortScanner(3, threads, verbose)
	return portScanner.ParsePortRange(portRange)
}

func updateCVEDatabase() error {
	logger := utils.NewLogger("cve-updater")

	cveDB, err := cvedb.NewCVEDatabase("database/cve_data.db")
	if err != nil {
		return err
	}
	defer cveDB.Close()

	logger.Info("使用NVD API获取CVE数据...")
	apiClient := cvedb.NewCVEAPIClient()

	cves, err := apiClient.FetchCVEsByYearRange(2025, 2026)
	if err != nil {
		logger.Error("API获取CVE数据失败: %v", err)
		logger.Info("尝试使用批量更新器作为备选方案...")

		bulkUpdater := cvedb.NewBulkCVEUpdater()
		if err := bulkUpdater.UpdateFrom2025ToCurrent(cveDB); err != nil {
			return fmt.Errorf("所有CVE数据更新方法都失败")
		}

		logger.Info("批量更新器成功更新CVE数据")
		return nil
	}

	logger.Info("成功获取 %d 个CVE，正在保存到数据库...", len(cves))
	successCount, err := apiClient.SaveCVEsToDatabase(cveDB, cves)
	if err != nil {
		logger.Warn("部分CVE保存失败: %v", err)
	}

	logger.Info("CVE数据更新完成: %d 个CVE成功保存", successCount)

	logger.Info("补充获取历史CVE数据...")
	bulkUpdater := cvedb.NewBulkCVEUpdater()
	if err := bulkUpdater.UpdateFrom2025ToCurrent(cveDB); err != nil {
		logger.Warn("补充历史数据失败: %v", err)
	}

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

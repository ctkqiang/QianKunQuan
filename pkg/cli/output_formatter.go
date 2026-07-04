package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"QianKunQuan/internal/model"
)

type OutputFormatter struct {
	format  string
	version string
}

func NewOutputFormatter(format, version string) *OutputFormatter {
	return &OutputFormatter{format: format, version: version}
}

func (of *OutputFormatter) PrintResult(result model.ScanResult, outputFile string) error {
	var output string

	switch strings.ToLower(of.format) {
	case "json":
		output = of.formatJSON(result)
	case "csv":
		output = of.formatCSV(result)
	default:
		output = of.formatEnhancedNmapStyle(result)
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, []byte(output), 0644)
	}

	fmt.Print(output)
	return nil
}

func (of *OutputFormatter) formatEnhancedNmapStyle(result model.ScanResult) string {
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("\n[乾坤圈端口扫描器] %s\n", of.version))
	builder.WriteString(strings.Repeat("═", 60) + "\n")
	builder.WriteString(fmt.Sprintf("目标: %s\n", result.Target))
	builder.WriteString(fmt.Sprintf("状态: %s\n", result.HostStatus))
	builder.WriteString(fmt.Sprintf("时间: %s\n\n", result.ScanTime))

	if len(result.Ports) == 0 {
		builder.WriteString("[!] 未发现任何端口\n")
		return builder.String()
	}

	openCount, filteredCount, closedCount := 0, 0, 0
	for _, port := range result.Ports {
		switch port.State {
		case "open":
			openCount++
		case "filtered":
			filteredCount++
		case "closed":
			closedCount++
		}
	}

	builder.WriteString(fmt.Sprintf("[端口状态统计] 开放(%d) | 过滤(%d) | 关闭(%d)\n\n",
		openCount, filteredCount, closedCount))

	builder.WriteString("[端口扫描结果]:\n")
	builder.WriteString(strings.Repeat("─", 80) + "\n")

	w := tabwriter.NewWriter(&builder, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "端口\t状态\t服务\t版本\tCVE信息\t风险等级")

	sortedPorts := make([]model.PortResult, len(result.Ports))
	copy(sortedPorts, result.Ports)

	for i := 0; i < len(sortedPorts)-1; i++ {
		for j := i + 1; j < len(sortedPorts); j++ {
			if sortedPorts[i].Port > sortedPorts[j].Port {
				sortedPorts[i], sortedPorts[j] = sortedPorts[j], sortedPorts[i]
			}
		}
	}

	for _, port := range sortedPorts {
		var stateTag, stateText string
		switch port.State {
		case "open":
			stateTag = "[+]"
			stateText = "开放"
		case "filtered":
			stateTag = "[F]"
			stateText = "过滤"
		case "closed":
			stateTag = "[-]"
			stateText = "关闭"
		default:
			stateTag = "[?]"
			stateText = port.State
		}

		serviceName := port.Service.Name
		if serviceName == "" {
			serviceName = getServiceNameByPort(port.Port)
		}

		version := port.Service.Version
		if version == "" {
			version = "-"
		}

		cveInfo := "-"
		if len(port.CVEs) > 0 {
			if len(port.CVEs) == 1 {
				cveInfo = port.CVEs[0].CVEID
			} else {
				maxScore := 0.0
				var maxCVE string
				for _, cve := range port.CVEs {
					if cve.Score > maxScore {
						maxScore = cve.Score
						maxCVE = cve.CVEID
					}
				}
				cveInfo = fmt.Sprintf("%s [+%d]", maxCVE, len(port.CVEs)-1)
			}
		}

		riskLevel := port.RiskLevel
		if riskLevel == "" {
			riskLevel = "-"
		}

		var riskTag string
		switch riskLevel {
		case "严重":
			riskTag = "[CRIT]"
		case "高":
			riskTag = "[HIGH]"
		case "中":
			riskTag = "[MED]"
		case "低":
			riskTag = "[LOW]"
		default:
			riskTag = "[-]"
		}

		fmt.Fprintf(w, "%d/tcp\t%s %s\t%s\t\t%s\t%s\t\t%s %s\n",
			port.Port,
			stateTag, stateText,
			serviceName,
			version,
			cveInfo,
			riskTag, riskLevel,
		)
	}
	w.Flush()

	hasOpenPorts := false
	for _, port := range result.Ports {
		if port.State == "open" {
			hasOpenPorts = true
			break
		}
	}

	if hasOpenPorts {
		hasCVEs := false
		totalCVEs := 0
		for _, port := range result.Ports {
			if port.State == "open" && len(port.CVEs) > 0 {
				hasCVEs = true
				totalCVEs += len(port.CVEs)
			}
		}

		if hasCVEs {
			builder.WriteString(fmt.Sprintf("\n[!] 发现 %d 个CVE漏洞:\n", totalCVEs))
			builder.WriteString(strings.Repeat("═", 60) + "\n")

			for _, port := range result.Ports {
				if port.State == "open" && len(port.CVEs) > 0 {
					serviceName := port.Service.Name
					if serviceName == "" {
						serviceName = "未知服务"
					}

					builder.WriteString(fmt.Sprintf("\n> 端口 %d/tcp (%s):\n",
						port.Port, serviceName))
					builder.WriteString(strings.Repeat("─", 40) + "\n")

					sortedCVEs := make([]model.CVEDetail, len(port.CVEs))
					copy(sortedCVEs, port.CVEs)

					for i := 0; i < len(sortedCVEs)-1; i++ {
						for j := i + 1; j < len(sortedCVEs); j++ {
							if sortedCVEs[i].Score < sortedCVEs[j].Score {
								sortedCVEs[i], sortedCVEs[j] = sortedCVEs[j], sortedCVEs[i]
							}
						}
					}

					for _, cve := range sortedCVEs {
						var severityTag string
						switch {
						case cve.Score >= 9.0:
							severityTag = "[严重]"
						case cve.Score >= 7.0:
							severityTag = "[高危]"
						case cve.Score >= 4.0:
							severityTag = "[中危]"
						default:
							severityTag = "[低危]"
						}

						builder.WriteString(fmt.Sprintf("%s %s ", severityTag, cve.CVEID))
						builder.WriteString(fmt.Sprintf("(CVSS: %.1f)", cve.Score))

						switch {
						case cve.Score >= 9.0:
							builder.WriteString(" CRITICAL")
						case cve.Score >= 7.0:
							builder.WriteString(" HIGH")
						case cve.Score >= 4.0:
							builder.WriteString(" MEDIUM")
						default:
							builder.WriteString(" LOW")
						}

						builder.WriteString("\n")

						desc := cve.Summary
						if len(desc) > 100 {
							desc = desc[:100] + "..."
						}
						builder.WriteString(fmt.Sprintf("    %s\n", desc))

						if cve.CNVDID != "" {
							builder.WriteString(fmt.Sprintf("    CNVD: %s\n", cve.CNVDID))
						}

						if len(cve.References) > 0 {
							builder.WriteString(fmt.Sprintf("    参考: %s\n", cve.References[0].URL))
						}
						builder.WriteString("\n")
					}
				}
			}
		} else {
			builder.WriteString("\n[OK] 未发现已知CVE漏洞\n")
		}
	}

	hasFiltered := false
	for _, port := range result.Ports {
		if port.State == "filtered" {
			hasFiltered = true
			break
		}
	}

	if hasFiltered {
		builder.WriteString("\n[说明]\n")
		builder.WriteString("  [F] 过滤 - 端口可能被防火墙阻止或无响应\n")
		builder.WriteString("  [+] 开放 - 端口正在运行服务\n")
		builder.WriteString("  [-] 关闭 - 端口没有运行服务\n")
	}

	builder.WriteString("\n" + strings.Repeat("═", 60) + "\n")
	builder.WriteString("[完成] 扫描结束\n")

	return builder.String()
}

func getServiceNameByPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 445:
		return "smb"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 8080:
		return "http-proxy"
	case 8443:
		return "https-alt"
	case 9200:
		return "elasticsearch"
	case 27017:
		return "mongodb"
	default:
		return "unknown"
	}
}

func (of *OutputFormatter) formatJSON(result model.ScanResult) string {
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf(`{"error": "%v"}`, err)
	}
	return string(jsonBytes)
}

func (of *OutputFormatter) formatCSV(result model.ScanResult) string {
	var builder strings.Builder
	writer := csv.NewWriter(&builder)

	writer.Write([]string{"端口", "协议", "服务", "版本", "状态", "CVE数量", "最高风险CVE", "风险分数", "风险等级"})

	for _, port := range result.Ports {
		topCVE := ""
		topScore := 0.0
		for _, cve := range port.CVEs {
			if cve.Score > topScore {
				topScore = cve.Score
				topCVE = cve.CVEID
			}
		}

		riskLevel := port.RiskLevel
		if riskLevel == "" {
			riskLevel = "-"
		}

		writer.Write([]string{
			strconv.Itoa(port.Port),
			port.Protocol,
			port.Service.Name,
			port.Service.Version,
			port.State,
			strconv.Itoa(len(port.CVEs)),
			topCVE,
			fmt.Sprintf("%.1f", topScore),
			riskLevel,
		})
	}

	writer.Flush()
	return builder.String()
}

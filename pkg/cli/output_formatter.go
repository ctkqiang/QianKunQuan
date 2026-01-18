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
	format string
}

func NewOutputFormatter(format string) *OutputFormatter {
	return &OutputFormatter{format: format}
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

// formatEnhancedNmapStyle 增强版nmap风格输出
func (of *OutputFormatter) formatEnhancedNmapStyle(result model.ScanResult) string {
	var builder strings.Builder

	// 标题行
	builder.WriteString(fmt.Sprintf("\n📡 乾坤圈端口扫描器 v1.0\n"))
	builder.WriteString(strings.Repeat("═", 60) + "\n")

	// 扫描信息
	builder.WriteString(fmt.Sprintf("目标: %s\n", result.Target))
	builder.WriteString(fmt.Sprintf("状态: %s\n", result.HostStatus))
	builder.WriteString(fmt.Sprintf("时间: %s\n\n", result.ScanTime))

	if len(result.Ports) == 0 {
		builder.WriteString("❌ 未发现任何端口\n")
		return builder.String()
	}

	// 统计信息
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

	builder.WriteString(fmt.Sprintf("📊 端口状态统计: 开放(%d) | 过滤(%d) | 关闭(%d)\n\n",
		openCount, filteredCount, closedCount))

	// 端口表格 - 类似nmap的输出
	builder.WriteString("🔍 端口扫描结果:\n")
	builder.WriteString(strings.Repeat("─", 80) + "\n")

	w := tabwriter.NewWriter(&builder, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "端口\t状态\t服务\t版本\tCVE信息\t风险等级")

	// 按端口号排序
	sortedPorts := make([]model.PortResult, len(result.Ports))
	copy(sortedPorts, result.Ports)

	// 简单排序
	for i := 0; i < len(sortedPorts)-1; i++ {
		for j := i + 1; j < len(sortedPorts); j++ {
			if sortedPorts[i].Port > sortedPorts[j].Port {
				sortedPorts[i], sortedPorts[j] = sortedPorts[j], sortedPorts[i]
			}
		}
	}

	for _, port := range sortedPorts {
		// 状态显示
		var stateIcon, stateText string
		switch port.State {
		case "open":
			stateIcon = "🟢"
			stateText = "开放"
		case "filtered":
			stateIcon = "🟡"
			stateText = "过滤"
		case "closed":
			stateIcon = "🔴"
			stateText = "关闭"
		default:
			stateIcon = "⚪"
			stateText = port.State
		}

		// 服务名称
		serviceName := port.Service.Name
		if serviceName == "" {
			// 尝试根据端口号猜测
			switch port.Port {
			case 21:
				serviceName = "ftp"
			case 22:
				serviceName = "ssh"
			case 80:
				serviceName = "http"
			case 443:
				serviceName = "https"
			case 3306:
				serviceName = "mysql"
			case 5432:
				serviceName = "postgresql"
			default:
				serviceName = "unknown"
			}
		}

		// 版本信息
		version := port.Service.Version
		if version == "" {
			version = "-"
		}

		// CVE信息
		cveInfo := ""
		if len(port.CVEs) > 0 {
			if len(port.CVEs) == 1 {
				cveInfo = fmt.Sprintf("%s", port.CVEs[0].CVEID)
			} else {
				// 显示最高分的CVE
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
		} else {
			cveInfo = "-"
		}

		// 风险等级
		riskLevel := port.RiskLevel
		if riskLevel == "" {
			riskLevel = "-"
		}

		// 风险等级图标
		var riskIcon string
		switch riskLevel {
		case "严重":
			riskIcon = "🔴"
		case "高":
			riskIcon = "🟠"
		case "中":
			riskIcon = "🟡"
		case "低":
			riskIcon = "🟢"
		default:
			riskIcon = "⚪"
		}

		fmt.Fprintf(w, "%d/tcp\t%s %s\t%s\t\t%s\t%s\t\t%s %s\n",
			port.Port,
			stateIcon, stateText,
			serviceName,
			version,
			cveInfo,
			riskIcon, riskLevel,
		)
	}
	w.Flush()

	// CVE详细信息
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
			builder.WriteString(fmt.Sprintf("\n⚠️  发现 %d 个CVE漏洞:\n", totalCVEs))
			builder.WriteString(strings.Repeat("═", 60) + "\n")

			for _, port := range result.Ports {
				if port.State == "open" && len(port.CVEs) > 0 {
					serviceName := port.Service.Name
					if serviceName == "" {
						serviceName = "未知服务"
					}

					builder.WriteString(fmt.Sprintf("\n🔸 端口 %d/tcp (%s):\n",
						port.Port, serviceName))
					builder.WriteString(strings.Repeat("─", 40) + "\n")

					// 按CVSS分数排序，先显示高危
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
						// 严重程度图标
						severityIcon := "⚠️"
						if cve.Score >= 9.0 {
							severityIcon = "🔥"
						} else if cve.Score >= 7.0 {
							severityIcon = "🔴"
						} else if cve.Score >= 4.0 {
							severityIcon = "🟠"
						}

						builder.WriteString(fmt.Sprintf("%s %s ", severityIcon, cve.CVEID))
						builder.WriteString(fmt.Sprintf("(CVSS: %.1f", cve.Score))

						// 严重等级文字
						switch {
						case cve.Score >= 9.0:
							builder.WriteString(" ⚠️ 严重")
						case cve.Score >= 7.0:
							builder.WriteString(" 🔴 高危")
						case cve.Score >= 4.0:
							builder.WriteString(" 🟠 中危")
						default:
							builder.WriteString(" 🟢 低危")
						}

						builder.WriteString(")\n")

						// 简短描述（限制长度）
						desc := cve.Summary
						if len(desc) > 100 {
							desc = desc[:100] + "..."
						}
						builder.WriteString(fmt.Sprintf("   📝 %s\n", desc))

						// 参考链接
						if len(cve.References) > 0 {
							builder.WriteString(fmt.Sprintf("   🔗 %s\n", cve.References[0].URL))
						}
						builder.WriteString("\n")
					}
				}
			}
		} else {
			builder.WriteString("\n✅ 好消息！未发现已知CVE漏洞\n")
		}
	}

	// 过滤端口说明
	hasFiltered := false
	for _, port := range result.Ports {
		if port.State == "filtered" {
			hasFiltered = true
			break
		}
	}

	if hasFiltered {
		builder.WriteString("\n💡 说明:\n")
		builder.WriteString("  🟡 过滤 - 端口可能被防火墙阻止或无响应\n")
		builder.WriteString("  🟢 开放 - 端口正在运行服务\n")
		builder.WriteString("  🔴 关闭 - 端口没有运行服务\n")
	}

	builder.WriteString("\n" + strings.Repeat("═", 60) + "\n")
	builder.WriteString("✨ 扫描完成！\n")

	return builder.String()
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

	// 写入表头
	writer.Write([]string{"端口", "协议", "服务", "版本", "状态", "CVE数量", "最高风险CVE", "风险分数", "风险等级"})

	// 写入数据
	for _, port := range result.Ports {
		// 查找最高风险的CVE
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

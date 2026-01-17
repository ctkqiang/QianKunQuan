package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
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
		output = of.formatText(result)
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, []byte(output), 0644)
	}

	fmt.Println(output)
	return nil
}

func (of *OutputFormatter) formatText(result model.ScanResult) string {
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("扫描结果: %s\n", result.Target))
	builder.WriteString(fmt.Sprintf("主机状态: %s\n", result.HostStatus))
	builder.WriteString(fmt.Sprintf("扫描时间: %s\n\n", result.ScanTime))

	builder.WriteString("开放端口:\n")
	builder.WriteString(strings.Repeat("-", 100) + "\n")

	w := tabwriter.NewWriter(&builder, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "端口\t协议\t服务\t版本\t状态\t风险等级\tCVE数量")
	fmt.Fprintln(w, "----\t----\t----\t----\t----\t--------\t-------")

	for _, port := range result.Ports {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%d\n",
			port.Port,
			port.Protocol,
			port.Service.Name,
			port.Service.Version,
			port.State,
			port.RiskLevel,
			len(port.CVEs),
		)
	}
	w.Flush()

	builder.WriteString("\n详细漏洞信息:\n")
	builder.WriteString(strings.Repeat("=", 100) + "\n")

	for _, port := range result.Ports {
		if len(port.CVEs) > 0 {
			builder.WriteString(fmt.Sprintf("\n端口 %d (%s):\n", port.Port, port.Service.Name))
			for _, cve := range port.CVEs {
				builder.WriteString(fmt.Sprintf("  • %s (CVSS: %.1f, 等级: %s)\n",
					cve.CVEID, cve.Score, cve.Severity))
				builder.WriteString(fmt.Sprintf("    描述: %s\n", cve.Summary))
			}
		}
	}

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
	writer.Write([]string{"端口", "协议", "服务", "版本", "状态", "风险等级", "CVE数量"})

	// 写入数据
	for _, port := range result.Ports {
		writer.Write([]string{
			fmt.Sprintf("%d", port.Port),
			port.Protocol,
			port.Service.Name,
			port.Service.Version,
			port.State,
			port.RiskLevel,
			fmt.Sprintf("%d", len(port.CVEs)),
		})
	}

	writer.Flush()
	return builder.String()
}

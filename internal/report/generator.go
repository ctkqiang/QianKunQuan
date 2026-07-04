package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"QianKunQuan/internal/model"
)

type ReportGenerator struct {
	title    string
	company  string
	assessor string
}

func NewReportGenerator(title, company, assessor string) *ReportGenerator {
	return &ReportGenerator{
		title:    title,
		company:  company,
		assessor: assessor,
	}
}

func (rg *ReportGenerator) BuildReport(target string, portScan *model.ScanResult, webScan *model.WebScanResult, attackPaths []model.AttackPath) *model.RedTeamReport {
	report := &model.RedTeamReport{
		Target:      target,
		ReportTime:  time.Now(),
		OverallRisk: rg.calculateOverallRisk(portScan, webScan, attackPaths),
		AttackPaths: attackPaths,
		PortScan:    portScan,
		WebScan:     webScan,
	}

	if portScan != nil {
		for _, p := range portScan.Ports {
			if p.State == "open" {
				report.Summary.OpenPorts++
				for _, cve := range p.CVEs {
					report.Summary.VulnCount++
					switch {
					case cve.Score >= 9.0:
						report.Summary.CriticalVuln++
					case cve.Score >= 7.0:
						report.Summary.HighVuln++
					case cve.Score >= 4.0:
						report.Summary.MediumVuln++
					default:
						report.Summary.LowVuln++
					}
				}
			}
		}
	}

	report.Summary.AttackPaths = len(attackPaths)

	report.CriticalHits = rg.extractCriticalHits(portScan, webScan, attackPaths)
	report.Recommendations = rg.generateRecommendations(portScan, webScan, attackPaths)

	return report
}

func (rg *ReportGenerator) calculateOverallRisk(portScan *model.ScanResult, webScan *model.WebScanResult, attackPaths []model.AttackPath) string {
	score := 0

	if portScan != nil {
		for _, p := range portScan.Ports {
			if p.State != "open" {
				continue
			}
			switch strings.ToLower(p.RiskLevel) {
			case "严重":
				score += 10
			case "高":
				score += 5
			case "中":
				score += 2
			}
		}
	}

	if webScan != nil {
		if webScan.WAF == "" {
			score += 3
		}
		if webScan.CMS != "" {
			score += 3
		}
		if len(webScan.URLs) > 5 {
			score += 3
		}
	}

	for _, ap := range attackPaths {
		switch strings.ToLower(ap.Risk) {
		case "严重":
			score += 8
		case "高":
			score += 4
		case "中":
			score += 2
		}
	}

	switch {
	case score >= 30:
		return "严重"
	case score >= 15:
		return "高"
	case score >= 5:
		return "中"
	default:
		return "低"
	}
}

func (rg *ReportGenerator) extractCriticalHits(portScan *model.ScanResult, webScan *model.WebScanResult, attackPaths []model.AttackPath) []model.CriticalHit {
	var hits []model.CriticalHit

	if portScan != nil {
		for _, p := range portScan.Ports {
			if p.State != "open" {
				continue
			}
			for _, cve := range p.CVEs {
				if cve.Score >= 9.0 {
					hits = append(hits, model.CriticalHit{
						Name:        cve.CVEID,
						Severity:    "严重",
						Description: cve.Summary,
						Location:    fmt.Sprintf("端口 %d (%s)", p.Port, p.Service.Name),
						Evidence:    fmt.Sprintf("CVSS %.1f", cve.Score),
					})
				}
			}
		}
	}

	if webScan != nil {
		if webScan.WAF == "" && len(webScan.URLs) > 3 {
			hits = append(hits, model.CriticalHit{
				Name:        "无WAF防护 + 敏感路径暴露",
				Severity:    "高",
				Description: "未检测到WAF防护，且存在多个敏感路径，攻击者可直接利用",
				Location:    webScan.Target,
				Evidence:    fmt.Sprintf("%d个敏感路径", len(webScan.URLs)),
			})
		}
	}

	for _, ap := range attackPaths {
		if strings.ToLower(ap.Risk) == "严重" {
			hits = append(hits, model.CriticalHit{
				Name:        ap.Technique,
				Severity:    ap.Risk,
				Description: ap.Description,
				Location:    ap.Tactic,
				Evidence:    strings.Join(ap.Tools, ", "),
			})
		}
	}

	return hits
}

func (rg *ReportGenerator) generateRecommendations(portScan *model.ScanResult, webScan *model.WebScanResult, attackPaths []model.AttackPath) []string {
	var recs []string

	if portScan != nil {
		serviceSeen := make(map[string]bool)
		for _, p := range portScan.Ports {
			if p.State != "open" {
				continue
			}
			service := strings.ToLower(p.Service.Name)
			switch {
			case strings.Contains(service, "redis") && !serviceSeen["redis"]:
				recs = append(recs, "[紧急] Redis服务配置认证密码，并绑定127.0.0.1")
				serviceSeen["redis"] = true
			case strings.Contains(service, "mongodb") && !serviceSeen["mongodb"]:
				recs = append(recs, "[紧急] MongoDB启用auth认证，限制内网访问")
				serviceSeen["mongodb"] = true
			case strings.Contains(service, "elasticsearch") && !serviceSeen["es"]:
				recs = append(recs, "[紧急] Elasticsearch启用x-pack安全模块")
				serviceSeen["es"] = true
			case strings.Contains(service, "mysql") && !serviceSeen["mysql"]:
				recs = append(recs, "[高危] MySQL修改默认密码，限制远程访问")
				serviceSeen["mysql"] = true
			case strings.Contains(service, "docker") && !serviceSeen["docker"]:
				recs = append(recs, "[紧急] Docker API启用TLS认证，关闭2375端口公网访问")
				serviceSeen["docker"] = true
			case strings.Contains(service, "kubernetes") && !serviceSeen["k8s"]:
				recs = append(recs, "[紧急] K8s API Server启用RBAC和认证")
				serviceSeen["k8s"] = true
			case strings.Contains(service, "ssh") && !serviceSeen["ssh"]:
				recs = append(recs, "[中危] SSH禁用密码登录，启用密钥认证+MFA")
				serviceSeen["ssh"] = true
			case strings.Contains(service, "rdp") && !serviceSeen["rdp"]:
				recs = append(recs, "[中危] RDP启用NLA，限制访问IP，启用账户锁定")
				serviceSeen["rdp"] = true
			case strings.Contains(service, "smb") && !serviceSeen["smb"]:
				recs = append(recs, "[紧急] 修补MS17-010，禁用SMBv1")
				serviceSeen["smb"] = true
			case strings.Contains(service, "ftp") && !serviceSeen["ftp"]:
				recs = append(recs, "[中危] FTP禁用匿名访问，使用SFTP替代")
				serviceSeen["ftp"] = true
			case strings.Contains(service, "telnet") && !serviceSeen["telnet"]:
				recs = append(recs, "[紧急] 禁用Telnet，迁移到SSH")
				serviceSeen["telnet"] = true
			}
		}
	}

	if webScan != nil {
		if webScan.WAF == "" {
			recs = append(recs, "[中危] 部署WAF（推荐阿里云盾/安全狗/长亭雷池）")
		}
		if webScan.CMS != "" {
			recs = append(recs, fmt.Sprintf("[中危] 升级 %s 到最新版本，移除不必要插件", webScan.CMS))
		}
		for _, dir := range webScan.URLs {
			if strings.Contains(dir.Path, ".git") || strings.Contains(dir.Path, ".env") {
				recs = append(recs, "[紧急] 清理源码泄露文件（.git/.env等），配置服务器禁止访问隐藏文件")
				break
			}
		}
	}

	recs = append(recs, "[建议] 建立常态化红队评估机制，定期开展攻防演练")
	recs = append(recs, "[建议] 部署EDR/HIDS，加强异常行为检测能力")

	return recs
}

func (rg *ReportGenerator) GenerateHTML(report *model.RedTeamReport) string {
	var b strings.Builder

	b.WriteString("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n")
	b.WriteString("<meta charset=\"UTF-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	b.WriteString(fmt.Sprintf("<title>%s - %s</title>\n", rg.title, report.Target))
	b.WriteString("<style>\n")
	b.WriteString(rg.htmlCSS())
	b.WriteString("</style>\n</head>\n<body>\n")

	b.WriteString("<div class=\"container\">\n")

	b.WriteString("<header>\n")
	b.WriteString(fmt.Sprintf("<h1>%s</h1>\n", rg.title))
	b.WriteString("<div class=\"meta\">\n")
	if rg.company != "" {
		b.WriteString(fmt.Sprintf("<span>客户: <strong>%s</strong></span>\n", rg.company))
	}
	b.WriteString(fmt.Sprintf("<span>目标: <strong>%s</strong></span>\n", report.Target))
	b.WriteString(fmt.Sprintf("<span>评估方: <strong>%s</strong></span>\n", rg.assessor))
	b.WriteString(fmt.Sprintf("<span>时间: <strong>%s</strong></span>\n", report.ReportTime.Format("2006-01-02 15:04:05")))
	b.WriteString("</div>\n")
	b.WriteString("</header>\n")

	riskColor := rg.getRiskColor(report.OverallRisk)
	b.WriteString("<div class=\"risk-banner\">\n")
	b.WriteString(fmt.Sprintf("<div class=\"risk-level\" style=\"background:%s\">\n", riskColor))
	b.WriteString(fmt.Sprintf("<span>总体风险等级</span>\n<strong>%s</strong>\n</div>\n", report.OverallRisk))
	b.WriteString("<div class=\"risk-stats\">\n")
	b.WriteString(fmt.Sprintf("<div class=\"stat\"><span>%d</span><label>开放端口</label></div>\n", report.Summary.OpenPorts))
	b.WriteString(fmt.Sprintf("<div class=\"stat\"><span>%d</span><label>漏洞总数</label></div>\n", report.Summary.VulnCount))
	b.WriteString(fmt.Sprintf("<div class=\"stat critical\"><span>%d</span><label>严重</label></div>\n", report.Summary.CriticalVuln))
	b.WriteString(fmt.Sprintf("<div class=\"stat high\"><span>%d</span><label>高危</label></div>\n", report.Summary.HighVuln))
	b.WriteString(fmt.Sprintf("<div class=\"stat medium\"><span>%d</span><label>中危</label></div>\n", report.Summary.MediumVuln))
	b.WriteString(fmt.Sprintf("<div class=\"stat\"><span>%d</span><label>攻击路径</label></div>\n", report.Summary.AttackPaths))
	b.WriteString("</div>\n</div>\n")

	if len(report.CriticalHits) > 0 {
		b.WriteString("<section>\n<h2>关键发现</h2>\n")
		b.WriteString("<div class=\"critical-hits\">\n")
		for _, hit := range report.CriticalHits {
			b.WriteString("<div class=\"hit-card\">\n")
			b.WriteString(fmt.Sprintf("<div class=\"hit-header %s\">%s · %s</div>\n", strings.ToLower(hit.Severity), hit.Name, hit.Severity))
			b.WriteString(fmt.Sprintf("<p>%s</p>\n", hit.Description))
			b.WriteString(fmt.Sprintf("<div class=\"hit-meta\">位置: %s | 证据: %s</div>\n", hit.Location, hit.Evidence))
			b.WriteString("</div>\n")
		}
		b.WriteString("</div>\n</section>\n")
	}

	if report.PortScan != nil && len(report.PortScan.Ports) > 0 {
		b.WriteString("<section>\n<h2>端口扫描结果</h2>\n")
		b.WriteString("<table>\n<thead><tr><th>端口</th><th>状态</th><th>服务</th><th>版本</th><th>CVE</th><th>风险</th></tr></thead>\n<tbody>\n")
		for _, p := range report.PortScan.Ports {
			if p.State != "open" {
				continue
			}
			cveCount := len(p.CVEs)
			cveStr := "-"
			if cveCount > 0 {
				cveStr = fmt.Sprintf("%d个", cveCount)
			}
			riskClass := strings.ToLower(p.RiskLevel)
			b.WriteString(fmt.Sprintf("<tr><td>%d/tcp</td><td class=\"open\">开放</td><td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td></tr>\n",
				p.Port, p.Service.Name, p.Service.Version, cveStr, riskClass, p.RiskLevel))
		}
		b.WriteString("</tbody>\n</table>\n</section>\n")
	}

	if report.WebScan != nil {
		b.WriteString("<section>\n<h2>Web应用侦察</h2>\n")
		b.WriteString("<div class=\"web-info\">\n")
		b.WriteString(fmt.Sprintf("<div class=\"info-item\"><label>服务器</label><span>%s</span></div>\n", report.WebScan.Server))
		b.WriteString(fmt.Sprintf("<div class=\"info-item\"><label>CMS</label><span>%s %s</span></div>\n", report.WebScan.CMS, report.WebScan.CMSVersion))
		b.WriteString(fmt.Sprintf("<div class=\"info-item\"><label>WAF</label><span>%s</span></div>\n", rg.wafDisplay(report.WebScan.WAF)))
		if len(report.WebScan.TechStack) > 0 {
			b.WriteString(fmt.Sprintf("<div class=\"info-item\"><label>技术栈</label><span>%s</span></div>\n", strings.Join(report.WebScan.TechStack, ", ")))
		}
		b.WriteString("</div>\n")

		if len(report.WebScan.URLs) > 0 {
			b.WriteString("<h3>敏感路径</h3>\n<table>\n<thead><tr><th>路径</th><th>状态码</th><th>大小</th><th>标题</th></tr></thead>\n<tbody>\n")
			for _, dir := range report.WebScan.URLs {
				b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td></tr>\n", dir.Path, dir.StatusCode, dir.Length, dir.Title))
			}
			b.WriteString("</tbody>\n</table>\n")
		}
		b.WriteString("</section>\n")
	}

	if len(report.AttackPaths) > 0 {
		b.WriteString("<section>\n<h2>攻击路径推荐</h2>\n")
		phaseMap := make(map[string][]model.AttackPath)
		var phaseOrder []string
		for _, ap := range report.AttackPaths {
			if _, ok := phaseMap[ap.Phase]; !ok {
				phaseOrder = append(phaseOrder, ap.Phase)
			}
			phaseMap[ap.Phase] = append(phaseMap[ap.Phase], ap)
		}

		for _, phase := range phaseOrder {
			b.WriteString(fmt.Sprintf("<h3>%s</h3>\n", phase))
			for _, ap := range phaseMap[phase] {
				riskClass := strings.ToLower(ap.Risk)
				b.WriteString("<div class=\"attack-card\">\n")
				b.WriteString(fmt.Sprintf("<div class=\"attack-header %s\"><strong>%s</strong> <span class=\"risk-tag %s\">%s</span></div>\n", riskClass, ap.Technique, riskClass, ap.Risk))
				b.WriteString(fmt.Sprintf("<p>%s</p>\n", ap.Description))
				if len(ap.Steps) > 0 {
					b.WriteString("<ol>\n")
					for _, s := range ap.Steps {
						b.WriteString(fmt.Sprintf("<li>%s</li>\n", s))
					}
					b.WriteString("</ol>\n")
				}
				b.WriteString(fmt.Sprintf("<div class=\"attack-tools\">工具: %s</div>\n", strings.Join(ap.Tools, ", ")))
				b.WriteString("</div>\n")
			}
		}
		b.WriteString("</section>\n")
	}

	if len(report.Recommendations) > 0 {
		b.WriteString("<section>\n<h2>整改建议</h2>\n<ul class=\"recs\">\n")
		for _, rec := range report.Recommendations {
			b.WriteString(fmt.Sprintf("<li>%s</li>\n", rec))
		}
		b.WriteString("</ul>\n</section>\n")
	}

	b.WriteString("<footer>\n<p>本报告由乾坤圈红队侦察平台自动生成 | 仅供授权安全评估使用</p>\n<p>[警告] 未经授权的渗透测试属违法行为，请确保已获得书面授权</p>\n</footer>\n")
	b.WriteString("</div>\n</body>\n</html>\n")

	return b.String()
}

func (rg *ReportGenerator) GenerateMarkdown(report *model.RedTeamReport) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# %s\n\n", rg.title))
	b.WriteString(fmt.Sprintf("> [警告] **法律声明**: 本报告仅供授权安全评估使用，未经授权的渗透测试属违法行为\n\n"))

	b.WriteString("## 评估概览\n\n")
	if rg.company != "" {
		b.WriteString(fmt.Sprintf("- **客户**: %s\n", rg.company))
	}
	b.WriteString(fmt.Sprintf("- **目标**: %s\n", report.Target))
	b.WriteString(fmt.Sprintf("- **评估方**: %s\n", rg.assessor))
	b.WriteString(fmt.Sprintf("- **报告时间**: %s\n", report.ReportTime.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("- **总体风险等级**: **%s**\n\n", report.OverallRisk))

	b.WriteString("## 风险统计\n\n")
	b.WriteString("| 指标 | 数值 |\n|------|------|\n")
	b.WriteString(fmt.Sprintf("| 开放端口 | %d |\n", report.Summary.OpenPorts))
	b.WriteString(fmt.Sprintf("| 漏洞总数 | %d |\n", report.Summary.VulnCount))
	b.WriteString(fmt.Sprintf("| 严重漏洞 | %d |\n", report.Summary.CriticalVuln))
	b.WriteString(fmt.Sprintf("| 高危漏洞 | %d |\n", report.Summary.HighVuln))
	b.WriteString(fmt.Sprintf("| 中危漏洞 | %d |\n", report.Summary.MediumVuln))
	b.WriteString(fmt.Sprintf("| 攻击路径 | %d |\n\n", report.Summary.AttackPaths))

	if len(report.CriticalHits) > 0 {
		b.WriteString("## 关键发现\n\n")
		for _, hit := range report.CriticalHits {
			b.WriteString(fmt.Sprintf("### %s [%s]\n", hit.Name, hit.Severity))
			b.WriteString(fmt.Sprintf("- **描述**: %s\n", hit.Description))
			b.WriteString(fmt.Sprintf("- **位置**: %s\n", hit.Location))
			b.WriteString(fmt.Sprintf("- **证据**: %s\n\n", hit.Evidence))
		}
	}

	if report.PortScan != nil && len(report.PortScan.Ports) > 0 {
		b.WriteString("## 端口扫描结果\n\n")
		b.WriteString("| 端口 | 状态 | 服务 | 版本 | CVE数 | 风险 |\n")
		b.WriteString("|------|------|------|------|-------|------|\n")
		for _, p := range report.PortScan.Ports {
			if p.State != "open" {
				continue
			}
			b.WriteString(fmt.Sprintf("| %d/tcp | 开放 | %s | %s | %d | %s |\n",
				p.Port, p.Service.Name, p.Service.Version, len(p.CVEs), p.RiskLevel))
		}
		b.WriteString("\n")
	}

	if report.WebScan != nil {
		b.WriteString("## Web应用侦察\n\n")
		b.WriteString(fmt.Sprintf("- **服务器**: %s\n", report.WebScan.Server))
		b.WriteString(fmt.Sprintf("- **CMS**: %s %s\n", report.WebScan.CMS, report.WebScan.CMSVersion))
		b.WriteString(fmt.Sprintf("- **WAF**: %s\n", rg.wafDisplay(report.WebScan.WAF)))
		if len(report.WebScan.TechStack) > 0 {
			b.WriteString(fmt.Sprintf("- **技术栈**: %s\n", strings.Join(report.WebScan.TechStack, ", ")))
		}
		b.WriteString("\n")

		if len(report.WebScan.URLs) > 0 {
			b.WriteString("### 敏感路径\n\n")
			b.WriteString("| 路径 | 状态码 | 大小 | 标题 |\n|------|--------|------|------|\n")
			for _, dir := range report.WebScan.URLs {
				b.WriteString(fmt.Sprintf("| %s | %d | %d | %s |\n", dir.Path, dir.StatusCode, dir.Length, dir.Title))
			}
			b.WriteString("\n")
		}
	}

	if len(report.AttackPaths) > 0 {
		b.WriteString("## 攻击路径推荐\n\n")
		phaseMap := make(map[string][]model.AttackPath)
		var phaseOrder []string
		for _, ap := range report.AttackPaths {
			if _, ok := phaseMap[ap.Phase]; !ok {
				phaseOrder = append(phaseOrder, ap.Phase)
			}
			phaseMap[ap.Phase] = append(phaseMap[ap.Phase], ap)
		}

		for _, phase := range phaseOrder {
			b.WriteString(fmt.Sprintf("### %s\n\n", phase))
			for _, ap := range phaseMap[phase] {
				b.WriteString(fmt.Sprintf("#### %s [%s]\n", ap.Technique, ap.Risk))
				b.WriteString(fmt.Sprintf("- **战术**: %s\n", ap.Tactic))
				b.WriteString(fmt.Sprintf("- **描述**: %s\n", ap.Description))
				if len(ap.Steps) > 0 {
					b.WriteString("- **步骤**:\n")
					for i, s := range ap.Steps {
						b.WriteString(fmt.Sprintf("  %d. %s\n", i+1, s))
					}
				}
				b.WriteString(fmt.Sprintf("- **工具**: %s\n\n", strings.Join(ap.Tools, ", ")))
			}
		}
	}

	if len(report.Recommendations) > 0 {
		b.WriteString("## 整改建议\n\n")
		for _, rec := range report.Recommendations {
			b.WriteString(fmt.Sprintf("- %s\n", rec))
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n*本报告由乾坤圈红队侦察平台自动生成*\n")

	return b.String()
}

func (rg *ReportGenerator) SaveReport(report *model.RedTeamReport, outputFile, format string) error {
	var content string

	switch strings.ToLower(format) {
	case "markdown", "md":
		content = rg.GenerateMarkdown(report)
	case "html":
		content = rg.GenerateHTML(report)
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		content = string(data)
	default:
		content = rg.GenerateHTML(report)
	}

	return os.WriteFile(outputFile, []byte(content), 0644)
}

func (rg *ReportGenerator) getRiskColor(risk string) string {
	switch strings.ToLower(risk) {
	case "严重":
		return "#dc3545"
	case "高":
		return "#fd7e14"
	case "中":
		return "#ffc107"
	default:
		return "#28a745"
	}
}

func (rg *ReportGenerator) wafDisplay(waf string) string {
	if waf == "" {
		return "未检测到WAF [警告]"
	}
	return waf
}

func (rg *ReportGenerator) htmlCSS() string {
	return `
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
header { text-align: center; padding: 30px 0; border-bottom: 2px solid #30363d; margin-bottom: 30px; }
header h1 { color: #ff6b6b; font-size: 28px; margin-bottom: 15px; }
.meta { display: flex; justify-content: center; gap: 30px; flex-wrap: wrap; }
.meta span { font-size: 14px; }
.meta strong { color: #58a6ff; }
.risk-banner { display: flex; gap: 20px; margin-bottom: 30px; align-items: stretch; }
.risk-level { padding: 20px 40px; border-radius: 8px; text-align: center; color: white; min-width: 200px; display: flex; flex-direction: column; justify-content: center; }
.risk-level span { font-size: 14px; opacity: 0.9; }
.risk-level strong { font-size: 32px; }
.risk-stats { flex: 1; display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 10px; }
.stat { background: #161b22; padding: 15px; border-radius: 6px; text-align: center; border: 1px solid #30363d; }
.stat span { display: block; font-size: 24px; font-weight: bold; color: #58a6ff; }
.stat label { font-size: 12px; color: #8b949e; }
.stat.critical span { color: #ff6b6b; }
.stat.high span { color: #fd7e14; }
.stat.medium span { color: #ffc107; }
section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 25px; margin-bottom: 25px; }
section h2 { color: #58a6ff; font-size: 22px; margin-bottom: 20px; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
section h3 { color: #f0883e; font-size: 18px; margin: 20px 0 10px; }
table { width: 100%; border-collapse: collapse; margin: 10px 0; }
th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 14px; }
th { background: #21262d; color: #8b949e; font-weight: 600; }
tr:hover { background: #21262d; }
td.open { color: #3fb950; }
td.严重, td.critical { color: #ff6b6b; font-weight: bold; }
td.高, td.high { color: #fd7e14; }
td.中, td.medium { color: #ffc107; }
td.低, td.low { color: #3fb950; }
.critical-hits { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; }
.hit-card { background: #0d1117; border-radius: 6px; overflow: hidden; border: 1px solid #30363d; }
.hit-header { padding: 10px 15px; font-weight: bold; color: white; }
.hit-header.严重 { background: #dc3545; }
.hit-header.高 { background: #fd7e14; }
.hit-card p { padding: 15px; font-size: 14px; }
.hit-meta { padding: 0 15px 15px; font-size: 12px; color: #8b949e; }
.web-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
.info-item { background: #0d1117; padding: 12px 15px; border-radius: 6px; border: 1px solid #30363d; }
.info-item label { display: block; font-size: 12px; color: #8b949e; margin-bottom: 5px; }
.info-item span { font-size: 14px; color: #c9d1d9; }
.attack-card { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; margin-bottom: 15px; overflow: hidden; }
.attack-header { padding: 12px 15px; background: #21262d; border-left: 4px solid #58a6ff; }
.attack-header.严重 { border-left-color: #dc3545; }
.attack-header.高 { border-left-color: #fd7e14; }
.attack-header.中 { border-left-color: #ffc107; }
.risk-tag { float: right; padding: 2px 10px; border-radius: 12px; font-size: 12px; }
.risk-tag.严重 { background: #dc3545; color: white; }
.risk-tag.高 { background: #fd7e14; color: white; }
.risk-tag.中 { background: #ffc107; color: black; }
.attack-card p { padding: 12px 15px; font-size: 14px; }
.attack-card ol { padding: 0 15px 12px 35px; font-size: 14px; }
.attack-card ol li { margin-bottom: 5px; }
.attack-tools { padding: 10px 15px; background: #161b22; font-size: 13px; color: #8b949e; border-top: 1px solid #30363d; }
.recs { list-style: none; padding: 0; }
.recs li { padding: 10px 15px; background: #0d1117; border-left: 3px solid #58a6ff; margin-bottom: 8px; border-radius: 4px; font-size: 14px; }
footer { text-align: center; padding: 30px 0; color: #8b949e; font-size: 13px; border-top: 1px solid #30363d; }
footer p { margin-bottom: 5px; }
@media (max-width: 768px) { .risk-banner { flex-direction: column; } .meta { flex-direction: column; gap: 5px; } }
`
}

package cvedb

import (
	"database/sql"
	"fmt"
	"strings"

	"QianKunQuan/internal/model"
)

func (cd *CVEDatabase) LookupCVEs(service model.ServiceInfo) ([]model.CVEDetail, error) {
	var cves []model.CVEDetail

	// 如果服务名称为空，不查询
	if service.Name == "" {
		return cves, nil
	}

	// 构建查询条件
	product := strings.ToLower(service.Name)
	version := service.Version

	// 处理常见服务名称映射
	serviceMap := map[string][]string{
		"HTTP":   {"apache", "nginx", "iis", "tomcat", "jetty", "lighttpd", "httpd"},
		"HTTPS":  {"apache", "nginx", "iis", "tomcat", "jetty", "lighttpd", "httpd"},
		"nginx":  {"nginx"},
		"Apache": {"apache", "httpd"},
		"IIS":    {"iis", "internet information services"},
		"Tomcat": {"tomcat"},
	}

	// 获取可能的搜索词
	searchTerms := []string{product}
	if alternatives, ok := serviceMap[service.Name]; ok {
		searchTerms = append(searchTerms, alternatives...)
	}

	// 为每个搜索词执行查询
	for _, term := range searchTerms {
		query := `
		SELECT c.cve_id, c.description, c.cvss_score, c.cvss_severity
		FROM cves c
		JOIN affected_software a ON c.cve_id = a.cve_id
		WHERE (
			LOWER(a.product) LIKE ? OR 
			LOWER(a.product) LIKE ? OR
			LOWER(a.vendor) LIKE ?
		)
		AND (a.version = ? OR a.version = '' OR a.version = 'ANY' OR ? = '')
		ORDER BY c.cvss_score DESC
		LIMIT 15
		`

		termPattern1 := "%" + term + "%"
		termPattern2 := "%" + strings.ReplaceAll(term, " ", "%") + "%"

		rows, err := cd.db.Query(query,
			termPattern1,
			termPattern2,
			termPattern1,
			version,
			version,
		)

		if err != nil {
			cd.logger.Error("CVE查询失败: %v", err)
			continue
		}

		for rows.Next() {
			var cve model.CVEDetail
			var description string
			var score sql.NullFloat64
			var severity sql.NullString

			err := rows.Scan(&cve.CVEID, &description, &score, &severity)
			if err != nil {
				continue
			}

			// 处理可能的空值
			if score.Valid {
				cve.Score = score.Float64
			}

			if severity.Valid {
				cve.Severity = severity.String
			}

			// 转换CVSS等级为中文
			switch {
			case cve.Score >= 9.0:
				cve.Severity = "严重"
			case cve.Score >= 7.0:
				cve.Severity = "高危"
			case cve.Score >= 4.0:
				cve.Severity = "中危"
			default:
				cve.Severity = "低危"
			}

			// 截断过长的描述
			if len(description) > 200 {
				cve.Summary = description[:200] + "..."
			} else {
				cve.Summary = description
			}

			// 添加参考链接
			cve.References = []model.Link{
				{
					Name: "NVD",
					URL:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.CVEID),
				},
				{
					Name: "CVE Details",
					URL:  fmt.Sprintf("https://www.cvedetails.com/cve/%s/", cve.CVEID),
				},
			}

			cves = append(cves, cve)
		}
		rows.Close()
	}

	return cves, nil
}

package cvedb

import (
	"database/sql"
	"fmt"
	"strings"

	"QianKunQuan/internal/model"
)

func (cd *CVEDatabase) LookupCVEs(service model.ServiceInfo) ([]model.CVEDetail, error) {
	var cves []model.CVEDetail

	// 如果服务名称为空，返回空
	if service.Name == "" {
		return cves, nil
	}

	// 清理服务名称
	serviceName := strings.ToLower(strings.TrimSpace(service.Name))
	version := strings.TrimSpace(service.Version)

	cd.logger.Debug("查询CVE: 服务=%s, 版本=%s", serviceName, version)

	// 服务名称映射到常见关键词
	keywords := cd.getKeywordsForService(serviceName)

	// 构建查询
	query, args := cd.buildCVEQuery(keywords, version)

	rows, err := cd.db.Query(query, args...)
	if err != nil {
		cd.logger.Error("CVE查询失败: %v", err)
		return cves, err
	}
	defer rows.Close()

	for rows.Next() {
		var cve model.CVEDetail
		var description string
		var score sql.NullFloat64
		var severity sql.NullString

		err := rows.Scan(&cve.CVEID, &description, &score, &severity)
		if err != nil {
			continue
		}

		// 处理空值
		if score.Valid {
			cve.Score = score.Float64
		}

		if severity.Valid {
			cve.Severity = severity.String
		}

		// 根据CVSS分数确定严重等级
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

		// 截断描述
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
				Name: "CVE.org",
				URL:  fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", cve.CVEID),
			},
		}

		cves = append(cves, cve)
	}

	cd.logger.Debug("找到 %d 个CVE", len(cves))
	return cves, nil
}

// 获取服务的搜索关键词
func (cd *CVEDatabase) getKeywordsForService(serviceName string) []string {
	// 服务名称到关键词的映射
	keywordMap := map[string][]string{
		"http": {
			"apache", "httpd", "http_server", "nginx", "iis", "microsoft-iis",
			"tomcat", "jetty", "lighttpd", "http", "web server",
		},
		"https": {
			"apache", "httpd", "http_server", "nginx", "iis", "microsoft-iis",
			"tomcat", "jetty", "lighttpd", "http", "https", "ssl", "tls",
			"openssl",
		},
		"nginx": {
			"nginx", "http", "https", "web server",
		},
		"apache": {
			"apache", "httpd", "http_server", "http", "https",
		},
		"iis": {
			"iis", "microsoft-iis", "internet information services", "http", "https",
		},
		"tomcat": {
			"tomcat", "apache_tomcat", "http", "https",
		},
		"mysql": {
			"mysql", "mariadb", "database", "rdbms",
		},
		"postgresql": {
			"postgresql", "postgres", "database", "rdbms",
		},
		"redis": {
			"redis", "database", "key-value",
		},
		"mongodb": {
			"mongodb", "database", "nosql",
		},
		"ssh": {
			"ssh", "openssh", "dropbear", "remote access",
		},
		"ftp": {
			"ftp", "vsftpd", "proftpd", "filezilla", "file transfer",
		},
		"smtp": {
			"smtp", "postfix", "exim", "sendmail", "mail",
		},
	}

	// 返回匹配的关键词，如果没有匹配则返回原始服务名
	if keywords, found := keywordMap[serviceName]; found {
		return keywords
	}

	return []string{serviceName}
}

// 构建CVE查询
func (cd *CVEDatabase) buildCVEQuery(keywords []string, version string) (string, []interface{}) {
	// 构建关键词条件
	var keywordConditions []string
	var args []interface{}

	for _, keyword := range keywords {
		keywordConditions = append(keywordConditions,
			"(LOWER(a.product) LIKE ? OR LOWER(a.vendor) LIKE ?)")
		args = append(args, "%"+keyword+"%", "%"+keyword+"%")
	}

	// 构建版本条件
	versionCondition := ""
	if version != "" {
		versionCondition = " AND (a.version = ? OR a.version = '' OR a.version IS NULL)"
		args = append(args, version)
	}

	// 完整的查询语句
	query := fmt.Sprintf(`
		SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.cvss_severity
		FROM cves c
		JOIN affected_software a ON c.cve_id = a.cve_id
		WHERE (%s) %s
		ORDER BY c.cvss_score DESC
		LIMIT 10
	`, strings.Join(keywordConditions, " OR "), versionCondition)

	return query, args
}

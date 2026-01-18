package cvedb

import (
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"QianKunQuan/internal/model"
	"QianKunQuan/internal/utils"
)

// VersionMatcher 版本匹配器，用于精确匹配CVE
type VersionMatcher struct {
	db     *sql.DB
	logger *utils.Logger
}

func NewVersionMatcher(db *sql.DB) *VersionMatcher {
	return &VersionMatcher{
		db:     db,
		logger: utils.NewLogger("version-matcher"),
	}
}

// LookupCVEsByVersion 根据服务和版本精确查找CVE
func (vm *VersionMatcher) LookupCVEsByVersion(service model.ServiceInfo) ([]model.CVEDetail, error) {
	var cves []model.CVEDetail

	if service.Name == "" {
		return cves, nil
	}

	serviceName := strings.ToLower(strings.TrimSpace(service.Name))
	version := strings.TrimSpace(service.Version)

	vm.logger.Debug("精确查询CVE: 服务=%s, 版本=%s", serviceName, version)

	// 获取所有相关的CVE
	allCVEs, err := vm.getAllRelatedCVEs(serviceName)
	if err != nil {
		return cves, err
	}

	// 如果没有版本信息，返回所有相关CVE
	if version == "" || version == "-" {
		return vm.convertToCVEDetails(allCVEs), nil
	}

	// 根据版本过滤CVE
	for _, cve := range allCVEs {
		if vm.isVersionAffected(cve, version) {
			cves = append(cves, vm.convertCVEDetail(cve))
		}
	}

	vm.logger.Debug("找到 %d 个匹配版本的CVE", len(cves))
	return cves, nil
}

// getAllRelatedCVEs 获取所有相关的CVE
func (vm *VersionMatcher) getAllRelatedCVEs(serviceName string) ([]CVEWithAffected, error) {
	var cves []CVEWithAffected

	// 获取服务的关键词
	keywords := vm.getServiceKeywords(serviceName)

	// 构建查询
	query, args := vm.buildCVEQuery(keywords)

	rows, err := vm.db.Query(query, args...)
	if err != nil {
		return cves, err
	}
	defer rows.Close()

	for rows.Next() {
		var cve CVEWithAffected
		var description string
		var score sql.NullFloat64
		var severity sql.NullString

		err := rows.Scan(&cve.ID, &description, &score, &severity)
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

		cve.Description = description

		// 获取受影响的软件信息
		affected, err := vm.getAffectedSoftware(cve.ID)
		if err == nil {
			cve.AffectedSoftware = affected
		}

		cves = append(cves, cve)
	}

	return cves, nil
}

// CVEWithAffected 包含受影响软件的CVE结构
type CVEWithAffected struct {
	ID               string
	Description      string
	Score            float64
	Severity         string
	AffectedSoftware []model.AffectedSoftware
}

// 获取受影响的软件信息
func (vm *VersionMatcher) getAffectedSoftware(cveID string) ([]model.AffectedSoftware, error) {
	var affected []model.AffectedSoftware

	query := `
	SELECT vendor, product, version, version_end, cpe
	FROM affected_software
	WHERE cve_id = ?
	`

	rows, err := vm.db.Query(query, cveID)
	if err != nil {
		return affected, err
	}
	defer rows.Close()

	for rows.Next() {
		var a model.AffectedSoftware
		var vendor, product, version, versionEnd, cpe sql.NullString

		err := rows.Scan(&vendor, &product, &version, &versionEnd, &cpe)
		if err != nil {
			continue
		}

		if vendor.Valid {
			a.Vendor = vendor.String
		}

		if product.Valid {
			a.Product = product.String
		}

		if version.Valid {
			a.Version = version.String
		}

		if versionEnd.Valid {
			a.VersionEnd = versionEnd.String
		}

		if cpe.Valid {
			a.CPEs = []string{cpe.String}
		}

		affected = append(affected, a)
	}

	return affected, nil
}

// 检查版本是否受影响
func (vm *VersionMatcher) isVersionAffected(cve CVEWithAffected, targetVersion string) bool {
	// 如果没有版本信息，默认受影响
	if len(cve.AffectedSoftware) == 0 {
		return true
	}

	for _, affected := range cve.AffectedSoftware {
		if vm.matchVersion(affected, targetVersion) {
			return true
		}
	}

	return false
}

// 匹配版本
func (vm *VersionMatcher) matchVersion(affected model.AffectedSoftware, targetVersion string) bool {
	// 如果受影响软件没有版本限制，则匹配所有版本
	if affected.Version == "" && affected.VersionEnd == "" {
		return true
	}

	// 尝试解析目标版本
	targetVer := vm.parseVersion(targetVersion)
	if targetVer == nil {
		// 如果无法解析，使用字符串匹配
		return vm.matchVersionString(affected, targetVersion)
	}

	// 解析受影响版本
	startVer := vm.parseVersion(affected.Version)
	endVer := vm.parseVersion(affected.VersionEnd)

	// 检查版本是否在范围内
	if startVer != nil {
		if cmp := vm.compareVersions(targetVer, startVer); cmp < 0 {
			return false
		}
	}

	if endVer != nil {
		if cmp := vm.compareVersions(targetVer, endVer); cmp > 0 {
			return false
		}
	}

	return true
}

// 解析版本号
func (vm *VersionMatcher) parseVersion(version string) []int {
	if version == "" {
		return nil
	}

	// 提取数字部分
	re := regexp.MustCompile(`\d+`)
	matches := re.FindAllString(version, -1)

	var parts []int
	for _, match := range matches {
		num, err := strconv.Atoi(match)
		if err != nil {
			continue
		}
		parts = append(parts, num)
	}

	return parts
}

// 比较版本号
func (vm *VersionMatcher) compareVersions(v1, v2 []int) int {
	maxLen := len(v1)
	if len(v2) > maxLen {
		maxLen = len(v2)
	}

	for i := 0; i < maxLen; i++ {
		var num1, num2 int

		if i < len(v1) {
			num1 = v1[i]
		}

		if i < len(v2) {
			num2 = v2[i]
		}

		if num1 > num2 {
			return 1
		}
		if num1 < num2 {
			return -1
		}
	}

	return 0
}

// 字符串版本匹配
func (vm *VersionMatcher) matchVersionString(affected model.AffectedSoftware, targetVersion string) bool {
	// 检查目标版本是否以受影响版本开头
	if affected.Version != "" && strings.HasPrefix(targetVersion, affected.Version) {
		return true
	}

	// 检查是否在版本范围内（字符串比较）
	if affected.Version != "" && affected.VersionEnd != "" {
		if targetVersion >= affected.Version && targetVersion <= affected.VersionEnd {
			return true
		}
	}

	return false
}

// 转换CVE格式
func (vm *VersionMatcher) convertCVEDetail(cve CVEWithAffected) model.CVEDetail {
	detail := model.CVEDetail{
		CVEID:    cve.ID,
		Score:    cve.Score,
		Severity: cve.Severity,
		Summary:  cve.Description,
	}

	// 截断描述
	if len(detail.Summary) > 200 {
		detail.Summary = detail.Summary[:200] + "..."
	}

	// 添加参考链接
	detail.References = []model.Link{
		{
			Name: "NVD",
			URL:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.ID),
		},
		{
			Name: "CVE.org",
			URL:  fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", cve.ID),
		},
	}

	return detail
}

func (vm *VersionMatcher) convertToCVEDetails(cves []CVEWithAffected) []model.CVEDetail {
	var details []model.CVEDetail
	for _, cve := range cves {
		details = append(details, vm.convertCVEDetail(cve))
	}
	return details
}

// 以下方法与之前的cve_lookup.go类似
func (vm *VersionMatcher) getServiceKeywords(serviceName string) []string {
	keywordMap := map[string][]string{
		"mysql":      {"mysql", "mariadb", "database", "rdbms"},
		"postgresql": {"postgresql", "postgres", "database", "rdbms"},
		"redis":      {"redis", "database", "key-value"},
		"mongodb":    {"mongodb", "database", "nosql"},
		"http":       {"apache", "httpd", "http_server", "nginx", "iis", "http"},
		"https":      {"apache", "httpd", "http_server", "nginx", "iis", "https", "openssl"},
		"nginx":      {"nginx", "http", "https"},
		"apache":     {"apache", "httpd", "http_server"},
		"ssh":        {"ssh", "openssh"},
		"ftp":        {"ftp", "vsftpd", "proftpd"},
		"smtp":       {"smtp", "postfix", "exim", "sendmail"},
	}

	if keywords, found := keywordMap[strings.ToLower(serviceName)]; found {
		return keywords
	}

	return []string{strings.ToLower(serviceName)}
}

func (vm *VersionMatcher) buildCVEQuery(keywords []string) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	for _, keyword := range keywords {
		conditions = append(conditions, "(LOWER(a.product) LIKE ? OR LOWER(a.vendor) LIKE ?)")
		args = append(args, "%"+keyword+"%", "%"+keyword+"%")
	}

	query := fmt.Sprintf(`
		SELECT DISTINCT c.cve_id, c.description, c.cvss_score, c.cvss_severity
		FROM cves c
		JOIN affected_software a ON c.cve_id = a.cve_id
		WHERE (%s)
		ORDER BY c.cvss_score DESC
		LIMIT 50
	`, strings.Join(conditions, " OR "))

	return query, args
}

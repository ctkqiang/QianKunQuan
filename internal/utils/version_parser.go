package utils

import (
	"regexp"
	"strings"
)

// VersionParser 版本号解析器
type VersionParser struct{}

func NewVersionParser() *VersionParser {
	return &VersionParser{}
}

// NormalizeVersion 标准化版本号
func (vp *VersionParser) NormalizeVersion(version string) string {
	// 移除多余的空格和前缀
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "V")
	version = strings.TrimPrefix(version, "version")
	version = strings.TrimPrefix(version, "Version")
	version = strings.TrimSpace(version)

	// 提取数字和点号
	re := regexp.MustCompile(`[\d\.]+`)
	matches := re.FindAllString(version, -1)
	if len(matches) > 0 {
		return matches[0]
	}

	return version
}

// CompareVersions 比较版本号
func (vp *VersionParser) CompareVersions(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var num1, num2 int

		if i < len(parts1) {
			num1 = vp.parsePart(parts1[i])
		}

		if i < len(parts2) {
			num2 = vp.parsePart(parts2[i])
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

func (vp *VersionParser) parsePart(part string) int {
	// 提取数字部分
	re := regexp.MustCompile(`\d+`)
	match := re.FindString(part)
	if match == "" {
		return 0
	}

	var result int
	for _, ch := range match {
		result = result*10 + int(ch-'0')
	}

	return result
}

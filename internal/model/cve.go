package model

import "time"

// CVE 漏洞信息结构
type CVE struct {
	ID           string    `json:"id" db:"cve_id"`
	Description  string    `json:"description" db:"description"`
	CVSSScore    float64   `json:"cvss_score" db:"cvss_score"`
	CVSSSeverity string    `json:"cvss_severity" db:"cvss_severity"`
	Published    time.Time `json:"published" db:"published"`
	Modified     time.Time `json:"modified" db:"modified"`

	// 受影响的软件/服务
	AffectedSoftware []AffectedSoftware `json:"affected_software"`
}

// AffectedSoftware 受影响的软件
type AffectedSoftware struct {
	Vendor     string   `json:"vendor" db:"vendor"`
	Product    string   `json:"product" db:"product"`
	Version    string   `json:"version" db:"version"`
	VersionEnd string   `json:"version_end" db:"version_end"`
	CPEs       []string `json:"cpes"`
}

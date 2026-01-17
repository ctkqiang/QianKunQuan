package models

import "time"

type CVE struct {
	ID              string    `json:"id" db:"id"` // CVE-2021-34527
	Description     string    `json:"description" db:"description"`
	Severity        string    `json:"severity" db:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	CVSSScore       float64   `json:"cvss_score" db:"cvss_score"`
	CVSSVector      string    `json:"cvss_vector" db:"cvss_vector"`
	AffectedProduct string    `json:"affected_product" db:"affected_product"`
	AffectedVersion string    `json:"affected_version" db:"affected_version"`
	References      []string  `json:"references" db:"references"`
	PublishedDate   time.Time `json:"published_date" db:"published_date"`
	LastModified    time.Time `json:"last_modified" db:"last_modified"`
}

type Vulnerability struct {
	PortInfo    PortInfo `json:"port_info"`
	CVEs        []CVE    `json:"cves"`
	RiskLevel   string   `json:"risk_level"` // 高危, 中危, 低危
	Description string   `json:"description"`
	Solution    string   `json:"solution"`
}

type ServiceCVEMapping struct {
	ServiceName    string   `json:"service_name" db:"service_name"`
	ServiceVersion string   `json:"service_version" db:"service_version"`
	CVEIDs         []string `json:"cve_ids" db:"cve_ids"`
}

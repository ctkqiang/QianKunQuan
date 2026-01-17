package model

// ScanResult 扫描结果
type ScanResult struct {
	Target         string       `json:"target"`
	OriginalTarget string       `json:"original_target,omitempty"`
	HostStatus     string       `json:"host_status"`
	ScanTime       string       `json:"scan_time"`
	Ports          []PortResult `json:"ports"`
}

// PortResult 端口扫描结果
type PortResult struct {
	Port      int         `json:"port"`
	Protocol  string      `json:"protocol"`
	State     string      `json:"state"` // open, closed, filtered
	Service   ServiceInfo `json:"service"`
	Banner    string      `json:"banner"`
	CVEs      []CVEDetail `json:"cves"`
	RiskLevel string      `json:"risk_level"` // 基于CVSS评分
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Product string `json:"product"`
	Extra   string `json:"extra"`
}

// CVEDetail 端口相关的CVE详情
type CVEDetail struct {
	CVEID      string  `json:"cve_id"`
	Score      float64 `json:"score"`
	Severity   string  `json:"severity"`
	Summary    string  `json:"summary"`
	References []Link  `json:"references"`
}

// Link 参考链接
type Link struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// ScanOptions 扫描选项
type ScanOptions struct {
	Target       string
	PortRange    string
	Timeout      int
	Threads      int
	OutputFile   string
	OutputFormat string // json, text, csv
	UpdateDB     bool
	Verbose      bool
}

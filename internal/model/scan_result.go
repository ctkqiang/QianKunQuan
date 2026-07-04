package model

import "time"

type ScanResult struct {
	Target         string       `json:"target"`
	OriginalTarget string       `json:"original_target,omitempty"`
	HostStatus     string       `json:"host_status"`
	ScanTime       string       `json:"scan_time"`
	Ports          []PortResult `json:"ports"`
}

type PortResult struct {
	Port      int         `json:"port"`
	Protocol  string      `json:"protocol"`
	State     string      `json:"state"`
	Service   ServiceInfo `json:"service"`
	Banner    string      `json:"banner"`
	CVEs      []CVEDetail `json:"cves"`
	RiskLevel string      `json:"risk_level"`
}

type ServiceInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Product string `json:"product"`
	Extra   string `json:"extra"`
}

type CVEDetail struct {
	CVEID       string   `json:"cve_id"`
	CNVDID      string   `json:"cnvd_id,omitempty"`
	CNNVDID     string   `json:"cnnvd_id,omitempty"`
	Score       float64  `json:"score"`
	Severity    string   `json:"severity"`
	Summary     string   `json:"summary"`
	References  []Link   `json:"references"`
	ATTACK      []string `json:"attack_tactics,omitempty"`
	HasPOC      bool     `json:"has_poc"`
	HasEXP      bool     `json:"has_exp"`
	POCLinks    []string `json:"poc_links,omitempty"`
}

type Link struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type ScanOptions struct {
	Target       string
	PortRange    string
	Timeout      int
	Threads      int
	OutputFile   string
	OutputFormat string
	UpdateDB     bool
	Verbose      bool
	ScanMode     string
}

type WebScanResult struct {
	Target       string            `json:"target"`
	ScanTime     string            `json:"scan_time"`
	URLs         []DirResult       `json:"urls"`
	CMS          string            `json:"cms"`
	CMSVersion   string            `json:"cms_version"`
	WAF          string            `json:"waf"`
	Server       string            `json:"server"`
	TechStack    []string          `json:"tech_stack"`
	Headers      map[string]string `json:"headers"`
	Title        string            `json:"title"`
	StatusCode   int               `json:"status_code"`
	Subdomains   []SubdomainResult `json:"subdomains,omitempty"`
}

type DirResult struct {
	URL        string `json:"url"`
	Path       string `json:"path"`
	StatusCode int    `json:"status_code"`
	Length     int    `json:"length"`
	Title      string `json:"title"`
	ContentType string `json:"content_type"`
}

type SubdomainResult struct {
	Subdomain string `json:"subdomain"`
	IP        string `json:"ip,omitempty"`
	Alive     bool   `json:"alive"`
	Source    string `json:"source"`
}

type AttackPath struct {
	Phase       string   `json:"phase"`
	Technique   string   `json:"technique"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
	Tools       []string `json:"tools"`
	Risk        string   `json:"risk"`
	References  []string `json:"references,omitempty"`
}

type RedTeamReport struct {
	Target       string         `json:"target"`
	ReportTime   time.Time      `json:"report_time"`
	OverallRisk  string         `json:"overall_risk"`
	Summary      ReportSummary  `json:"summary"`
	PortScan     *ScanResult    `json:"port_scan,omitempty"`
	WebScan      *WebScanResult `json:"web_scan,omitempty"`
	AttackPaths  []AttackPath   `json:"attack_paths"`
	CriticalHits []CriticalHit  `json:"critical_hits"`
	Recommendations []string    `json:"recommendations"`
}

type ReportSummary struct {
	OpenPorts    int `json:"open_ports"`
	VulnCount    int `json:"vuln_count"`
	CriticalVuln int `json:"critical_vuln"`
	HighVuln     int `json:"high_vuln"`
	MediumVuln   int `json:"medium_vuln"`
	LowVuln      int `json:"low_vuln"`
	AttackPaths  int `json:"attack_paths"`
}

type CriticalHit struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Evidence    string `json:"evidence"`
}

type VulnRef struct {
	CVEID    string
	CNVDID   string
	Type     string
	POCLink  string
	EXPLink  string
	Tactics  []string
}

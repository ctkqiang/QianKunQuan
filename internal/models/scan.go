package models

import "time"

type ScanType string

const (
	TCPScan  ScanType = "tcp"
	UDPScan  ScanType = "udp"
	FullScan ScanType = "full"
)

type ScanRequest struct {
	ID          string    `json:"id" db:"id"`
	TargetIP    string    `json:"target_ip" db:"target_ip"`
	TargetRange string    `json:"target_range" db:"target_range"`
	Ports       string    `json:"ports" db:"ports"` // "80,443,1-1000"
	ScanType    ScanType  `json:"scan_type" db:"scan_type"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	Status      string    `json:"status" db:"status"` // pending, running, completed, failed
}

type ScanResult struct {
	ID              string          `json:"id" db:"id"`
	ScanID          string          `json:"scan_id" db:"scan_id"`
	IPAddress       string          `json:"ip_address" db:"ip_address"`
	Hostname        string          `json:"hostname" db:"hostname"`
	OpenPorts       []PortInfo      `json:"open_ports" db:"open_ports"`
	OSGuess         string          `json:"os_guess" db:"os_guess"`
	ScanTime        time.Time       `json:"scan_time" db:"scan_time"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type PortInfo struct {
	Port     int    `json:"port" db:"port"`
	Protocol string `json:"protocol" db:"protocol"` // tcp, udp
	State    string `json:"state" db:"state"`       // open, closed, filtered
	Service  string `json:"service" db:"service"`   // http, ssh, ftp
	Version  string `json:"version" db:"version"`
	Banner   string `json:"banner" db:"banner"`
}

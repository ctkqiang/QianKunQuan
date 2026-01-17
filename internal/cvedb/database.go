package cvedb

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

type Database struct {
	db     *sql.DB
	logger *logrus.Logger
}

func NewDatabase(dbPath string) (*Database, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("数据库连接失败: %v", err)
	}

	if err := createTables(db); err != nil {
		return nil, err
	}

	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	return &Database{db: db, logger: logger}, nil
}

func createTables(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS cve_records (
            id TEXT PRIMARY KEY,
            description TEXT,
            severity TEXT,
            cvss_score REAL,
            cvss_vector TEXT,
            affected_product TEXT,
            affected_version TEXT,
            references TEXT,
            published_date DATETIME,
            last_modified DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,

		`CREATE TABLE IF NOT EXISTS service_cve_mapping (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT,
            service_version TEXT,
            cve_id TEXT,
            port_range TEXT,
            FOREIGN KEY (cve_id) REFERENCES cve_records(id)
        )`,

		`CREATE TABLE IF NOT EXISTS scan_history (
            id TEXT PRIMARY KEY,
            target_ip TEXT,
            target_range TEXT,
            ports TEXT,
            scan_type TEXT,
            status TEXT,
            start_time DATETIME,
            end_time DATETIME,
            results TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`,

		`CREATE INDEX IF NOT EXISTS idx_cve_product ON cve_records(affected_product)`,
		`CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_records(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_service_mapping ON service_cve_mapping(service_name, service_version)`,
	}

	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("创建表失败: %v, 查询: %s", err, query)
		}
	}

	return nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

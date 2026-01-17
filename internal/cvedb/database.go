package cvedb

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"QianKunQuan/internal/utils"

	_ "github.com/mattn/go-sqlite3"
)

type CVEDatabase struct {
	db     *sql.DB
	path   string
	logger *utils.Logger
}

func NewCVEDatabase(dbPath string) (*CVEDatabase, error) {
	logger := utils.NewLogger("cvedb")

	// 确保目录存在
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %v", err)
	}

	cvedb := &CVEDatabase{
		db:     db,
		path:   dbPath,
		logger: logger,
	}

	// 初始化表
	if err := cvedb.initTables(); err != nil {
		return nil, err
	}

	return cvedb, nil
}

func (cd *CVEDatabase) initTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS cves (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cve_id TEXT UNIQUE NOT NULL,
		description TEXT,
		cvss_score REAL,
		cvss_severity TEXT,
		published DATE,
		modified DATE
	);
	
	CREATE TABLE IF NOT EXISTS affected_software (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cve_id TEXT,
		vendor TEXT,
		product TEXT,
		version TEXT,
		version_end TEXT,
		cpe TEXT,
		FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
	);
	
	CREATE INDEX IF NOT EXISTS idx_product ON affected_software(product);
	CREATE INDEX IF NOT EXISTS idx_cve_id ON cves(cve_id);
	`

	_, err := cd.db.Exec(schema)
	return err
}

func (cd *CVEDatabase) Close() error {
	return cd.db.Close()
}

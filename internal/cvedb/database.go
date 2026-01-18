package cvedb

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"QianKunQuan/internal/model"
	"QianKunQuan/internal/utils"

	_ "github.com/mattn/go-sqlite3"
)

type CVEDatabase struct {
	db         *sql.DB
	path       string
	logger     *utils.Logger
	downloader *CVEDownloader
}

func NewCVEDatabase(dbPath string) (*CVEDatabase, error) {
	logger := utils.NewLogger("cvedb")

	// 确保目录存在
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %v", err)
	}

	// 确保feeds目录存在
	feedsDir := filepath.Join(dir, "feeds")
	if err := os.MkdirAll(feedsDir, 0755); err != nil {
		return nil, fmt.Errorf("创建feeds目录失败: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %v", err)
	}

	cvedb := &CVEDatabase{
		db:         db,
		path:       dbPath,
		logger:     logger,
		downloader: NewCVEDownloader(),
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
		modified DATE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS affected_software (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cve_id TEXT NOT NULL,
		vendor TEXT,
		product TEXT,
		version TEXT,
		version_end TEXT,
		cpe TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
	);
	
	CREATE INDEX IF NOT EXISTS idx_product ON affected_software(product);
	CREATE INDEX IF NOT EXISTS idx_vendor ON affected_software(vendor);
	CREATE INDEX IF NOT EXISTS idx_cve_product ON affected_software(cve_id, product);
	
	CREATE TABLE IF NOT EXISTS update_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		source TEXT,
		records_added INTEGER
	);
	`

	_, err := cd.db.Exec(schema)
	return err
}

// InsertCVE 插入CVE数据到数据库
func (cd *CVEDatabase) InsertCVE(cve model.CVE) error {
	tx, err := cd.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 插入CVE基本信息
	_, err = tx.Exec(`
		INSERT OR REPLACE INTO cves 
		(cve_id, description, cvss_score, cvss_severity, published, modified)
		VALUES (?, ?, ?, ?, ?, ?)`,
		cve.ID, cve.Description, cve.CVSSScore, cve.CVSSSeverity,
		cve.Published, cve.Modified,
	)
	if err != nil {
		return err
	}

	// 插入受影响软件
	for _, software := range cve.AffectedSoftware {
		for _, cpe := range software.CPEs {
			_, err = tx.Exec(`
				INSERT OR REPLACE INTO affected_software 
				(cve_id, vendor, product, version, version_end, cpe)
				VALUES (?, ?, ?, ?, ?, ?)`,
				cve.ID, software.Vendor, software.Product,
				software.Version, software.VersionEnd, cpe,
			)
			if err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

// HasData 检查数据库中是否有数据
func (cd *CVEDatabase) HasData() (bool, error) {
	var count int
	err := cd.db.QueryRow("SELECT COUNT(*) FROM cves").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetCveCount 获取CVE总数
func (cd *CVEDatabase) GetCveCount() (int, error) {
	var count int
	err := cd.db.QueryRow("SELECT COUNT(*) FROM cves").Scan(&count)
	return count, err
}

// UpdateDatabase 更新CVE数据库
func (cd *CVEDatabase) UpdateDatabase() error {
	cd.logger.Info("开始更新CVE数据库...")

	// 下载CVE数据
	if err := cd.downloader.DownloadFeeds(); err != nil {
		cd.logger.Error("下载CVE数据失败: %v", err)
		return err
	}

	// 解析并存储到数据库
	if err := cd.downloader.ParseAndStore(cd); err != nil {
		cd.logger.Error("解析存储CVE数据失败: %v", err)
		return err
	}

	// 记录更新历史
	count, _ := cd.GetCveCount()
	_, err := cd.db.Exec(`
		INSERT INTO update_history (source, records_added)
		VALUES (?, ?)`,
		"NVD JSON Feed", count,
	)

	if err != nil {
		cd.logger.Error("记录更新历史失败: %v", err)
	}

	cd.logger.Info("CVE数据库更新完成，总计 %d 个记录", count)
	return nil
}

// GetUpdateHistory 获取更新历史
func (cd *CVEDatabase) GetUpdateHistory() ([]map[string]interface{}, error) {
	rows, err := cd.db.Query(`
		SELECT id, last_update, source, records_added
		FROM update_history
		ORDER BY last_update DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []map[string]interface{}
	for rows.Next() {
		var id, recordsAdded int
		var lastUpdate, source string

		err := rows.Scan(&id, &lastUpdate, &source, &recordsAdded)
		if err != nil {
			continue
		}

		history = append(history, map[string]interface{}{
			"id":            id,
			"last_update":   lastUpdate,
			"source":        source,
			"records_added": recordsAdded,
		})
	}

	return history, nil
}

func (cd *CVEDatabase) Close() error {
	return cd.db.Close()
}

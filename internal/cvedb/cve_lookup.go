package cvedb

import (
	"fmt"
	"strings"

	"QianKunQuan/internal/model"
)

func (cd *CVEDatabase) LookupCVEs(service model.ServiceInfo) ([]model.CVEDetail, error) {
	var cves []model.CVEDetail

	query := `
	SELECT c.cve_id, c.description, c.cvss_score, c.cvss_severity
	FROM cves c
	JOIN affected_software a ON c.cve_id = a.cve_id
	WHERE LOWER(a.product) LIKE ? 
	AND (a.version = ? OR a.version = '' OR a.version = 'ANY')
	ORDER BY c.cvss_score DESC
	LIMIT 10
	`

	productPattern := "%" + strings.ToLower(service.Product) + "%"
	if service.Product == "" {
		productPattern = "%" + strings.ToLower(service.Name) + "%"
	}

	rows, err := cd.db.Query(query, productPattern, service.Version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var cve model.CVEDetail
		var description string

		err := rows.Scan(&cve.CVEID, &description, &cve.Score, &cve.Severity)
		if err != nil {
			continue
		}

		// 截断过长的描述
		if len(description) > 200 {
			cve.Summary = description[:200] + "..."
		} else {
			cve.Summary = description
		}

		// 添加参考链接
		cve.References = []model.Link{
			{Name: "NVD", URL: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve.CVEID)},
			{Name: "CVE Details", URL: fmt.Sprintf("https://www.cvedetails.com/cve/%s/", cve.CVEID)},
		}

		cves = append(cves, cve)
	}

	return cves, nil
}

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
				INSERT INTO affected_software 
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

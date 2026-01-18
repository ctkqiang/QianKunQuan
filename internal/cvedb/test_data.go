package cvedb

import (
	"time"

	"QianKunQuan/internal/model"
)

// InitTestData 初始化测试数据
func (cd *CVEDatabase) InitTestData() error {
	cd.logger.Info("初始化测试CVE数据...")

	// 测试CVE数据
	testCVEs := []model.CVE{
		{
			ID:           "CVE-2021-23017",
			Description:  "Nginx DNS解析漏洞，可导致拒绝服务攻击",
			CVSSScore:    7.5,
			CVSSSeverity: "HIGH",
			Published:    time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC),
			Modified:     time.Date(2021, 6, 15, 0, 0, 0, 0, time.UTC),
			AffectedSoftware: []model.AffectedSoftware{
				{
					Vendor:     "Nginx",
					Product:    "nginx",
					Version:    "0.6.18",
					VersionEnd: "1.20.0",
					CPEs:       []string{"cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"},
				},
			},
		},
		{
			ID:           "CVE-2021-40438",
			Description:  "Apache HTTP Server 请求走私漏洞",
			CVSSScore:    8.2,
			CVSSSeverity: "HIGH",
			Published:    time.Date(2021, 9, 16, 0, 0, 0, 0, time.UTC),
			Modified:     time.Date(2021, 9, 24, 0, 0, 0, 0, time.UTC),
			AffectedSoftware: []model.AffectedSoftware{
				{
					Vendor:     "Apache",
					Product:    "http_server",
					Version:    "2.4.48",
					VersionEnd: "2.4.48",
					CPEs:       []string{"cpe:2.3:a:apache:http_server:2.4.48:*:*:*:*:*:*:*"},
				},
			},
		},
		{
			ID:           "CVE-2022-3602",
			Description:  "OpenSSL X.509证书验证漏洞",
			CVSSScore:    9.8,
			CVSSSeverity: "CRITICAL",
			Published:    time.Date(2022, 11, 1, 0, 0, 0, 0, time.UTC),
			Modified:     time.Date(2022, 11, 8, 0, 0, 0, 0, time.UTC),
			AffectedSoftware: []model.AffectedSoftware{
				{
					Vendor:     "OpenSSL",
					Product:    "openssl",
					Version:    "3.0.0",
					VersionEnd: "3.0.6",
					CPEs:       []string{"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"},
				},
			},
		},
	}

	// 插入测试数据
	successCount := 0
	for _, cve := range testCVEs {
		err := cd.InsertCVE(cve)
		if err != nil {
			cd.logger.Error("插入CVE失败 %s: %v", cve.ID, err)
		} else {
			successCount++
			cd.logger.Debug("插入CVE: %s", cve.ID)
		}
	}

	cd.logger.Info("测试CVE数据初始化完成，成功插入 %d 个CVE记录", successCount)
	return nil
}

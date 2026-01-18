package cvedb

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"QianKunQuan/internal/model"
	"QianKunQuan/internal/utils"
)

// BulkCVEUpdater 批量更新CVE数据库（从2025年到当前）
type BulkCVEUpdater struct {
	baseURL    string
	localDir   string
	logger     *utils.Logger
	httpClient *http.Client
}

func NewBulkCVEUpdater() *BulkCVEUpdater {
	return &BulkCVEUpdater{
		baseURL:  "https://nvd.nist.gov/feeds/json/cve/1.1/",
		localDir: "database/nvd_feeds",
		logger:   utils.NewLogger("bulk-updater"),
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

// UpdateFrom2025ToCurrent 从2025年更新到当前年份
func (bu *BulkCVEUpdater) UpdateFrom2025ToCurrent(db *CVEDatabase) error {
	bu.logger.Info("开始更新CVE数据库（从2025年到当前）...")

	// 创建目录
	if err := os.MkdirAll(bu.localDir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	// 获取需要下载的年份
	years := bu.getYearsToDownload()

	totalCVEs := 0
	for _, year := range years {
		filename := fmt.Sprintf("nvdcve-1.1-%d.json.zip", year)
		url := bu.baseURL + filename
		localPath := filepath.Join(bu.localDir, filename)

		bu.logger.Info("下载 %d 年CVE数据...", year)

		// 下载文件
		if err := bu.downloadFile(url, localPath); err != nil {
			bu.logger.Warn("下载 %d 年数据失败: %v", year, err)
			continue
		}

		// 解析并存储
		count, err := bu.parseAndStore(db, localPath)
		if err != nil {
			bu.logger.Warn("解析 %d 年数据失败: %v", year, err)
			continue
		}

		totalCVEs += count
		bu.logger.Info("%d 年数据导入完成: %d 个CVE", year, count)
	}

	// 同时下载最近更新的数据
	bu.logger.Info("下载最近更新的CVE数据...")
	recentFiles := []string{
		"nvdcve-1.1-modified.json.zip",
		"nvdcve-1.1-recent.json.zip",
	}

	for _, filename := range recentFiles {
		url := bu.baseURL + filename
		localPath := filepath.Join(bu.localDir, filename)

		if err := bu.downloadFile(url, localPath); err != nil {
			bu.logger.Warn("下载 %s 失败: %v", filename, err)
			continue
		}

		count, err := bu.parseAndStore(db, localPath)
		if err != nil {
			bu.logger.Warn("解析 %s 失败: %v", filename, err)
			continue
		}

		totalCVEs += count
		bu.logger.Info("%s 导入完成: %d 个CVE", filename, count)
	}

	bu.logger.Info("CVE数据库更新完成，总计 %d 个CVE记录", totalCVEs)
	return nil
}

// 获取需要下载的年份（从2025年到当前年份）
func (bu *BulkCVEUpdater) getYearsToDownload() []int {
	startYear := 2025
	currentYear := time.Now().Year()

	var years []int
	for year := startYear; year <= currentYear; year++ {
		years = append(years, year)
	}

	return years
}

// 下载文件
func (bu *BulkCVEUpdater) downloadFile(url, localPath string) error {
	// 检查文件是否已存在
	if _, err := os.Stat(localPath); err == nil {
		bu.logger.Debug("文件已存在，跳过下载: %s", localPath)
		return nil
	}

	// 发起HTTP请求
	resp, err := bu.httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP错误: %s", resp.Status)
	}

	// 创建文件
	out, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer out.Close()

	// 复制内容
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	return nil
}

// 解析并存储CVE数据
func (bu *BulkCVEUpdater) parseAndStore(db *CVEDatabase, zipPath string) (int, error) {
	// 检查文件是否存在
	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		return 0, fmt.Errorf("文件不存在: %s", zipPath)
	}

	// 解压文件
	jsonData, err := bu.extractZip(zipPath)
	if err != nil {
		return 0, err
	}

	// 解析JSON
	var cveData struct {
		CVEItems []struct {
			CVE struct {
				ID          string `json:"id"`
				Description struct {
					Data []struct {
						Value string `json:"value"`
					} `json:"description_data"`
				} `json:"description"`
			} `json:"cve"`
			Impact struct {
				BaseMetricV3 struct {
					CVSSV3 struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssV3"`
				} `json:"baseMetricV3"`
			} `json:"impact"`
			Configurations struct {
				Nodes []struct {
					CpeMatch []struct {
						Vulnerable bool   `json:"vulnerable"`
						Criteria   string `json:"criteria"`
					} `json:"cpe_match"`
				} `json:"nodes"`
			} `json:"configurations"`
			PublishedDate    string `json:"publishedDate"`
			LastModifiedDate string `json:"lastModifiedDate"`
		} `json:"CVE_Items"`
	}

	if err := json.Unmarshal(jsonData, &cveData); err != nil {
		return 0, err
	}

	// 存储到数据库
	count := 0
	for _, item := range cveData.CVEItems {
		cve := model.CVE{
			ID:           item.CVE.ID,
			Description:  item.CVE.Description.Data[0].Value,
			CVSSScore:    item.Impact.BaseMetricV3.CVSSV3.BaseScore,
			CVSSSeverity: item.Impact.BaseMetricV3.CVSSV3.BaseSeverity,
		}

		// 解析日期
		if published, err := time.Parse("2006-01-02T15:04:05.000", item.PublishedDate); err == nil {
			cve.Published = published
		}

		if modified, err := time.Parse("2006-01-02T15:04:05.000", item.LastModifiedDate); err == nil {
			cve.Modified = modified
		}

		// 提取受影响的软件
		for _, node := range item.Configurations.Nodes {
			for _, cpe := range node.CpeMatch {
				if cpe.Vulnerable {
					// 解析CPE字符串
					parts := strings.Split(cpe.Criteria, ":")
					if len(parts) >= 5 {
						software := model.AffectedSoftware{
							Vendor:  parts[3],
							Product: parts[4],
							CPEs:    []string{cpe.Criteria},
						}

						// 提取版本信息
						if len(parts) > 5 && parts[5] != "*" {
							software.Version = parts[5]
						}

						cve.AffectedSoftware = append(cve.AffectedSoftware, software)
					}
				}
			}
		}

		// 插入数据库
		if err := db.InsertCVE(cve); err != nil {
			bu.logger.Debug("插入CVE失败 %s: %v", cve.ID, err)
		} else {
			count++
		}

		// 每1000条显示一次进度
		if count%1000 == 0 {
			bu.logger.Info("已导入 %d 条CVE记录...", count)
		}
	}

	return count, nil
}

// 解压ZIP文件
func (bu *BulkCVEUpdater) extractZip(zipPath string) ([]byte, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	for _, f := range r.File {
		if strings.HasSuffix(f.Name, ".json") {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()

			content, err := io.ReadAll(rc)
			if err != nil {
				return nil, err
			}

			return content, nil
		}
	}

	return nil, fmt.Errorf("未找到JSON文件")
}

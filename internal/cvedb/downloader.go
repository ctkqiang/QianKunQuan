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

type CVEDownloader struct {
	baseURL    string
	localDir   string
	logger     *utils.Logger
	httpClient *http.Client
}

func NewCVEDownloader() *CVEDownloader {
	return &CVEDownloader{
		baseURL:  "https://nvd.nist.gov/feeds/json/cve/1.1/",
		localDir: "database/feeds",
		logger:   utils.NewLogger("cve-downloader"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CVE JSON格式（根据CVE.org规范）
type CVERecord struct {
	CVEItems []struct {
		CVE struct {
			DataType    string `json:"data_type"`
			DataFormat  string `json:"data_format"`
			DataVersion string `json:"data_version"`
			CVEDataMeta struct {
				ID       string `json:"ID"`
				ASSIGNER string `json:"ASSIGNER"`
			} `json:"CVE_data_meta"`
			Problemtype struct {
				ProblemtypeData []struct {
					Description []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description"`
				} `json:"problemtype_data"`
			} `json:"problemtype"`
			References struct {
				ReferenceData []struct {
					URL string `json:"url"`
				} `json:"reference_data"`
			} `json:"references"`
			Description struct {
				DescriptionData []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
		} `json:"cve"`
		Impact struct {
			BaseMetricV3 struct {
				CVSSV3 struct {
					Version               string  `json:"version"`
					VectorString          string  `json:"vectorString"`
					AttackVector          string  `json:"attackVector"`
					AttackComplexity      string  `json:"attackComplexity"`
					PrivilegesRequired    string  `json:"privilegesRequired"`
					UserInteraction       string  `json:"userInteraction"`
					Scope                 string  `json:"scope"`
					ConfidentialityImpact string  `json:"confidentialityImpact"`
					IntegrityImpact       string  `json:"integrityImpact"`
					AvailabilityImpact    string  `json:"availabilityImpact"`
					BaseScore             float64 `json:"baseScore"`
					BaseSeverity          string  `json:"baseSeverity"`
				} `json:"cvssV3"`
			} `json:"baseMetricV3"`
			BaseMetricV2 struct {
				CVSSV2 struct {
					Version               string  `json:"version"`
					VectorString          string  `json:"vectorString"`
					AccessVector          string  `json:"accessVector"`
					AccessComplexity      string  `json:"accessComplexity"`
					Authentication        string  `json:"authentication"`
					ConfidentialityImpact string  `json:"confidentialityImpact"`
					IntegrityImpact       string  `json:"integrityImpact"`
					AvailabilityImpact    string  `json:"availabilityImpact"`
					BaseScore             float64 `json:"baseScore"`
				} `json:"cvssV2"`
				Severity                string `json:"severity"`
				ExploitabilityScore     string `json:"exploitabilityScore"`
				ImpactScore             string `json:"impactScore"`
				ObtainAllPrivilege      bool   `json:"obtainAllPrivilege"`
				ObtainUserPrivilege     bool   `json:"obtainUserPrivilege"`
				ObtainOtherPrivilege    bool   `json:"obtainOtherPrivilege"`
				UserInteractionRequired bool   `json:"userInteractionRequired"`
			} `json:"baseMetricV2"`
		} `json:"impact"`
		Configurations struct {
			Nodes []struct {
				Operator string `json:"operator"`
				CpeMatch []struct {
					Vulnerable      bool   `json:"vulnerable"`
					Criteria        string `json:"criteria"`
					MatchCriteriaID string `json:"matchCriteriaId"`
				} `json:"cpe_match"`
			} `json:"nodes"`
		} `json:"configurations"`
		PublishedDate    string `json:"publishedDate"`
		LastModifiedDate string `json:"lastModifiedDate"`
	} `json:"CVE_Items"`
}

// 获取CVE数据源列表
func (cd *CVEDownloader) GetFeedList() []string {
	return []string{
		"nvdcve-1.1-modified.json.zip",
		"nvdcve-1.1-recent.json.zip",
		"nvdcve-1.1-2023.json.zip",
		"nvdcve-1.1-2022.json.zip",
		"nvdcve-1.1-2021.json.zip",
		"nvdcve-1.1-2020.json.zip",
	}
}

// 下载CVE数据
func (cd *CVEDownloader) DownloadFeeds() error {
	// 创建目录
	if err := os.MkdirAll(cd.localDir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	feeds := cd.GetFeedList()

	for _, feed := range feeds {
		url := cd.baseURL + feed
		localPath := filepath.Join(cd.localDir, feed)

		cd.logger.Info("下载CVE数据: %s", feed)

		// 下载文件
		if err := cd.downloadFile(url, localPath); err != nil {
			cd.logger.Error("下载失败 %s: %v", feed, err)
			continue
		}

		cd.logger.Info("下载完成: %s", feed)
	}

	return nil
}

// 下载单个文件
func (cd *CVEDownloader) downloadFile(url, localPath string) error {
	// 发起HTTP请求
	resp, err := cd.httpClient.Get(url)
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

// 解压并解析CVE数据
func (cd *CVEDownloader) ParseAndStore(db *CVEDatabase) error {
	cd.logger.Info("开始解析CVE数据...")

	feeds := cd.GetFeedList()
	totalCVEs := 0

	for _, feed := range feeds {
		zipPath := filepath.Join(cd.localDir, feed)

		// 检查文件是否存在
		if _, err := os.Stat(zipPath); os.IsNotExist(err) {
			cd.logger.Warn("文件不存在: %s", zipPath)
			continue
		}

		// 解压文件
		jsonData, err := cd.extractZip(zipPath)
		if err != nil {
			cd.logger.Error("解压失败 %s: %v", feed, err)
			continue
		}

		// 解析JSON
		var cveRecord CVERecord
		if err := json.Unmarshal(jsonData, &cveRecord); err != nil {
			cd.logger.Error("解析JSON失败 %s: %v", feed, err)
			continue
		}

		// 存储到数据库
		count := cd.storeCVEs(db, &cveRecord)
		totalCVEs += count
		cd.logger.Info("从 %s 导入 %d 个CVE记录", feed, count)
	}

	cd.logger.Info("CVE数据导入完成，总计 %d 个记录", totalCVEs)
	return nil
}

// 解压ZIP文件
func (cd *CVEDownloader) extractZip(zipPath string) ([]byte, error) {
	// 打开ZIP文件
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	// 读取第一个文件（应该是JSON文件）
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, ".json") {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()

			// 读取所有内容
			content, err := io.ReadAll(rc)
			if err != nil {
				return nil, err
			}

			return content, nil
		}
	}

	return nil, fmt.Errorf("未找到JSON文件")
}

// 存储CVE数据到数据库
func (cd *CVEDownloader) storeCVEs(db *CVEDatabase, record *CVERecord) int {
	count := 0

	for _, item := range record.CVEItems {
		// 提取基本信息
		cveID := item.CVE.CVEDataMeta.ID
		description := ""
		if len(item.CVE.Description.DescriptionData) > 0 {
			description = item.CVE.Description.DescriptionData[0].Value
		}

		// 提取CVSS分数
		cvssScore := 0.0
		cvssSeverity := "UNKNOWN"

		// 优先使用CVSS v3
		if item.Impact.BaseMetricV3.CVSSV3.BaseScore > 0 {
			cvssScore = item.Impact.BaseMetricV3.CVSSV3.BaseScore
			cvssSeverity = item.Impact.BaseMetricV3.CVSSV3.BaseSeverity
		} else if item.Impact.BaseMetricV2.CVSSV2.BaseScore > 0 {
			cvssScore = item.Impact.BaseMetricV2.CVSSV2.BaseScore
			cvssSeverity = item.Impact.BaseMetricV2.Severity
		}

		// 解析发布日期
		published, _ := time.Parse("2006-01-02T15:04:05", item.PublishedDate)
		modified, _ := time.Parse("2006-01-02T15:04:05", item.LastModifiedDate)

		// 创建CVE模型
		cve := model.CVE{
			ID:           cveID,
			Description:  description,
			CVSSScore:    cvssScore,
			CVSSSeverity: cvssSeverity,
			Published:    published,
			Modified:     modified,
		}

		// 提取受影响的软件
		for _, node := range item.Configurations.Nodes {
			for _, cpe := range node.CpeMatch {
				if cpe.Vulnerable {
					// 解析CPE字符串
					parts := strings.Split(cpe.Criteria, ":")
					if len(parts) >= 5 {
						vendor := parts[3]
						product := parts[4]

						// 清理产品名称
						if product == "*" {
							product = ""
						}

						// 提取版本信息
						version := ""
						if len(parts) > 5 {
							version = parts[5]
							if version == "*" {
								version = ""
							}
						}

						// 添加受影响软件
						software := model.AffectedSoftware{
							Vendor:  vendor,
							Product: product,
							Version: version,
							CPEs:    []string{cpe.Criteria},
						}

						cve.AffectedSoftware = append(cve.AffectedSoftware, software)
					}
				}
			}
		}

		// 插入数据库
		if err := db.InsertCVE(cve); err != nil {
			cd.logger.Debug("插入CVE失败 %s: %v", cveID, err)
		} else {
			count++
		}
	}

	return count
}

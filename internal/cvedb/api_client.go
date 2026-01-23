package cvedb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"QianKunQuan/internal/model"
	"QianKunQuan/internal/utils"
)

// CVEAPIClient 用于从NVD API获取CVE数据的客户端
type CVEAPIClient struct {
	baseURL    string
	logger     *utils.Logger
	httpClient *http.Client
}

// NewCVEAPIClient 创建新的CVE API客户端
func NewCVEAPIClient() *CVEAPIClient {
	return &CVEAPIClient{
		baseURL: "https://services.nvd.nist.gov/rest/json/cves/2.0",
		logger:  utils.NewLogger("cve-api-client"),
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableCompression:  false,
				MaxIdleConnsPerHost: 10,
			},
		},
	}
}

// NVD API响应结构
type NVDResponse struct {
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
	TotalResults    int                `json:"totalResults"`
	Vulnerabilities []NVDVulnerability `json:"vulnerabilities"`
}

// NVD漏洞数据结构
type NVDVulnerability struct {
	CVE struct {
		ID               string `json:"id"`
		SourceIdentifier string `json:"sourceIdentifier"`
		Published        string `json:"published"`
		LastModified     string `json:"lastModified"`
		VulnStatus       string `json:"vulnStatus"`
		Descriptions     []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			CvssMetricV31 []struct {
				CvssData struct {
					Version      string  `json:"version"`
					Vector       string  `json:"vectorString"`
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
			CvssMetricV30 []struct {
				CvssData struct {
					Version      string  `json:"version"`
					Vector       string  `json:"vectorString"`
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"cvssMetricV30"`
			CvssMetricV2 []struct {
				CvssData struct {
					Version   string  `json:"version"`
					Vector    string  `json:"vectorString"`
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssData"`
				BaseSeverity string `json:"baseSeverity"`
			} `json:"cvssMetricV2"`
		} `json:"metrics"`
		Weaknesses []struct {
			Source      string `json:"source"`
			Type        string `json:"type"`
			Description []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description"`
		} `json:"weaknesses"`
		Configurations []struct {
			Nodes []struct {
				Operator string `json:"operator"`
				CpeMatch []struct {
					Vulnerable      bool   `json:"vulnerable"`
					Criteria        string `json:"criteria"`
					MatchCriteriaId string `json:"matchCriteriaId"`
				} `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"cve"`
}

// FetchCVEsByYearRange 获取指定年份范围的CVE数据
func (client *CVEAPIClient) FetchCVEsByYearRange(startYear, endYear int) ([]model.CVE, error) {
	var allCVEs []model.CVE

	for year := startYear; year <= endYear; year++ {
		client.logger.Info("开始获取 %d 年CVE数据...", year)

		// 获取该年份的所有CVE（处理分页）
		yearCVEs, err := client.fetchCVEsForYear(year)
		if err != nil {
			client.logger.Error("获取 %d 年CVE数据失败: %v", year, err)
			continue
		}

		allCVEs = append(allCVEs, yearCVEs...)
		client.logger.Info("%d 年获取完成: %d 个CVE", year, len(yearCVEs))

		// 避免速率限制，每请求一次后暂停一下
		time.Sleep(2 * time.Second)
	}

	client.logger.Info("总计获取 %d 个CVE数据 (%d-%d)", len(allCVEs), startYear, endYear)
	return allCVEs, nil
}

// fetchCVEsForYear 获取单个年份的CVE数据（处理分页）
func (client *CVEAPIClient) fetchCVEsForYear(year int) ([]model.CVE, error) {
	var yearCVEs []model.CVE
	startIndex := 0
	resultsPerPage := 2000

	for {
		url := fmt.Sprintf("%s?pubStartDate=%d-01-01T00:00:00.000&pubEndDate=%d-12-31T23:59:59.999&startIndex=%d&resultsPerPage=%d",
			client.baseURL, year, year, startIndex, resultsPerPage)

		client.logger.Debug("请求URL: %s", url)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("创建请求失败: %v", err)
		}

		// 设置请求头
		req.Header.Set("User-Agent", "QianKunQuan/1.0")
		req.Header.Set("Accept", "application/json")

		// 发送请求
		resp, err := client.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP请求失败: %v", err)
		}

		defer resp.Body.Close()

		// 检查响应状态
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("API返回错误: %s, 响应: %s", resp.Status, string(body))
		}

		// 解析响应
		var nvdResponse NVDResponse
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("读取响应失败: %v", err)
		}

		if err := json.Unmarshal(body, &nvdResponse); err != nil {
			client.logger.Error("解析JSON失败: %v, 响应: %s", err, string(body[:500]))
			return nil, fmt.Errorf("解析JSON失败: %v", err)
		}

		// 转换NVD响应为内部CVE模型
		for _, vuln := range nvdResponse.Vulnerabilities {
			cve := client.convertNVDToCVE(vuln)
			yearCVEs = append(yearCVEs, cve)
		}

		client.logger.Debug("获取到 %d 个CVE，总计 %d 个，总结果数: %d",
			len(nvdResponse.Vulnerabilities), len(yearCVEs), nvdResponse.TotalResults)

		// 检查是否还有更多数据
		if startIndex+len(nvdResponse.Vulnerabilities) >= nvdResponse.TotalResults {
			break
		}

		// 更新起始索引
		startIndex += len(nvdResponse.Vulnerabilities)

		// 避免速率限制
		time.Sleep(1 * time.Second)
	}

	return yearCVEs, nil
}

// convertNVDToCVE 将NVD API响应转换为内部CVE模型
func (client *CVEAPIClient) convertNVDToCVE(vuln NVDVulnerability) model.CVE {
	cve := model.CVE{
		ID: vuln.CVE.ID,
	}

	// 提取描述
	if len(vuln.CVE.Descriptions) > 0 {
		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}
	}

	// 提取CVSS分数和严重性
	if len(vuln.CVE.Metrics.CvssMetricV31) > 0 {
		cve.CVSSScore = vuln.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore
		cve.CVSSSeverity = vuln.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
	} else if len(vuln.CVE.Metrics.CvssMetricV30) > 0 {
		cve.CVSSScore = vuln.CVE.Metrics.CvssMetricV30[0].CvssData.BaseScore
		cve.CVSSSeverity = vuln.CVE.Metrics.CvssMetricV30[0].CvssData.BaseSeverity
	} else if len(vuln.CVE.Metrics.CvssMetricV2) > 0 {
		cve.CVSSScore = vuln.CVE.Metrics.CvssMetricV2[0].CvssData.BaseScore
		cve.CVSSSeverity = vuln.CVE.Metrics.CvssMetricV2[0].BaseSeverity
	}

	// 解析发布日期
	if published, err := time.Parse("2006-01-02T15:04:05.000", vuln.CVE.Published); err == nil {
		cve.Published = published
	}

	// 解析修改日期
	if modified, err := time.Parse("2006-01-02T15:04:05.000", vuln.CVE.LastModified); err == nil {
		cve.Modified = modified
	}

	// 提取受影响的软件
	for _, config := range vuln.CVE.Configurations {
		for _, node := range config.Nodes {
			for _, cpeMatch := range node.CpeMatch {
				if cpeMatch.Vulnerable {
					// 解析CPE字符串
					parts := strings.Split(cpeMatch.Criteria, ":")
					if len(parts) >= 5 {
						software := model.AffectedSoftware{
							Vendor:  parts[3],
							Product: parts[4],
							CPEs:    []string{cpeMatch.Criteria},
						}

						// 提取版本信息
						if len(parts) > 5 && parts[5] != "*" {
							software.Version = parts[5]
						}

						// 如果有版本结束范围
						if len(parts) > 6 && parts[6] != "*" {
							software.VersionEnd = parts[6]
						}

						cve.AffectedSoftware = append(cve.AffectedSoftware, software)
					}
				}
			}
		}
	}

	return cve
}

// SaveCVEsToDatabase 将CVE数据保存到数据库
func (client *CVEAPIClient) SaveCVEsToDatabase(db *CVEDatabase, cves []model.CVE) (int, error) {
	successCount := 0
	failureCount := 0

	client.logger.Info("开始保存 %d 个CVE到数据库...", len(cves))

	for i, cve := range cves {
		if err := db.InsertCVE(cve); err != nil {
			failureCount++
			client.logger.Debug("保存CVE失败 %s: %v", cve.ID, err)
		} else {
			successCount++
		}

		// 每100条显示一次进度
		if (i+1)%100 == 0 {
			client.logger.Info("已保存 %d/%d 个CVE...", i+1, len(cves))
		}
	}

	client.logger.Info("CVE保存完成: %d 成功, %d 失败", successCount, failureCount)

	if failureCount > 0 {
		return successCount, fmt.Errorf("部分CVE保存失败: %d 个失败", failureCount)
	}

	return successCount, nil
}

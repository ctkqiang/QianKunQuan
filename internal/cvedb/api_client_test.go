package cvedb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewCVEAPIClient(t *testing.T) {
	client := NewCVEAPIClient()
	if client == nil {
		t.Fatal("NewCVEAPIClient() 返回 nil")
	}
	if client.baseURL != "https://services.nvd.nist.gov/rest/json/cves/2.0" {
		t.Errorf("期望baseURL为 %s, 实际得到 %s", "https://services.nvd.nist.gov/rest/json/cves/2.0", client.baseURL)
	}
	if client.logger == nil {
		t.Error("logger 不应为 nil")
	}
	if client.httpClient == nil {
		t.Error("httpClient 不应为 nil")
	}
}

func TestConvertNVDToCVE(t *testing.T) {
	client := NewCVEAPIClient()

	// 创建测试用的NVD漏洞数据
	vuln := NVDVulnerability{
		CVE: struct {
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
		}{
			ID:           "CVE-2025-1001",
			Published:    "2025-01-15T10:30:45.000",
			LastModified: "2025-01-20T14:25:30.000",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "测试CVE描述"},
			},
			Metrics: struct {
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
			}{
				CvssMetricV31: []struct {
					CvssData struct {
						Version      string  `json:"version"`
						Vector       string  `json:"vectorString"`
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				}{
					{
						CvssData: struct {
							Version      string  `json:"version"`
							Vector       string  `json:"vectorString"`
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						}{
							Version:      "3.1",
							Vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							BaseScore:    9.8,
							BaseSeverity: "CRITICAL",
						},
					},
				},
			},
		},
	}

	cve := client.convertNVDToCVE(vuln)

	if cve.ID != "CVE-2025-1001" {
		t.Errorf("期望CVE ID为 CVE-2025-1001, 实际得到 %s", cve.ID)
	}
	if cve.Description != "测试CVE描述" {
		t.Errorf("期望描述为 '测试CVE描述', 实际得到 %s", cve.Description)
	}
	if cve.CVSSScore != 9.8 {
		t.Errorf("期望CVSS分数为 9.8, 实际得到 %f", cve.CVSSScore)
	}
	if cve.CVSSSeverity != "CRITICAL" {
		t.Errorf("期望CVSS严重性为 CRITICAL, 实际得到 %s", cve.CVSSSeverity)
	}

	expectedPublished, _ := time.Parse("2006-01-02T15:04:05.000", "2025-01-15T10:30:45.000")
	if !cve.Published.Equal(expectedPublished) {
		t.Errorf("发布日期不匹配")
	}
}

func TestFetchCVEsForYearWithMockServer(t *testing.T) {
	// 创建模拟HTTP服务器
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证请求参数
		if r.Method != "GET" {
			t.Errorf("期望GET请求, 实际得到 %s", r.Method)
		}

		// 返回模拟的NVD API响应
		response := NVDResponse{
			ResultsPerPage: 2,
			StartIndex:     0,
			TotalResults:   2,
			Vulnerabilities: []NVDVulnerability{
				{
					CVE: struct {
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
					}{
						ID:           "CVE-2025-2001",
						Published:    "2025-03-10T08:15:30.000",
						LastModified: "2025-03-12T11:20:45.000",
						Descriptions: []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						}{
							{Lang: "en", Value: "模拟CVE #1描述"},
						},
						Metrics: struct {
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
						}{
							CvssMetricV31: []struct {
								CvssData struct {
									Version      string  `json:"version"`
									Vector       string  `json:"vectorString"`
									BaseScore    float64 `json:"baseScore"`
									BaseSeverity string  `json:"baseSeverity"`
								} `json:"cvssData"`
							}{
								{
									CvssData: struct {
										Version      string  `json:"version"`
										Vector       string  `json:"vectorString"`
										BaseScore    float64 `json:"baseScore"`
										BaseSeverity string  `json:"baseSeverity"`
									}{
										Version:      "3.1",
										Vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
										BaseScore:    7.5,
										BaseSeverity: "HIGH",
									},
								},
							},
						},
					},
				},
				{
					CVE: struct {
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
					}{
						ID:           "CVE-2025-2002",
						Published:    "2025-05-20T14:30:00.000",
						LastModified: "2025-05-25T09:45:15.000",
						Descriptions: []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						}{
							{Lang: "en", Value: "模拟CVE #2描述"},
						},
						Metrics: struct {
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
						}{
							CvssMetricV31: []struct {
								CvssData struct {
									Version      string  `json:"version"`
									Vector       string  `json:"vectorString"`
									BaseScore    float64 `json:"baseScore"`
									BaseSeverity string  `json:"baseSeverity"`
								} `json:"cvssData"`
							}{
								{
									CvssData: struct {
										Version      string  `json:"version"`
										Vector       string  `json:"vectorString"`
										BaseScore    float64 `json:"baseScore"`
										BaseSeverity string  `json:"baseSeverity"`
									}{
										Version:      "3.1",
										Vector:       "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L",
										BaseScore:    5.0,
										BaseSeverity: "MEDIUM",
									},
								},
							},
						},
					},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer testServer.Close()

	// 创建API客户端，使用测试服务器的URL
	client := NewCVEAPIClient()
	client.baseURL = testServer.URL + "/rest/json/cves/2.0"

	// 测试获取CVE数据
	cves, err := client.fetchCVEsForYear(2025)
	if err != nil {
		t.Fatalf("fetchCVEsForYear 失败: %v", err)
	}

	if len(cves) != 2 {
		t.Errorf("期望获取2个CVE, 实际得到 %d", len(cves))
	}

	// 验证第一个CVE
	if cves[0].ID != "CVE-2025-2001" {
		t.Errorf("第一个CVE ID应为 CVE-2025-2001, 实际得到 %s", cves[0].ID)
	}
	if cves[0].CVSSScore != 7.5 {
		t.Errorf("第一个CVE CVSS分数应为 7.5, 实际得到 %f", cves[0].CVSSScore)
	}
	if cves[0].CVSSSeverity != "HIGH" {
		t.Errorf("第一个CVE严重性应为 HIGH, 实际得到 %s", cves[0].CVSSSeverity)
	}

	// 验证第二个CVE
	if cves[1].ID != "CVE-2025-2002" {
		t.Errorf("第二个CVE ID应为 CVE-2025-2002, 实际得到 %s", cves[1].ID)
	}
	if cves[1].CVSSScore != 5.0 {
		t.Errorf("第二个CVE CVSS分数应为 5.0, 实际得到 %f", cves[1].CVSSScore)
	}
	if cves[1].CVSSSeverity != "MEDIUM" {
		t.Errorf("第二个CVE严重性应为 MEDIUM, 实际得到 %s", cves[1].CVSSSeverity)
	}
}

func TestFetchCVEsForYearWithPagination(t *testing.T) {
	callCount := 0
	totalResults := 5

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		// 第一页：返回3个结果
		if callCount == 1 {
			response := NVDResponse{
				ResultsPerPage: 3,
				StartIndex:     0,
				TotalResults:   totalResults,
				Vulnerabilities: []NVDVulnerability{
					createMockVulnerability("CVE-2025-3001"),
					createMockVulnerability("CVE-2025-3002"),
					createMockVulnerability("CVE-2025-3003"),
				},
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 第二页：返回2个结果
		if callCount == 2 {
			response := NVDResponse{
				ResultsPerPage: 2,
				StartIndex:     3,
				TotalResults:   totalResults,
				Vulnerabilities: []NVDVulnerability{
					createMockVulnerability("CVE-2025-3004"),
					createMockVulnerability("CVE-2025-3005"),
				},
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
			return
		}

		// 不应有第三次调用
		t.Errorf("不应有第%d次API调用", callCount)
	}))
	defer testServer.Close()

	client := NewCVEAPIClient()
	client.baseURL = testServer.URL + "/rest/json/cves/2.0"

	cves, err := client.fetchCVEsForYear(2025)
	if err != nil {
		t.Fatalf("fetchCVEsForYear 失败: %v", err)
	}

	if len(cves) != totalResults {
		t.Errorf("期望获取%d个CVE, 实际得到 %d", totalResults, len(cves))
	}

	if callCount != 2 {
		t.Errorf("期望2次API调用（分页）, 实际得到 %d", callCount)
	}
}

func TestFetchCVEsForYearWithAPIError(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal Server Error"}`))
	}))
	defer testServer.Close()

	client := NewCVEAPIClient()
	client.baseURL = testServer.URL + "/rest/json/cves/2.0"

	_, err := client.fetchCVEsForYear(2025)
	if err == nil {
		t.Error("期望API错误，但未返回错误")
	}

	expectedErr := "API返回错误: 500 Internal Server Error, 响应: {\"error\": \"Internal Server Error\"}"
	if err.Error() != expectedErr {
		t.Errorf("错误消息不匹配。期望: %s, 实际: %s", expectedErr, err.Error())
	}
}

func TestFetchCVEsByYearRange(t *testing.T) {
	callCount := 0

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++

		response := NVDResponse{
			ResultsPerPage: 1,
			StartIndex:     0,
			TotalResults:   1,
			Vulnerabilities: []NVDVulnerability{
				createMockVulnerability(fmt.Sprintf("CVE-%d-1001", 2025+(callCount-1))),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))
	defer testServer.Close()

	client := NewCVEAPIClient()
	client.baseURL = testServer.URL + "/rest/json/cves/2.0"

	// 测试获取2025-2026年数据
	cves, err := client.FetchCVEsByYearRange(2025, 2026)
	if err != nil {
		t.Fatalf("FetchCVEsByYearRange 失败: %v", err)
	}

	if len(cves) != 2 {
		t.Errorf("期望获取2个CVE（两年各一个）, 实际得到 %d", len(cves))
	}

	if callCount != 2 {
		t.Errorf("期望2次API调用（两年各一次）, 实际得到 %d", callCount)
	}

	// 验证年份
	if cves[0].ID != "CVE-2025-1001" {
		t.Errorf("第一个CVE应为 CVE-2025-1001, 实际得到 %s", cves[0].ID)
	}
	if cves[1].ID != "CVE-2026-1001" {
		t.Errorf("第二个CVE应为 CVE-2026-1001, 实际得到 %s", cves[1].ID)
	}
}

// 辅助函数：创建模拟漏洞数据
func createMockVulnerability(cveID string) NVDVulnerability {
	return NVDVulnerability{
		CVE: struct {
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
		}{
			ID:           cveID,
			Published:    "2025-01-01T00:00:00.000",
			LastModified: "2025-01-02T00:00:00.000",
			Descriptions: []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			}{
				{Lang: "en", Value: "测试CVE描述 " + cveID},
			},
			Metrics: struct {
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
			}{
				CvssMetricV31: []struct {
					CvssData struct {
						Version      string  `json:"version"`
						Vector       string  `json:"vectorString"`
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				}{
					{
						CvssData: struct {
							Version      string  `json:"version"`
							Vector       string  `json:"vectorString"`
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						}{
							Version:      "3.1",
							Vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							BaseScore:    9.8,
							BaseSeverity: "CRITICAL",
						},
					},
				},
			},
		},
	}
}

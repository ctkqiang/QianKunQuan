package scanner

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"QianKunQuan/internal/model"
	"QianKunQuan/internal/utils"
)

type SubdomainScanner struct {
	domain     string
	threads    int
	verbose    bool
	logger     *utils.Logger
	dnsEnum    bool
	httpCheck  bool
	httpClient *http.Client
}

func NewSubdomainScanner(domain string, threads int, dnsEnum, httpCheck, verbose bool) *SubdomainScanner {
	return &SubdomainScanner{
		domain:    domain,
		threads:   threads,
		verbose:   verbose,
		dnsEnum:   dnsEnum,
		httpCheck: httpCheck,
		logger:    utils.NewLogger("subdomain"),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (ss *SubdomainScanner) Scan(customWordlist []string) []model.SubdomainResult {
	var results []model.SubdomainResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	wordlist := model.SubdomainPrefixes
	if len(customWordlist) > 0 {
		wordlist = customWordlist
	}

	ss.logger.Info("开始子域名枚举: %s", ss.domain)
	ss.logger.Info("字典大小: %d", len(wordlist))

	sem := make(chan struct{}, ss.threads)

	for _, prefix := range wordlist {
		wg.Add(1)
		sem <- struct{}{}

		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			subdomain := p + "." + ss.domain
			result := model.SubdomainResult{
				Subdomain: subdomain,
				Source:    "dns-brute",
			}

			if ss.dnsEnum {
				ips, err := net.LookupHost(subdomain)
				if err == nil && len(ips) > 0 {
					result.Alive = true
					result.IP = strings.Join(ips, ", ")

					if ss.httpCheck {
						if ss.checkHTTPAlive(subdomain) {
							result.Source = "dns+http"
						}
					}

					mu.Lock()
					results = append(results, result)
					mu.Unlock()

					if ss.verbose {
						ss.logger.Info("发现子域名: %s (%s)", subdomain, result.IP)
					}
				}
			}
		}(prefix)
	}

	wg.Wait()

	ss.logger.Info("子域名枚举完成，共发现 %d 个子域名", len(results))
	return results
}

func (ss *SubdomainScanner) checkHTTPAlive(subdomain string) bool {
	urls := []string{
		"http://" + subdomain,
		"https://" + subdomain,
	}

	for _, u := range urls {
		resp, err := ss.httpClient.Get(u)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != 0 {
				return true
			}
		}
	}

	return false
}

func (ss *SubdomainScanner) PrintResult(results []model.SubdomainResult) string {
	var builder strings.Builder

	builder.WriteString("\n")
	builder.WriteString("[子域名枚举报告]\n")
	builder.WriteString(strings.Repeat("═", 60) + "\n")
	builder.WriteString(fmt.Sprintf("主域名: %s\n", ss.domain))
	builder.WriteString(fmt.Sprintf("发现子域名: %d 个\n\n", len(results)))

	if len(results) == 0 {
		builder.WriteString("[!] 未发现任何子域名\n")
		builder.WriteString(strings.Repeat("═", 60) + "\n")
		return builder.String()
	}

	builder.WriteString(fmt.Sprintf("%-40s %-20s %s\n", "子域名", "IP地址", "状态"))
	builder.WriteString(strings.Repeat("─", 60) + "\n")

	for i, r := range results {
		status := "[+] 存活"
		if !r.Alive {
			status = "[-] 未知"
		}

		ip := r.IP
		if len(ip) > 18 {
			ip = ip[:18] + "..."
		}
		if ip == "" {
			ip = "-"
		}

		builder.WriteString(fmt.Sprintf("%-40s %-20s %s\n",
			r.Subdomain, ip, status))

		if i >= 50 {
			builder.WriteString(fmt.Sprintf("\n... 还有 %d 个子域名未显示 ...\n", len(results)-50))
			break
		}
	}

	builder.WriteString("\n" + strings.Repeat("═", 60) + "\n")
	builder.WriteString(fmt.Sprintf("[完成] 枚举结束，共发现 %d 个子域名\n", len(results)))

	return builder.String()
}

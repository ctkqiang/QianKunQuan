package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"QianKunQuan/internal/model"
	"QianKunQuan/internal/utils"
)

type WebScanner struct {
	baseURL    string
	threads    int
	timeout    int
	verbose    bool
	logger     *utils.Logger
	client     *http.Client
	userAgent  string
	cookie     string
}

func NewWebScanner(baseURL string, threads, timeout int, verbose bool, proxy, userAgent, cookie string) *WebScanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 30 * time.Second,
	}

	if proxy != "" {
		if proxyURL, err := url.Parse(proxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}

	return &WebScanner{
		baseURL:   strings.TrimRight(baseURL, "/"),
		threads:   threads,
		timeout:   timeout,
		verbose:   verbose,
		logger:    utils.NewLogger("web-scanner"),
		userAgent: userAgent,
		cookie:    cookie,
		client: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (ws *WebScanner) Scan() *model.WebScanResult {
	result := &model.WebScanResult{
		Target:     ws.baseURL,
		Headers:    make(map[string]string),
		TechStack:  []string{},
		StatusCode: 200,
	}

	startTime := time.Now()

	ws.logger.Info("开始Web侦察: %s", ws.baseURL)

	resp, body, err := ws.doRequest("GET", ws.baseURL)
	if err == nil {
		result.StatusCode = resp.StatusCode
		for k, v := range resp.Header {
			if len(v) > 0 {
				result.Headers[k] = v[0]
			}
		}

		result.Server = resp.Header.Get("Server")
		if result.Server != "" {
			result.TechStack = append(result.TechStack, "Server: "+result.Server)
		}

		xPowered := resp.Header.Get("X-Powered-By")
		if xPowered != "" {
			result.TechStack = append(result.TechStack, "X-Powered-By: "+xPowered)
		}

		title := extractTitle(body)
		result.Title = title

		if ws.verbose {
			ws.logger.Info("首页状态: %d, 标题: %s", resp.StatusCode, title)
		}
	} else {
		ws.logger.Warn("首页访问失败: %v", err)
		result.StatusCode = 0
	}

	ws.logger.Info("正在检测WAF...")
	waf := ws.detectWAF(resp, body)
	result.WAF = waf
	if waf != "" {
		ws.logger.Info("检测到WAF: %s", waf)
	} else {
		ws.logger.Info("未检测到常见WAF")
	}

	ws.logger.Info("正在识别CMS...")
	cms, cmsVer := ws.detectCMS(resp, body)
	result.CMS = cms
	result.CMSVersion = cmsVer
	if cms != "" {
		ws.logger.Info("识别到CMS: %s %s", cms, cmsVer)
	} else {
		ws.logger.Info("未识别到已知CMS")
	}

	result.TechStack = append(result.TechStack, ws.detectTechStack(resp, body)...)

	ws.logger.Info("正在进行目录爆破...")
	dirs := ws.dirBruteForce()
	result.URLs = dirs
	if len(dirs) > 0 {
		ws.logger.Info("发现 %d 个敏感路径", len(dirs))
	}

	result.ScanTime = time.Since(startTime).String()
	return result
}

func (ws *WebScanner) doRequest(method, urlStr string) (*http.Response, string, error) {
	req, err := http.NewRequest(method, urlStr, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("User-Agent", ws.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if ws.cookie != "" {
		req.Header.Set("Cookie", ws.cookie)
	}

	resp, err := ws.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return resp, "", err
	}

	return resp, string(body), nil
}

func extractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func (ws *WebScanner) detectWAF(resp *http.Response, body string) string {
	lowerBody := strings.ToLower(body)

	for _, waf := range model.WAFFingerprints {
		for headerKey, headerVal := range waf.Header {
			if resp != nil {
				if val := resp.Header.Get(headerKey); val != "" {
					if headerVal == "" || strings.Contains(strings.ToLower(val), strings.ToLower(headerVal)) {
						return waf.Name
					}
				}
			}
		}

		for _, pattern := range waf.Body {
			if strings.Contains(lowerBody, strings.ToLower(pattern)) {
				return waf.Name
			}
		}
	}

	return ""
}

func (ws *WebScanner) detectCMS(resp *http.Response, body string) (string, string) {
	lowerBody := strings.ToLower(body)

	for _, cms := range model.CMSFingerprints {
		matchCount := 0
		for _, pattern := range cms.Body {
			if strings.Contains(lowerBody, strings.ToLower(pattern)) {
				matchCount++
			}
		}

		if resp != nil {
			for headerKey, headerVal := range cms.Header {
				if val := resp.Header.Get(headerKey); val != "" {
					if headerVal == "" || strings.Contains(strings.ToLower(val), strings.ToLower(headerVal)) {
						matchCount += 2
					}
				}
			}
		}

		if matchCount >= 1 {
			version := ws.extractCMSVersion(cms.Name, body)
			return cms.Name, version
		}
	}

	return "", ""
}

func (ws *WebScanner) extractCMSVersion(cmsName, body string) string {
	lowerBody := strings.ToLower(body)
	versionPatterns := map[string][]string{
		"WordPress": {`(?i)wordpress\s+(\d+\.\d+(\.\d+)?)`, `(?i)content="WordPress\s+(\d+\.\d+(\.\d+)?)"`},
		"DedeCMS":   {`(?i)dedecms\s*v?(\d+\.\d+(\.\d+)?)`, `(?i)织梦内容管理系统\s*v?(\d+\.\d+)`},
		"Discuz!":   {`(?i)discuz!?(?:\s*X)?\s*(\d+\.\d+(\.\d+)?)`},
		"Joomla!":   {`(?i)joomla!\s*(\d+\.\d+(\.\d+)?)`},
		"Drupal":    {`(?i)drupal\s*(\d+\.\d+(\.\d+)?)`},
		"Typecho":   {`(?i)typecho\s*(\d+\.\d+(\.\d+)?)`},
		"ThinkPHP":  {`(?i)thinkphp\s*(\d+\.\d+(\.\d+)?)`},
		"Tomcat":    {`(?i)apache\s+tomcat\s*/?\s*(\d+\.\d+(\.\d+)?)`},
		"Nginx":     {`(?i)nginx/(\d+\.\d+(\.\d+)?)`},
		"Apache":    {`(?i)apache/(\d+\.\d+(\.\d+)?)`},
		"IIS":       {`(?i)microsoft-iis/(\d+\.\d+)`},
	}

	if patterns, ok := versionPatterns[cmsName]; ok {
		for _, pattern := range patterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindStringSubmatch(lowerBody)
			if len(matches) > 1 {
				return matches[1]
			}
		}
	}

	return ""
}

func (ws *WebScanner) detectTechStack(resp *http.Response, body string) []string {
	var tech []string
	lowerBody := strings.ToLower(body)

	if strings.Contains(lowerBody, "php") || strings.Contains(lowerBody, ".php") {
		tech = append(tech, "PHP")
	}
	if strings.Contains(lowerBody, "java") || strings.Contains(lowerBody, ".jsp") || strings.Contains(lowerBody, ".do") || strings.Contains(lowerBody, ".action") {
		tech = append(tech, "Java")
	}
	if strings.Contains(lowerBody, "asp.net") || strings.Contains(lowerBody, ".aspx") {
		tech = append(tech, "ASP.NET")
	}
	if strings.Contains(lowerBody, "python") || strings.Contains(lowerBody, "django") || strings.Contains(lowerBody, "flask") {
		tech = append(tech, "Python")
	}
	if strings.Contains(lowerBody, "node.js") || strings.Contains(lowerBody, "nodejs") || strings.Contains(lowerBody, "express") {
		tech = append(tech, "Node.js")
	}
	if strings.Contains(lowerBody, "vue") || strings.Contains(lowerBody, "vue.js") {
		tech = append(tech, "Vue.js")
	}
	if strings.Contains(lowerBody, "react") {
		tech = append(tech, "React")
	}
	if strings.Contains(lowerBody, "jquery") {
		tech = append(tech, "jQuery")
	}
	if strings.Contains(lowerBody, "bootstrap") {
		tech = append(tech, "Bootstrap")
	}

	if resp != nil {
		cookies := resp.Cookies()
		for _, c := range cookies {
			name := strings.ToLower(c.Name)
			if strings.Contains(name, "phpsessid") {
				if !contains(tech, "PHP") {
					tech = append(tech, "PHP (Session)")
				}
			}
			if strings.Contains(name, "jsessionid") {
				if !contains(tech, "Java") {
					tech = append(tech, "Java (JSP)")
				}
			}
			if strings.Contains(name, "aspsession") || strings.Contains(name, "asp.net_sessionid") {
				if !contains(tech, "ASP.NET") {
					tech = append(tech, "ASP.NET (Session)")
				}
			}
		}
	}

	return tech
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.Contains(strings.ToLower(s), strings.ToLower(item)) {
			return true
		}
	}
	return false
}

func (ws *WebScanner) dirBruteForce() []model.DirResult {
	wordlist := model.DefaultDirWordlist
	var results []model.DirResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, ws.threads)

	for _, path := range wordlist {
		wg.Add(1)
		sem <- struct{}{}

		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			fullURL := ws.baseURL + p
			resp, body, err := ws.doRequest("GET", fullURL)

			if err != nil {
				return
			}

			if resp.StatusCode >= 200 && resp.StatusCode < 300 ||
				resp.StatusCode == 403 ||
				resp.StatusCode == 401 ||
				resp.StatusCode == 301 ||
				resp.StatusCode == 302 {

				contentType := resp.Header.Get("Content-Type")
				title := extractTitle(body)
				length := len(body)

				if isInterestingPath(p, resp.StatusCode) {
					result := model.DirResult{
						URL:         fullURL,
						Path:        p,
						StatusCode:  resp.StatusCode,
						Length:      length,
						Title:       title,
						ContentType: contentType,
					}

					mu.Lock()
					results = append(results, result)
					mu.Unlock()

					if ws.verbose {
						ws.logger.Info("发现路径 [%d] %s", resp.StatusCode, p)
					}
				}
			}
		}(path)
	}

	wg.Wait()

	return results
}

func isInterestingPath(path string, statusCode int) bool {
	if statusCode == 404 {
		return false
	}

	sensitivePaths := []string{
		"/admin", "/login", "/manager", "/manage",
		"/wp-admin", "/phpmyadmin", "/pma",
		"/phpinfo.php", "/info.php", "/test.php",
		"/.git/", "/.svn/", "/.env", "/.htaccess", "/.htpasswd",
		"/backup", "/bak", "/backup.sql", "/www.zip", "/web.zip",
		"/config.php", "/config.inc.php", "/web.config",
		"/install", "/install.php",
		"/api", "/swagger", "/docs", "/actuator", "/druid",
		"/console", "/jmx-console", "/web-console", "/admin-console",
		"/upload", "/uploads", "/files", "/download",
		"/robots.txt", "/sitemap.xml", "/crossdomain.xml",
		"/.DS_Store", "/.well-known/",
	}

	lowerPath := strings.ToLower(path)
	for _, sp := range sensitivePaths {
		if strings.Contains(lowerPath, strings.ToLower(sp)) {
			return true
		}
	}

	if statusCode == 200 && (strings.HasSuffix(path, ".zip") ||
		strings.HasSuffix(path, ".rar") ||
		strings.HasSuffix(path, ".sql") ||
		strings.HasSuffix(path, ".tar") ||
		strings.HasSuffix(path, ".tar.gz") ||
		strings.HasSuffix(path, ".bak") ||
		strings.HasSuffix(path, ".backup")) {
		return true
	}

	return false
}

func (ws *WebScanner) PrintResult(result *model.WebScanResult) string {
	var builder strings.Builder

	builder.WriteString("\n")
	builder.WriteString("[Web应用侦察报告]\n")
	builder.WriteString(strings.Repeat("═", 60) + "\n")
	builder.WriteString(fmt.Sprintf("目标: %s\n", result.Target))
	builder.WriteString(fmt.Sprintf("耗时: %s\n\n", result.ScanTime))

	builder.WriteString("[基础信息]\n")
	builder.WriteString(strings.Repeat("─", 40) + "\n")
	builder.WriteString(fmt.Sprintf("  状态码: %d\n", result.StatusCode))
	if result.Title != "" {
		builder.WriteString(fmt.Sprintf("  标题: %s\n", result.Title))
	}
	if result.Server != "" {
		builder.WriteString(fmt.Sprintf("  服务器: %s\n", result.Server))
	}
	if len(result.TechStack) > 0 {
		builder.WriteString(fmt.Sprintf("  技术栈: %s\n", strings.Join(result.TechStack, ", ")))
	}
	builder.WriteString("\n")

	if result.WAF != "" {
		builder.WriteString("[WAF检测]\n")
		builder.WriteString(strings.Repeat("─", 40) + "\n")
		builder.WriteString(fmt.Sprintf("  检测到WAF: [警告] %s\n\n", result.WAF))
	} else {
		builder.WriteString("[WAF检测]\n")
		builder.WriteString(strings.Repeat("─", 40) + "\n")
		builder.WriteString(fmt.Sprintf("  未检测到常见WAF [OK]\n\n"))
	}

	if result.CMS != "" {
		builder.WriteString("[CMS识别]\n")
		builder.WriteString(strings.Repeat("─", 40) + "\n")
		builder.WriteString(fmt.Sprintf("  CMS: [发现] %s", result.CMS))
		if result.CMSVersion != "" {
			builder.WriteString(fmt.Sprintf(" v%s", result.CMSVersion))
		}
		builder.WriteString("\n\n")
	} else {
		builder.WriteString("[CMS识别]\n")
		builder.WriteString(strings.Repeat("─", 40) + "\n")
		builder.WriteString(fmt.Sprintf("  未识别到已知CMS [-]\n\n"))
	}

	if len(result.URLs) > 0 {
		builder.WriteString(fmt.Sprintf("[目录爆破] 发现 %d 个敏感路径:\n", len(result.URLs)))
		builder.WriteString(strings.Repeat("─", 60) + "\n")
		builder.WriteString(fmt.Sprintf("%-8s %-10s %-40s %s\n", "状态码", "大小", "路径", "标题"))
		builder.WriteString(strings.Repeat("─", 60) + "\n")

		for _, dir := range result.URLs {
			statusTag := "[200]"
			switch dir.StatusCode {
			case 403, 401:
				statusTag = "[403]"
			case 301, 302:
				statusTag = "[302]"
			default:
				statusTag = fmt.Sprintf("[%d]", dir.StatusCode)
			}

			title := dir.Title
			if len(title) > 30 {
				title = title[:30] + "..."
			}
			if title == "" {
				title = "-"
			}

			builder.WriteString(fmt.Sprintf("%s %-5s %-10s %-40s %s\n",
				statusTag, "",
				fmt.Sprintf("%d字节", dir.Length),
				dir.Path, title))
		}
		builder.WriteString("\n")
	}

	builder.WriteString(strings.Repeat("═", 60) + "\n")
	builder.WriteString("[完成] Web侦察结束\n")

	return builder.String()
}

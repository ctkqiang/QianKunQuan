package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"QianKunQuan/internal/model"
)

type Command struct {
	Name        string
	Description string
	Handler     func(args []string) error
}

type Parser struct {
	Options  model.ScanOptions
	commands map[string]*Command
}

func NewParser() *Parser {
	return &Parser{
		commands: make(map[string]*Command),
	}
}

func (p *Parser) Register(name, desc string, handler func(args []string) error) {
	p.commands[name] = &Command{
		Name:        name,
		Description: desc,
		Handler:     handler,
	}
}

func (p *Parser) Parse() error {
	if len(os.Args) < 2 {
		p.printBanner()
		p.printMainHelp()
		return fmt.Errorf("请指定子命令")
	}

	cmdName := os.Args[1]
	if cmdName == "-h" || cmdName == "-help" || cmdName == "--help" || cmdName == "help" {
		p.printBanner()
		p.printMainHelp()
		os.Exit(0)
	}

	if cmdName == "-v" || cmdName == "-version" || cmdName == "--version" || cmdName == "version" {
		p.printBanner()
		os.Exit(0)
	}

	cmd, exists := p.commands[cmdName]
	if !exists {
		p.printBanner()
		fmt.Fprintf(os.Stderr, "[错误] 未知命令: %s\n\n", cmdName)
		p.printMainHelp()
		return fmt.Errorf("未知命令: %s", cmdName)
	}

	return cmd.Handler(os.Args[2:])
}

func (p *Parser) printBanner() {
	banner := `
  ██████╗ ██╗ █████╗ ███╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗
 ██╔═══██╗██║██╔══██╗████╗  ██║██║ ██╔╝██║   ██║████╗  ██║██╔═══██╗██║   ██║██╔══██╗████╗  ██║
 ██║   ██║██║███████║██╔██╗ ██║█████╔╝ ██║   ██║██╔██╗ ██║██║   ██║██║   ██║███████║██╔██╗ ██║
 ██║▄▄ ██║██║██╔══██║██║╚██╗██║██╔═██╗ ██║   ██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██║╚██╗██║
 ╚██████╔╝██║██║  ██║██║ ╚████║██║  ██╗╚██████╔╝██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║
  ╚══▀▀═╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
`
	fmt.Println(banner)
	fmt.Println("  [红队侦察作战平台] Red Team Reconnaissance Framework")
	fmt.Println("  只为合法授权的安全评估与红蓝对抗而设计")
	fmt.Println("  [警告] 使用前请确保已获得书面授权，一切后果自负")
	fmt.Println()
}

func (p *Parser) printMainHelp() {
	fmt.Println("[用法] qiankunquan <命令> [选项]")
	fmt.Println()
	fmt.Println("== 核心命令 ==")
	fmt.Println()
	fmt.Println("  侦察类:")
	fmt.Println("    scan         端口扫描与服务识别")
	fmt.Println("    web          Web应用侦察（目录爆破 + CMS识别 + WAF检测）")
	fmt.Println("    subdomain    子域名枚举")
	fmt.Println("    full         全量侦察（端口 + Web + 子域名 一键全开）")
	fmt.Println()
	fmt.Println("  利用类:")
	fmt.Println("    vuln         漏洞利用索引（按服务/CVE查POC/EXP）")
	fmt.Println("    attack       攻击路径推荐（基于扫描结果生成攻击向量）")
	fmt.Println()
	fmt.Println("  输出类:")
	fmt.Println("    report       生成红队评估报告（Markdown / HTML）")
	fmt.Println()
	fmt.Println("  系统类:")
	fmt.Println("    update       更新漏洞数据库")
	fmt.Println("    help         显示帮助信息")
	fmt.Println()
	fmt.Println("[快速示例]")
	fmt.Println("  qiankunquan scan -t example.com -p common")
	fmt.Println("  qiankunquan web -u http://example.com --dirscan")
	fmt.Println("  qiankunquan subdomain -d example.com")
	fmt.Println("  qiankunquan full -t example.com -o report.html")
	fmt.Println("  qiankunquan vuln -s redis")
	fmt.Println("  qiankunquan attack --target example.com")
	fmt.Println()
	fmt.Println("[提示] 查看子命令详情: qiankunquan <命令> -h")
	fmt.Println()
}

func (p *Parser) ParseScanArgs(args []string) (*model.ScanOptions, error) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	opt := &model.ScanOptions{}

	var target string
	var ports string
	var mode string

	fs.StringVar(&target, "target", "", "目标IP/域名")
	fs.StringVar(&target, "t", "", "目标IP/域名 (缩写)")
	fs.StringVar(&ports, "ports", "common", "端口范围 (common/full/top100/top1000/1-65535/22,80,443)")
	fs.StringVar(&ports, "p", "common", "端口范围 (缩写)")
	fs.StringVar(&mode, "mode", "default", "扫描模式: default/fast/sneaky/deep")
	fs.StringVar(&mode, "m", "default", "扫描模式 (缩写)")
	fs.IntVar(&opt.Timeout, "timeout", 3, "连接超时(秒)")
	fs.IntVar(&opt.Timeout, "T", 3, "连接超时(秒) (缩写)")
	fs.IntVar(&opt.Threads, "threads", 200, "并发线程数")
	fs.IntVar(&opt.Threads, "th", 200, "并发线程数 (缩写)")
	fs.StringVar(&opt.OutputFile, "output", "", "输出文件")
	fs.StringVar(&opt.OutputFile, "o", "", "输出文件 (缩写)")
	fs.StringVar(&opt.OutputFormat, "format", "text", "输出格式: text/json/csv")
	fs.StringVar(&opt.OutputFormat, "f", "text", "输出格式 (缩写)")
	fs.BoolVar(&opt.Verbose, "verbose", false, "详细模式")
	fs.BoolVar(&opt.Verbose, "v", false, "详细模式 (缩写)")
	fs.BoolVar(&opt.UpdateDB, "update", false, "先更新CVE数据库再扫描")
	fs.StringVar(&opt.ScanMode, "scan-mode", "tcp", "扫描方式: tcp/syn/udp")

	fs.Usage = func() {
		fmt.Println("[端口扫描] scan")
		fmt.Println()
		fmt.Println("用法: qiankunquan scan [选项]")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("端口预设:")
		fmt.Println("  common   常见端口 (~70个)")
		fmt.Println("  top100   Nmap Top 100")
		fmt.Println("  top1000  Nmap Top 1000")
		fmt.Println("  full     全端口 (1-65535)")
		fmt.Println()
		fmt.Println("扫描模式:")
		fmt.Println("  default  默认速度")
		fmt.Println("  fast     快速模式 (高并发，牺牲精度)")
		fmt.Println("  sneaky   隐蔽模式 (低速率，模拟正常流量)")
		fmt.Println("  deep     深度模式 (慢扫描，含banner提取)")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  qiankunquan scan -t 192.168.1.1 -p common")
		fmt.Println("  qiankunquan scan -t example.com -p 1-1000 -m fast")
		fmt.Println("  qiankunquan scan -t target.com -o result.json -f json")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if target == "" {
		return nil, fmt.Errorf("必须指定目标 (-t <目标>)")
	}

	opt.Target = target
	opt.PortRange = ports
	opt.ScanMode = mode

	return opt, nil
}

func (p *Parser) ParseWebArgs(args []string) (*WebScanOptions, error) {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	opt := &WebScanOptions{}

	fs.StringVar(&opt.URL, "url", "", "目标URL (http://example.com)")
	fs.StringVar(&opt.URL, "u", "", "目标URL (缩写)")
	fs.BoolVar(&opt.DirScan, "dirscan", true, "开启目录爆破")
	fs.BoolVar(&opt.CMSDetect, "cms", true, "开启CMS识别")
	fs.BoolVar(&opt.WAFDetect, "waf", true, "开启WAF检测")
	fs.BoolVar(&opt.TechDetect, "tech", true, "开启技术栈识别")
	fs.IntVar(&opt.Threads, "threads", 50, "并发线程数")
	fs.IntVar(&opt.Threads, "th", 50, "并发线程数 (缩写)")
	fs.IntVar(&opt.Timeout, "timeout", 5, "请求超时(秒)")
	fs.StringVar(&opt.Wordlist, "wordlist", "", "自定义目录字典文件")
	fs.StringVar(&opt.OutputFile, "output", "", "输出文件")
	fs.StringVar(&opt.OutputFile, "o", "", "输出文件 (缩写)")
	fs.StringVar(&opt.OutputFormat, "format", "text", "输出格式: text/json")
	fs.StringVar(&opt.OutputFormat, "f", "text", "输出格式 (缩写)")
	fs.BoolVar(&opt.Verbose, "verbose", false, "详细模式")
	fs.BoolVar(&opt.Verbose, "v", false, "详细模式 (缩写)")
	fs.StringVar(&opt.Proxy, "proxy", "", "代理地址 (http://127.0.0.1:8080)")
	fs.StringVar(&opt.UserAgent, "user-agent", "", "自定义User-Agent")
	fs.StringVar(&opt.Cookie, "cookie", "", "自定义Cookie")

	fs.Usage = func() {
		fmt.Println("[Web应用侦察] web")
		fmt.Println()
		fmt.Println("用法: qiankunquan web [选项]")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("包含功能:")
		fmt.Println("  [+] 目录爆破 (内置300+常见敏感路径)")
		fmt.Println("  [+] CMS识别 (织梦/帝国/ThinkPHP/WordPress等20+国内主流CMS)")
		fmt.Println("  [+] WAF检测 (安全狗/阿里云盾/CloudFlare等15+主流WAF)")
		fmt.Println("  [+] 技术栈识别 (服务器/语言/框架)")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  qiankunquan web -u http://example.com")
		fmt.Println("  qiankunquan web -u https://target.com --dirscan -w wordlist.txt")
		fmt.Println("  qiankunquan web -u http://192.168.1.1:8080 -o web_result.json -f json")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if opt.URL == "" {
		return nil, fmt.Errorf("必须指定目标URL (-u <URL>)")
	}

	if !strings.HasPrefix(opt.URL, "http://") && !strings.HasPrefix(opt.URL, "https://") {
		opt.URL = "http://" + opt.URL
	}

	return opt, nil
}

func (p *Parser) ParseSubdomainArgs(args []string) (*SubdomainOptions, error) {
	fs := flag.NewFlagSet("subdomain", flag.ExitOnError)
	opt := &SubdomainOptions{}

	fs.StringVar(&opt.Domain, "domain", "", "目标域名 (example.com)")
	fs.StringVar(&opt.Domain, "d", "", "目标域名 (缩写)")
	fs.StringVar(&opt.Wordlist, "wordlist", "", "子域名字典文件")
	fs.IntVar(&opt.Threads, "threads", 100, "并发线程数")
	fs.IntVar(&opt.Threads, "th", 100, "并发线程数 (缩写)")
	fs.BoolVar(&opt.DNSEnum, "dns", true, "DNS枚举")
	fs.BoolVar(&opt.HTTPCheck, "http", true, "HTTP存活探测")
	fs.BoolVar(&opt.Verbose, "verbose", false, "详细模式")
	fs.BoolVar(&opt.Verbose, "v", false, "详细模式 (缩写)")
	fs.StringVar(&opt.OutputFile, "output", "", "输出文件")
	fs.StringVar(&opt.OutputFile, "o", "", "输出文件 (缩写)")
	fs.StringVar(&opt.OutputFormat, "format", "text", "输出格式: text/json")
	fs.StringVar(&opt.OutputFormat, "f", "text", "输出格式 (缩写)")

	fs.Usage = func() {
		fmt.Println("[子域名枚举] subdomain")
		fmt.Println()
		fmt.Println("用法: qiankunquan subdomain [选项]")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  qiankunquan subdomain -d example.com")
		fmt.Println("  qiankunquan subdomain -d target.com -w subdomains.txt")
		fmt.Println("  qiankunquan subdomain -d example.com -o subdomains.json -f json")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if opt.Domain == "" {
		return nil, fmt.Errorf("必须指定目标域名 (-d <域名>)")
	}

	opt.Domain = strings.TrimPrefix(opt.Domain, "www.")

	return opt, nil
}

func (p *Parser) ParseVulnArgs(args []string) (*VulnOptions, error) {
	fs := flag.NewFlagSet("vuln", flag.ExitOnError)
	opt := &VulnOptions{}

	fs.StringVar(&opt.Service, "service", "", "按服务名查询 (ssh/mysql/redis等)")
	fs.StringVar(&opt.Service, "s", "", "按服务名查询 (缩写)")
	fs.StringVar(&opt.CVE, "cve", "", "按CVE编号查询 (CVE-2023-xxxx)")
	fs.StringVar(&opt.CNVD, "cnvd", "", "按CNVD编号查询")
	fs.StringVar(&opt.CMS, "cms", "", "按CMS查询 (dedecms/thinkphp/wordpress等)")
	fs.BoolVar(&opt.ShowPOC, "poc", true, "显示POC命令")
	fs.BoolVar(&opt.ShowEXP, "exp", true, "显示EXP命令")
	fs.StringVar(&opt.OutputFile, "output", "", "输出文件")
	fs.StringVar(&opt.OutputFile, "o", "", "输出文件 (缩写)")

	fs.Usage = func() {
		fmt.Println("[漏洞利用索引] vuln")
		fmt.Println()
		fmt.Println("用法: qiankunquan vuln [选项]")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("支持的服务:")
		fmt.Println("  ssh, ftp, smb, mysql, redis, mongodb, elasticsearch,")
		fmt.Println("  postgresql, oracle, rdp, telnet, vnc, dns, ldap,")
		fmt.Println("  docker, kubernetes, zookeeper, nfs, tomcat, ...")
		fmt.Println()
		fmt.Println("支持的CMS:")
		fmt.Println("  dedecms, thinkphp, wordpress, discuz, phpcms,")
		fmt.Println("  ecshop, metinfo, joomla, drupal, typecho, ...")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  qiankunquan vuln -s redis")
		fmt.Println("  qiankunquan vuln --cms thinkphp")
		fmt.Println("  qiankunquan vuln -cve CVE-2021-44228")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if opt.Service == "" && opt.CVE == "" && opt.CNVD == "" && opt.CMS == "" {
		return nil, fmt.Errorf("请至少指定一个查询条件 (-s/-cve/--cnvd/--cms)")
	}

	return opt, nil
}

func (p *Parser) ParseAttackArgs(args []string) (*AttackOptions, error) {
	fs := flag.NewFlagSet("attack", flag.ExitOnError)
	opt := &AttackOptions{}

	fs.StringVar(&opt.Target, "target", "", "目标地址")
	fs.StringVar(&opt.Target, "t", "", "目标地址 (缩写)")
	fs.StringVar(&opt.InputFile, "input", "", "输入扫描结果文件 (JSON格式)")
	fs.StringVar(&opt.InputFile, "i", "", "输入扫描结果文件 (缩写)")
	fs.StringVar(&opt.OutputFile, "output", "", "输出文件")
	fs.StringVar(&opt.OutputFile, "o", "", "输出文件 (缩写)")
	fs.StringVar(&opt.OutputFormat, "format", "text", "输出格式: text/markdown")
	fs.StringVar(&opt.OutputFormat, "f", "text", "输出格式 (缩写)")
	fs.BoolVar(&opt.Verbose, "verbose", false, "详细模式")
	fs.BoolVar(&opt.Verbose, "v", false, "详细模式 (缩写)")
	fs.StringVar(&opt.Phase, "phase", "all", "攻击阶段: all/recon/initial/lateral/exec/privesc")
	fs.BoolVar(&opt.ShowATTACK, "attack", true, "显示ATT&CK映射")

	fs.Usage = func() {
		fmt.Println("[攻击路径推荐] attack")
		fmt.Println()
		fmt.Println("用法: qiankunquan attack [选项]")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("攻击阶段:")
		fmt.Println("  all       全部阶段")
		fmt.Println("  recon     侦察阶段")
		fmt.Println("  initial   初始访问")
		fmt.Println("  lateral   横向移动")
		fmt.Println("  exec      命令执行")
		fmt.Println("  privesc   权限提升")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  qiankunquan attack -t example.com")
		fmt.Println("  qiankunquan attack -i scan_result.json -o attack_path.md")
		fmt.Println("  qiankunquan attack -t target.com --phase initial -f markdown")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if opt.Target == "" && opt.InputFile == "" {
		return nil, fmt.Errorf("请指定目标 (-t) 或输入文件 (-i)")
	}

	return opt, nil
}

func (p *Parser) ParseReportArgs(args []string) (*ReportOptions, error) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	opt := &ReportOptions{}

	fs.StringVar(&opt.Target, "target", "", "目标地址")
	fs.StringVar(&opt.Target, "t", "", "目标地址 (缩写)")
	fs.StringVar(&opt.InputFile, "input", "", "输入扫描结果文件 (JSON)")
	fs.StringVar(&opt.InputFile, "i", "", "输入扫描结果文件 (缩写)")
	fs.StringVar(&opt.OutputFile, "output", "redteam_report.html", "输出文件")
	fs.StringVar(&opt.OutputFile, "o", "redteam_report.html", "输出文件 (缩写)")
	fs.StringVar(&opt.OutputFormat, "format", "html", "输出格式: html/markdown")
	fs.StringVar(&opt.OutputFormat, "f", "html", "输出格式 (缩写)")
	fs.StringVar(&opt.Title, "title", "红队评估报告", "报告标题")
	fs.StringVar(&opt.Company, "company", "", "客户名称")
	fs.StringVar(&opt.Assessor, "assessor", "乾坤圈红队", "评估人员")
	fs.BoolVar(&opt.FullScan, "full", false, "执行全量扫描后生成报告")
	fs.BoolVar(&opt.Verbose, "verbose", false, "详细模式")
	fs.BoolVar(&opt.Verbose, "v", false, "详细模式 (缩写)")

	fs.Usage = func() {
		fmt.Println("[红队报告生成] report")
		fmt.Println()
		fmt.Println("用法: qiankunquan report [选项]")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("报告模板:")
		fmt.Println("  html      交互式HTML报告（含图表、ATT&CK矩阵）")
		fmt.Println("  markdown  Markdown格式报告（便于编辑）")
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  qiankunquan report -t example.com -o report.html")
		fmt.Println("  qiankunquan report -i full_scan.json -f markdown -o report.md")
		fmt.Println("  qiankunquan report --full -t target.com --company \"某某科技\"")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if opt.Target == "" && opt.InputFile == "" {
		return nil, fmt.Errorf("请指定目标 (-t) 或输入文件 (-i)")
	}

	return opt, nil
}

func (p *Parser) ParseUpdateArgs(args []string) (*UpdateOptions, error) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	opt := &UpdateOptions{}

	fs.BoolVar(&opt.FullUpdate, "full", false, "全量更新")
	fs.BoolVar(&opt.CNVD, "cnvd", true, "更新CNVD漏洞库")
	fs.BoolVar(&opt.CMS, "cms", true, "更新CMS指纹库")
	fs.BoolVar(&opt.Exploit, "exploit", true, "更新利用脚本索引")
	fs.StringVar(&opt.Proxy, "proxy", "", "代理地址")
	fs.BoolVar(&opt.Verbose, "verbose", false, "详细模式")
	fs.BoolVar(&opt.Verbose, "v", false, "详细模式 (缩写)")

	fs.Usage = func() {
		fmt.Println("[数据库更新] update")
		fmt.Println()
		fmt.Println("用法: qiankunquan update [选项]")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  qiankunquan update")
		fmt.Println("  qiankunquan update --full")
		fmt.Println("  qiankunquan update --proxy http://127.0.0.1:7890")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return opt, nil
}

func (p *Parser) ParseFullArgs(args []string) (*FullScanOptions, error) {
	fs := flag.NewFlagSet("full", flag.ExitOnError)
	opt := &FullScanOptions{}

	fs.StringVar(&opt.Target, "target", "", "目标地址")
	fs.StringVar(&opt.Target, "t", "", "目标地址 (缩写)")
	fs.StringVar(&opt.OutputFile, "output", "", "输出文件")
	fs.StringVar(&opt.OutputFile, "o", "", "输出文件 (缩写)")
	fs.StringVar(&opt.OutputFormat, "format", "html", "输出格式: html/json/markdown")
	fs.StringVar(&opt.OutputFormat, "f", "html", "输出格式 (缩写)")
	fs.StringVar(&opt.PortRange, "ports", "top1000", "端口范围")
	fs.StringVar(&opt.PortRange, "p", "top1000", "端口范围 (缩写)")
	fs.IntVar(&opt.Threads, "threads", 300, "并发线程数")
	fs.IntVar(&opt.Threads, "th", 300, "并发线程数 (缩写)")
	fs.BoolVar(&opt.Subdomain, "subdomain", true, "子域名枚举")
	fs.BoolVar(&opt.PortScan, "portscan", true, "端口扫描")
	fs.BoolVar(&opt.WebScan, "web", true, "Web侦察")
	fs.BoolVar(&opt.AttackPath, "attack", true, "攻击路径推荐")
	fs.BoolVar(&opt.VulnIndex, "vuln", true, "漏洞利用索引")
	fs.BoolVar(&opt.Verbose, "verbose", false, "详细模式")
	fs.BoolVar(&opt.Verbose, "v", false, "详细模式 (缩写)")

	fs.Usage = func() {
		fmt.Println("[全量侦察] full")
		fmt.Println()
		fmt.Println("用法: qiankunquan full [选项]")
		fmt.Println()
		fmt.Println("一站式红队侦察：子域名 + 端口 + Web + 漏洞 + 攻击路径")
		fmt.Println()
		fmt.Println("选项:")
		fs.PrintDefaults()
		fmt.Println()
		fmt.Println("示例:")
		fmt.Println("  qiankunquan full -t example.com")
		fmt.Println("  qiankunquan full -t target.com -o report.html -f html")
		fmt.Println("  qiankunquan full -t 192.168.1.0/24 --subdomain=false")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if opt.Target == "" {
		return nil, fmt.Errorf("必须指定目标 (-t <目标>)")
	}

	return opt, nil
}

type WebScanOptions struct {
	URL          string
	DirScan      bool
	CMSDetect    bool
	WAFDetect    bool
	TechDetect   bool
	Threads      int
	Timeout      int
	Wordlist     string
	OutputFile   string
	OutputFormat string
	Verbose      bool
	Proxy        string
	UserAgent    string
	Cookie       string
}

type SubdomainOptions struct {
	Domain       string
	Wordlist     string
	Threads      int
	DNSEnum      bool
	HTTPCheck    bool
	OutputFile   string
	OutputFormat string
	Verbose      bool
}

type VulnOptions struct {
	Service    string
	CVE        string
	CNVD       string
	CMS        string
	ShowPOC    bool
	ShowEXP    bool
	OutputFile string
}

type AttackOptions struct {
	Target      string
	InputFile   string
	OutputFile  string
	OutputFormat string
	Verbose     bool
	Phase       string
	ShowATTACK  bool
}

type ReportOptions struct {
	Target       string
	InputFile    string
	OutputFile   string
	OutputFormat string
	Title        string
	Company      string
	Assessor     string
	FullScan     bool
	Verbose      bool
}

type UpdateOptions struct {
	FullUpdate bool
	CNVD       bool
	CMS        bool
	Exploit    bool
	Proxy      string
	Verbose    bool
}

type FullScanOptions struct {
	Target       string
	OutputFile   string
	OutputFormat string
	PortRange    string
	Threads      int
	Subdomain    bool
	PortScan     bool
	WebScan      bool
	AttackPath   bool
	VulnIndex    bool
	Verbose      bool
}

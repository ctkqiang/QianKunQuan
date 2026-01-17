package cli

import (
	"flag"
	"fmt"
	"os"

	"QianKunQuan/internal/model"
)

type Parser struct {
	Options model.ScanOptions
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse() error {
	var help bool

	flag.StringVar(&p.Options.Target, "target", "", "目标IP地址或域名")
	flag.StringVar(&p.Options.PortRange, "ports", "", "端口范围 (如: 1-1000,80,443)")
	flag.IntVar(&p.Options.Timeout, "timeout", 2, "连接超时时间(秒)")
	flag.IntVar(&p.Options.Threads, "threads", 100, "并发线程数")
	flag.StringVar(&p.Options.OutputFile, "output", "", "输出文件")
	flag.StringVar(&p.Options.OutputFormat, "format", "text", "输出格式 (text, json, csv)")
	flag.BoolVar(&p.Options.UpdateDB, "update", false, "更新CVE数据库")
	flag.BoolVar(&p.Options.Verbose, "verbose", false, "显示详细信息")
	flag.BoolVar(&help, "help", false, "显示帮助")

	flag.Parse()

	if help {
		p.printHelp()
		os.Exit(0)
	}

	if p.Options.Target == "" {
		return fmt.Errorf("必须指定目标地址")
	}

	return nil
}

func (p *Parser) printHelp() {
	fmt.Println("乾坤圈 - Go语言端口扫描与CVE检测工具")
	fmt.Println("")
	fmt.Println("使用方法: QianKunQuan [选项]")
	fmt.Println("")
	fmt.Println("选项:")
	fmt.Println("  -target string    目标IP地址或域名")
	fmt.Println("  -ports string     端口范围 (默认: 常见端口)")
	fmt.Println("  -timeout int      连接超时时间(秒) (默认: 2)")
	fmt.Println("  -threads int      并发线程数 (默认: 100)")
	fmt.Println("  -output string    输出文件")
	fmt.Println("  -format string    输出格式 (text, json, csv) (默认: text)")
	fmt.Println("  -update           更新CVE数据库")
	fmt.Println("  -verbose          显示详细信息")
	fmt.Println("  -help             显示帮助")
	fmt.Println("")
	fmt.Println("示例:")
	fmt.Println("  QianKunQuan -target 192.168.1.1 -ports 1-1000")
	fmt.Println("  QianKunQuan -target example.com -ports 80,443,8080 -output result.json -format json")
}

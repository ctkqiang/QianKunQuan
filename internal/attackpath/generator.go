package attackpath

import (
	"fmt"
	"strings"

	"QianKunQuan/internal/model"
)

type AttackPathGenerator struct{}

func NewAttackPathGenerator() *AttackPathGenerator {
	return &AttackPathGenerator{}
}

func (apg *AttackPathGenerator) GenerateFromPortScan(scanResult *model.ScanResult) []model.AttackPath {
	var paths []model.AttackPath
	seen := make(map[string]bool)

	for _, port := range scanResult.Ports {
		if port.State != "open" {
			continue
		}

		service := strings.ToLower(port.Service.Name)
		version := port.Service.Version

		servicePaths := apg.getAttackPathsForService(service, version)
		for _, p := range servicePaths {
			key := p.Technique
			if !seen[key] {
				seen[key] = true
				paths = append(paths, p)
			}
		}
	}

	return paths
}

func (apg *AttackPathGenerator) GenerateFromWebScan(webResult *model.WebScanResult) []model.AttackPath {
	var paths []model.AttackPath
	seen := make(map[string]bool)

	if webResult.CMS != "" {
		cmsPaths := apg.getAttackPathsForCMS(strings.ToLower(webResult.CMS))
		for _, p := range cmsPaths {
			key := p.Technique
			if !seen[key] {
				seen[key] = true
				paths = append(paths, p)
			}
		}
	}

	if webResult.WAF != "" {
		wafBypass := model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "防御绕过",
			Technique:   "WAF绕过",
			Description: fmt.Sprintf("检测到WAF: %s，需要进行WAF绕过测试", webResult.WAF),
			Steps: []string{
				"识别WAF类型和规则特征",
				"使用分块传输、Unicode编码绕过",
				"测试HTTP方法变更绕过",
				"尝试User-Agent和Referer伪造",
				"使用Payload编码变形",
			},
			Tools: []string{"sqlmap --tamper", "xray --waf", "burp suite", "nuclei"},
			Risk:  "中",
		}
		paths = append(paths, wafBypass)
	}

	for _, dir := range webResult.URLs {
		if dir.StatusCode == 403 || dir.StatusCode == 401 {
			continue
		}
		if strings.Contains(dir.Path, "admin") || strings.Contains(dir.Path, "login") {
			adminPath := model.AttackPath{
				Phase:       "初始访问",
				Tactic:      "凭证访问",
				Technique:   "后台弱口令",
				Description: fmt.Sprintf("发现后台入口: %s，可尝试弱口令爆破", dir.Path),
				Steps: []string{
					"收集后台管理员用户名",
					"使用常见密码字典爆破",
					"测试默认账号密码",
					"检查是否存在验证码绕过",
				},
				Tools: []string{"hydra", "burp intruder", "superdict", "xbruteforcer"},
				Risk:  "中",
			}
			key := "admin-brute-" + dir.Path
			if !seen[key] {
				seen[key] = true
				paths = append(paths, adminPath)
			}
		}
		if strings.Contains(dir.Path, ".git") {
			gitLeak := model.AttackPath{
				Phase:       "收集",
				Tactic:      "信息泄露",
				Technique:   "Git源码泄露",
				Description: "发现.git目录泄露，可获取完整源码",
				Steps: []string{
					"使用GitHack或GitTools下载源码",
					"分析源码寻找硬编码密钥",
					"查找数据库配置文件",
					"审计代码漏洞",
				},
				Tools: []string{"GitHack", "GitTools", "gitleaks", "trufflehog"},
				Risk:  "严重",
			}
			if !seen["git-leak"] {
				seen["git-leak"] = true
				paths = append(paths, gitLeak)
			}
		}
	}

	return paths
}

func (apg *AttackPathGenerator) getAttackPathsForService(service, version string) []model.AttackPath {
	var paths []model.AttackPath

	switch {
	case strings.Contains(service, "ssh"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "凭证访问",
			Technique:   "SSH弱口令/密钥",
			Description: "SSH服务开放，可尝试密码喷洒或密钥攻击",
			Steps: []string{
				"收集有效用户名（枚举或社工）",
				"使用常见密码进行密码喷洒",
				"检查是否支持密钥认证",
				"测试SSH配置漏洞",
			},
			Tools: []string{"hydra", "patator", "medusa", "nmap --script ssh-*"},
			Risk:  "高",
		})
		paths = append(paths, model.AttackPath{
			Phase:       "侦察",
			Tactic:      "发现",
			Technique:   "SSH信息收集",
			Description: "通过SSH服务 banner 和脚本获取系统信息",
			Steps: []string{
				"获取SSH版本和算法列表",
				"用户名枚举测试",
				"检查认证方式",
			},
			Tools: []string{"nmap", "ssh-audit", "ssh"},
			Risk:  "低",
		})

	case strings.Contains(service, "ftp"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "发现",
			Technique:   "FTP匿名访问",
			Description: "FTP服务开放，测试匿名登录",
			Steps: []string{
				"测试anonymous/anonymous登录",
				"浏览可访问目录",
				"下载敏感文件",
				"测试上传权限",
			},
			Tools: []string{"ftp", "nmap --script ftp-*", "filezilla"},
			Risk:  "高",
		})

	case strings.Contains(service, "smb") || strings.Contains(service, "microsoft-ds"):
		paths = append(paths, model.AttackPath{
			Phase:       "侦察",
			Tactic:      "发现",
			Technique:   "SMB枚举",
			Description: "SMB服务开放，可枚举用户、共享、域信息",
			Steps: []string{
				"空会话枚举用户和组",
				"列出共享目录",
				"探测操作系统版本",
				"检查SMBv1（永恒之蓝）",
			},
			Tools: []string{"enum4linux", "smbclient", "crackmapexec", "nmap"},
			Risk:  "中",
		})
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "SMB远程代码执行",
			Description: "检测SMB相关RCE漏洞（永恒之蓝等）",
			Steps: []string{
				"检测MS17-010（永恒之蓝）",
				"检查SMBv1是否启用",
				"验证系统补丁状态",
			},
			Tools: []string{"nmap --script smb-vuln-*", "metasploit", "crackmapexec"},
			Risk:  "严重",
		})

	case strings.Contains(service, "mysql"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "凭证访问",
			Technique:   "MySQL弱口令",
			Description: "MySQL数据库开放，可尝试弱口令登录",
			Steps: []string{
				"测试root空密码",
				"密码爆破",
				"登录后执行UDF提权",
				"导出webshell",
			},
			Tools: []string{"hydra", "mysql", "metasploit", "sqlmap"},
			Risk:  "高",
		})

	case strings.Contains(service, "redis"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "Redis未授权访问",
			Description: "Redis默认无认证，可直接访问并getshell",
			Steps: []string{
				"验证未授权访问",
				"写SSH公钥getshell",
				"写webshell（如果有web路径）",
				"主从复制RCE",
			},
			Tools: []string{"redis-cli", "metasploit", "python-redis"},
			Risk:  "严重",
		})

	case strings.Contains(service, "mongodb"):
		paths = append(paths, model.AttackPath{
			Phase:       "收集",
			Tactic:      "发现",
			Technique:   "MongoDB未授权访问",
			Description: "MongoDB默认无认证，可直接读取全部数据",
			Steps: []string{
				"验证未授权访问",
				"列出所有数据库",
				"导出敏感数据",
				"查找管理员凭证",
			},
			Tools: []string{"mongo", "nosqlmap", "metasploit"},
			Risk:  "高",
		})

	case strings.Contains(service, "elasticsearch"):
		paths = append(paths, model.AttackPath{
			Phase:       "收集",
			Tactic:      "发现",
			Technique:   "Elasticsearch未授权访问",
			Description: "ES默认无认证，可读取/修改数据，旧版本可能RCE",
			Steps: []string{
				"列出所有索引",
				"读取敏感数据",
				"检测Groovy脚本RCE（CVE-2014-3120）",
				"检查版本是否有已知RCE",
			},
			Tools: []string{"curl", "kibana", "metasploit", "nuclei"},
			Risk:  "高",
		})

	case strings.Contains(service, "rdp") || strings.Contains(service, "ms-wbt"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "凭证访问",
			Technique:   "RDP弱口令/BlueKeep",
			Description: "RDP服务开放，可尝试弱口令或BlueKeep漏洞",
			Steps: []string{
				"检测CVE-2019-0708（BlueKeep）",
				"密码爆破登录",
				"检查RDP安全配置",
			},
			Tools: []string{"crackmapexec", "hydra", "xfreerdp", "nmap"},
			Risk:  "高",
		})

	case strings.Contains(service, "telnet"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "凭证访问",
			Technique:   "Telnet弱口令/明文传输",
			Description: "Telnet明文传输，易被中间人截获密码",
			Steps: []string{
				"密码爆破",
				"网络窃听（中间人）",
				"获取shell后提权",
			},
			Tools: []string{"hydra", "telnet", "bettercap"},
			Risk:  "高",
		})

	case strings.Contains(service, "vnc"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "凭证访问",
			Technique:   "VNC弱口令/无密码",
			Description: "VNC服务可能无密码或弱密码，可直接控制桌面",
			Steps: []string{
				"检查是否无密码访问",
				"密码爆破",
				"截获屏幕内容",
			},
			Tools: []string{"vncviewer", "hydra", "vncsnapshot"},
			Risk:  "高",
		})

	case strings.Contains(service, "docker"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "Docker API未授权",
			Description: "Docker Remote API未授权可直接getshell",
			Steps: []string{
				"验证未授权访问",
				"创建挂载宿主机根目录的容器",
				"chroot获取宿主机root权限",
			},
			Tools: []string{"docker", "curl", "metasploit"},
			Risk:  "严重",
		})

	case strings.Contains(service, "kubernetes"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "K8s API未授权",
			Description: "K8s API Server未授权可控制整个集群",
			Steps: []string{
				"探测API接口权限",
				"列出所有Pod/Namespace",
				"创建特权Pod逃逸",
				"获取集群控制权限",
			},
			Tools: []string{"kubectl", "kube-hunter", "shark"},
			Risk:  "严重",
		})

	case strings.Contains(service, "zookeeper"):
		paths = append(paths, model.AttackPath{
			Phase:       "收集",
			Tactic:      "发现",
			Technique:   "ZooKeeper未授权",
			Description: "ZooKeeper默认无认证，可读取/修改节点数据",
			Steps: []string{
				"列出所有znode",
				"读取配置和敏感数据",
				"查找服务注册信息",
			},
			Tools: []string{"zkCli.sh", "nc", "zoomeye"},
			Risk:  "中",
		})

	case strings.Contains(service, "postgresql"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "凭证访问",
			Technique:   "PostgreSQL弱口令",
			Description: "PostgreSQL数据库开放，可尝试弱口令",
			Steps: []string{
				"测试postgres默认账号",
				"密码爆破",
				"UDF/Copy执行命令",
				"大对象写入文件",
			},
			Tools: []string{"psql", "hydra", "metasploit"},
			Risk:  "高",
		})

	case strings.Contains(service, "oracle"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "凭证访问",
			Technique:   "Oracle默认密码",
			Description: "Oracle数据库有大量默认账号密码",
			Steps: []string{
				"测试SYS/SYSTEM默认密码",
				"TNS监听器信息泄露",
				"密码爆破",
				"Java存储过程RCE",
			},
			Tools: []string{"sqlplus", "odat", "nmap --script oracle-*"},
			Risk:  "高",
		})

	case strings.Contains(service, "ldap"):
		paths = append(paths, model.AttackPath{
			Phase:       "侦察",
			Tactic:      "发现",
			Technique:   "LDAP匿名绑定",
			Description: "LDAP服务允许匿名查询，可枚举域用户",
			Steps: []string{
				"匿名绑定查询",
				"枚举用户/组/计算机",
				"查找高价值目标",
				"收集域信息",
			},
			Tools: []string{"ldapsearch", "enum4linux", "bloodhound"},
			Risk:  "中",
		})

	case strings.Contains(service, "dns"):
		paths = append(paths, model.AttackPath{
			Phase:       "侦察",
			Tactic:      "发现",
			Technique:   "DNS区域传送",
			Description: "DNS服务器可能允许区域传送，获取全域名记录",
			Steps: []string{
				"测试AXFR区域传送",
				"枚举子域名",
				"收集网络拓扑信息",
			},
			Tools: []string{"dig", "nslookup", "dnsrecon", "fierce"},
			Risk:  "中",
		})
	}

	return paths
}

func (apg *AttackPathGenerator) getAttackPathsForCMS(cms string) []model.AttackPath {
	var paths []model.AttackPath

	switch {
	case strings.Contains(cms, "dedecms"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "织梦CMS漏洞利用",
			Description: "DedeCMS存在多个已知漏洞，可尝试getshell",
			Steps: []string{
				"确定CMS版本",
				"检查后台路径（默认/dede）",
				"尝试弱口令登录后台",
				"测试变量覆盖、SQL注入等漏洞",
				"后台上传getshell",
			},
			Tools: []string{"nuclei", "xray", "burp suite"},
			Risk:  "高",
		})

	case strings.Contains(cms, "thinkphp"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "ThinkPHP RCE",
			Description: "ThinkPHP 5.x存在多处RCE漏洞，可直接getshell",
			Steps: []string{
				"检测ThinkPHP版本",
				"测试5.x RCE（CVE-2018-20062等）",
				"测试2.x RCE",
				"写入webshell",
			},
			Tools: []string{"nuclei", "xray", "metasploit"},
			Risk:  "严重",
		})

	case strings.Contains(cms, "wordpress"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "WordPress漏洞链",
			Description: "WordPress核心+插件+主题存在大量漏洞",
			Steps: []string{
				"枚举用户名（REST API/WP-JSON）",
				"密码爆破（xmlrpc）",
				"扫描插件漏洞",
				"后台主题/插件编辑getshell",
			},
			Tools: []string{"wpscan", "nuclei", "xray"},
			Risk:  "中",
		})

	case strings.Contains(cms, "discuz"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "Discuz!漏洞利用",
			Description: "Discuz!存在多个已知漏洞，包括SSRF、SQL注入等",
			Steps: []string{
				"确定Discuz版本",
				"检查UC_KEY配置",
				"测试SSRF漏洞",
				"后台getshell",
			},
			Tools: []string{"nuclei", "xray", "burp suite"},
			Risk:  "中",
		})

	case strings.Contains(cms, "phpcms"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "PHPCMS漏洞利用",
			Description: "PHPCMS存在SQL注入、文件上传等漏洞",
			Steps: []string{
				"确定版本",
				"测试SQL注入",
				"测试文件上传",
				"后台getshell",
			},
			Tools: []string{"nuclei", "xray", "sqlmap"},
			Risk:  "中",
		})

	case strings.Contains(cms, "ecshop"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "ECShop漏洞利用",
			Description: "ECShop存在SQL注入、代码执行等漏洞",
			Steps: []string{
				"确定版本",
				"测试SQL注入",
				"测试代码执行",
			},
			Tools: []string{"nuclei", "xray", "sqlmap"},
			Risk:  "中",
		})

	case strings.Contains(cms, "joomla"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "Joomla漏洞利用",
			Description: "Joomla存在多个已知RCE漏洞",
			Steps: []string{
				"确定版本",
				"测试com_fields SQL注入（CVE-2017-8917）",
				"后台模板编辑getshell",
			},
			Tools: []string{"joomscan", "nuclei", "metasploit"},
			Risk:  "中",
		})

	case strings.Contains(cms, "drupal"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "Drupal漏洞利用",
			Description: "Drupal存在Drupalgeddon系列RCE漏洞",
			Steps: []string{
				"确定版本",
				"测试Drupalgeddon系列漏洞",
				"后台模块上传getshell",
			},
			Tools: []string{"droopescan", "nuclei", "metasploit"},
			Risk:  "高",
		})

	case strings.Contains(cms, "typecho"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "Typecho反序列化RCE",
			Description: "Typecho install.php反序列化可直接getshell",
			Steps: []string{
				"检查install.php是否存在",
				"构造反序列化payload",
				"写入webshell",
			},
			Tools: []string{"nuclei", "xray", "python"},
			Risk:  "高",
		})

	case strings.Contains(cms, "ruoyi"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "若依管理系统漏洞",
			Description: "若依(RuoYi)系统存在多处漏洞",
			Steps: []string{
				"确定版本（Vue/PHP/Java版）",
				"测试未授权访问",
				"测试SQL注入",
				"后台定时任务getshell",
			},
			Tools: []string{"nuclei", "xray", "burp suite"},
			Risk:  "高",
		})

	case strings.Contains(cms, "tomcat"):
		paths = append(paths, model.AttackPath{
			Phase:       "初始访问",
			Tactic:      "执行",
			Technique:   "Tomcat管理器部署WAR",
			Description: "Tomcat Manager弱口令可部署WAR包getshell",
			Steps: []string{
				"检测Manager/Host Manager路径",
				"弱口令爆破（tomcat/tomcat等）",
				"部署WAR包",
				"获取webshell",
			},
			Tools: []string{"metasploit", "nmap", "hydra"},
			Risk:  "高",
		})
	}

	return paths
}

func getSeverityTag(severity string) string {
	switch strings.ToLower(severity) {
	case "严重", "critical":
		return "CRIT"
	case "高", "high":
		return "HIGH"
	case "中", "medium":
		return "MED"
	case "低", "low":
		return "LOW"
	default:
		return "INFO"
	}
}

func (apg *AttackPathGenerator) FormatAttackPaths(paths []model.AttackPath) string {
	var builder strings.Builder

	if len(paths) == 0 {
		builder.WriteString("\n[!] 未生成攻击路径建议\n")
		return builder.String()
	}

	builder.WriteString("\n")
	builder.WriteString("[攻击路径推荐]\n")
	builder.WriteString(strings.Repeat("═", 70) + "\n")
	builder.WriteString(fmt.Sprintf("共生成 %d 条攻击路径建议\n\n", len(paths)))

	phases := map[string][]model.AttackPath{}
	for _, p := range paths {
		phases[p.Phase] = append(phases[p.Phase], p)
	}

	phaseOrder := []string{"侦察", "收集", "初始访问", "执行", "凭证访问", "权限提升", "横向移动", "持久化", "防御绕过"}

	for _, phase := range phaseOrder {
		phasePaths, ok := phases[phase]
		if !ok || len(phasePaths) == 0 {
			continue
		}

		builder.WriteString(fmt.Sprintf("[阶段] %s (%d条)\n", phase, len(phasePaths)))
		builder.WriteString(strings.Repeat("─", 70) + "\n")

		for i, p := range phasePaths {
			riskTag := getSeverityTag(p.Risk)
			builder.WriteString(fmt.Sprintf("  [%d] [%s] %s\n", i+1, riskTag, p.Technique))
			builder.WriteString(fmt.Sprintf("      战术: %s | 风险: %s\n", p.Tactic, p.Risk))
			builder.WriteString(fmt.Sprintf("      描述: %s\n", p.Description))
			builder.WriteString(fmt.Sprintf("      工具: %s\n", strings.Join(p.Tools, ", ")))

			if len(p.Steps) > 0 {
				builder.WriteString("      攻击步骤:\n")
				for j, step := range p.Steps {
					builder.WriteString(fmt.Sprintf("        %d. %s\n", j+1, step))
				}
			}
			builder.WriteString("\n")
		}
	}

	builder.WriteString(strings.Repeat("═", 70) + "\n")
	builder.WriteString(fmt.Sprintf("[完成] 路径分析结束，共 %d 条攻击建议\n", len(paths)))
	builder.WriteString("[警告] 仅供授权安全评估使用，违法必究\n")

	return builder.String()
}

package main

import (
	"flag"
	"fmt"
	"github.com/guchangan1/CodeVulnScan/rule"
	"github.com/guchangan1/CodeVulnScan/scanner"
	"os"
	"strings"
)

// 版本信息
const version = "1.0.0"

// 命令行参数
type Options struct {
	Language      string
	ScanDir       string
	ExcludeDir    string
	FileExtension string
	Verbose       bool
	WorkerCount   int
	MaxDepth      int
	OutputCSV     string // CSV输出文件路径
}

func main() {
	// 打印banner
	printBanner()

	// 解析命令行参数
	opts := parseOptions()

	// 验证命令行参数
	if err := validateOptions(opts); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// 准备扫描参数
	var fileExtensions []string

	// 设置文件扩展名
	if opts.FileExtension != "" {
		fileExtensions = strings.Split(opts.FileExtension, ",")
		// 确保每个扩展名都以.开头
		for i, ext := range fileExtensions {
			if !strings.HasPrefix(ext, ".") {
				fileExtensions[i] = "." + ext
			}
		}
	} else {
		// 根据语言确定默认扩展名
		fileExtensions = getDefaultExtensions(opts.Language)
	}

	// 加载规则
	rules, err := loadRules(opts.Language)
	if err != nil {
		fmt.Printf("加载规则失败: %v\n", err)
		os.Exit(1)
	}

	// 设置最大深度，如果未指定则使用默认值100
	maxDepth := 100
	if opts.MaxDepth > 0 {
		maxDepth = opts.MaxDepth
	}

	// 开始扫描
	results, err := scanFiles(opts.ScanDir, opts.ExcludeDir, fileExtensions, rules, opts.Verbose, maxDepth, opts.WorkerCount)
	if err != nil {
		fmt.Printf("扫描失败: %v\n", err)
		os.Exit(1)
	}

	// 输出结果
	printResults(results)

	// 如果指定了CSV输出文件，则导出结果
	if opts.OutputCSV != "" {
		err = scanner.ExportToCSV(results, opts.OutputCSV)
		if err != nil {
			fmt.Printf("导出CSV失败: %v\n", err)
			os.Exit(1)
		}
	}
}

// 打印banner
func printBanner() {
	banner := `
   _____          _      _   _       _       _____                 
  / ____|        | |    | \ | |     | |     / ____|                
 | |     ___   __| | ___|  \| |_   _| |_ __| (___   ___ __ _ _ __  
 | |    / _ \ / _' |/ _ \ . ' | | | | | '_ \\___ \ / __/ _' | '_ \ 
 | |___| (_) | (_| |  __/ |\  | |_| | | | | |___) | (_| (_| | | | |
  \_____\___/ \__,_|\___|_| \_|\__,_|_|_| |_|_____/ \___\__,_|_| |_|
                                                                   
                                                 Version: ` + version + `
`
	fmt.Println(banner)
	fmt.Println("一款使用正则语法进行匹配目标代码漏洞Sink点的代码审计扫描器，用于红队快速定位漏洞点。")
	fmt.Println("注：发现sink点不代表目标存在漏洞，需要红队师傅自行跟踪Source点。\n")
}

// 解析命令行参数
func parseOptions() *Options {
	opts := &Options{}

	flag.StringVar(&opts.Language, "T", "", "审计模式，根据模式选择对应的规则库。\n可选值：java、net、php、python、leak\n注：java默认指定.java后缀，net默认指定.cs，php默认指定.php，当使用-e时可以进行主动指定后缀\n无论选择哪种语言，都会自动加载敏感信息扫描规则，扫描配置文件中的敏感信息\n也可以单独选择leak模式，只扫描敏感信息")
	flag.StringVar(&opts.ScanDir, "d", "", "要扫描的目录")
	flag.StringVar(&opts.ExcludeDir, "nd", "", "排除目录")
	flag.StringVar(&opts.FileExtension, "e", "", "主动指定扫描的文件后缀，多个后缀用逗号分隔")
	flag.BoolVar(&opts.Verbose, "v", false, "输出详细信息")
	flag.IntVar(&opts.WorkerCount, "w", 0, "工作协程数量，默认为0表示使用CPU核心数")
	flag.IntVar(&opts.MaxDepth, "m", 100, "最大扫描深度，默认为100")
	flag.StringVar(&opts.OutputCSV, "o", "", "将扫描结果导出到CSV文件")

	// 自定义帮助信息
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "//使用net语言的规则进行扫描\n")
		fmt.Fprintf(os.Stderr, "%s -T net -d /home/xxxx\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "//使用java语言的规则进行扫描\n")
		fmt.Fprintf(os.Stderr, "%s -T java -d /home/xxxx\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "//使用php语言的规则进行扫描，排除resource目录\n")
		fmt.Fprintf(os.Stderr, "%s -T php -d /home/xxxx -nd /home/xxxx/resource\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "//使用python语言的规则进行扫描，排除resource目录\n")
		fmt.Fprintf(os.Stderr, "%s -T python -d /home/xxxx -nd /home/xxxx/resource\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "//专门扫描配置文件敏感信息（硬编码等）\n")
		fmt.Fprintf(os.Stderr, "%s -T leak -d /home/xxxx -e yml,java\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "//将扫描结果导出到CSV文件\n")
		fmt.Fprintf(os.Stderr, "%s -T java -d /home/xxxx -o results.csv\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "//注意：所有扫描都会自动包含敏感信息扫描，无需额外指定\n")
	}

	flag.Parse()
	return opts
}

// 验证命令行参数
func validateOptions(opts *Options) error {
	if opts.Language == "" {
		return fmt.Errorf("请指定审计语言 (-T)")
	}

	if opts.ScanDir == "" {
		return fmt.Errorf("请指定要扫描的目录 (-d)")
	}

	// 检查目录是否存在
	if _, err := os.Stat(opts.ScanDir); os.IsNotExist(err) {
		return fmt.Errorf("扫描目录不存在: %s", opts.ScanDir)
	}

	// 检查排除目录是否存在
	if opts.ExcludeDir != "" {
		if _, err := os.Stat(opts.ExcludeDir); os.IsNotExist(err) {
			return fmt.Errorf("排除目录不存在: %s", opts.ExcludeDir)
		}
	}

	return nil
}

// 根据语言确定默认的文件扩展名
func getDefaultExtensions(language string) []string {
	// 根据语言确定默认扩展名
	var extensions []string

	switch strings.ToLower(language) {
	case "java":
		extensions = []string{".java"}
	case "net":
		extensions = []string{".cs"}
	case "php":
		extensions = []string{".php"}
	case "python":
		extensions = []string{".py"}
	case "leak":
		// 对于敏感信息扫描，默认扫描多种配置文件
		return []string{".yml", ".yaml", ".xml", ".properties", ".config", ".json"}
	default:
		// 默认情况下，使用与语言名称相同的扩展名
		extensions = []string{"." + language}
	}

	// 如果不是专门的敏感信息扫描，则添加配置文件扩展名
	if strings.ToLower(language) != "leak" {
		// 添加常见配置文件扩展名用于敏感信息扫描
		configExtensions := []string{".yml", ".yaml", ".xml", ".properties", ".config", ".json"}
		extensions = append(extensions, configExtensions...)
	}

	return extensions
}

// 加载规则
func loadRules(language string) ([]rule.Rule, error) {
	rm := rule.NewRuleManager()

	// 加载指定语言的规则
	langRules, err := rm.LoadRules(language)
	if err != nil {
		return nil, err
	}

	// 如果指定的语言不是leak（敏感信息扫描），则额外加载敏感信息扫描规则
	if strings.ToLower(language) != "leak" {
		leakRules, err := rm.LoadRules("leak")
		if err != nil {
			// 如果加载敏感信息规则失败，仅打印警告，不影响主要扫描
			fmt.Printf("警告: 加载敏感信息扫描规则失败: %v\n", err)
		} else {
			// 合并规则
			langRules = append(langRules, leakRules...)
			fmt.Println("已自动加载敏感信息扫描规则")
		}
	}

	return langRules, nil
}

// 扫描文件
func scanFiles(scanDir, excludeDir string, extensions []string, rules []rule.Rule, verbose bool, maxDepth int, workerCount int) ([]scanner.ScanResult, error) {
	// 创建扫描器
	// 将 rule.Rule 类型转换为 scanner.Rule 类型
	scannerRules := make([]scanner.Rule, len(rules))
	for i, r := range rules {
		scannerRules[i] = scanner.Rule(r)
	}
	s := scanner.NewScanner(scanDir, excludeDir, extensions, scannerRules, verbose, maxDepth, workerCount)
	return s.Scan()
}

// 输出结果
func printResults(results []scanner.ScanResult) {
	scanner.PrintResults(results)
}

package scanner

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Rule 定义了漏洞检测规则
type Rule struct {
	FileType  string // 文件类型，如java、php、net等
	RegexRule string // 正则表达式规则
	Readme    string // 规则说明
	VulName   string // 漏洞名称
	LikeName  string // 可选，用于模糊匹配文件名
}

// ScanResult 表示扫描结果
type ScanResult struct {
	FilePath    string // 文件路径
	LineNumber  int    // 行号
	MatchedLine string // 匹配的行内容
	Rule        Rule   // 匹配的规则
}

// Scanner 结构体用于文件扫描
type Scanner struct {
	ScanDir     string   // 扫描目录
	ExcludeDir  string   // 排除目录
	Extensions  []string // 文件扩展名
	Rules       []Rule   // 规则列表
	ScanResults []ScanResult
	Verbose     bool // 详细输出模式
	MaxDepth    int  // 最大扫描深度
	WorkerCount int  // 工作协程数量
}

// NewScanner 创建一个新的扫描器
func NewScanner(scanDir, excludeDir string, extensions []string, rules []Rule, verbose bool, maxDepth int, workerCount int) *Scanner {
	// 如果未指定最大深度，则使用默认值100
	if maxDepth <= 0 {
		maxDepth = 100
	}

	// 如果未指定工作协程数量，则使用CPU核心数
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}

	return &Scanner{
		ScanDir:     scanDir,
		ExcludeDir:  excludeDir,
		Extensions:  extensions,
		Rules:       rules,
		Verbose:     verbose,
		MaxDepth:    maxDepth,
		WorkerCount: workerCount,
	}
}

// Scan 开始扫描文件
func (s *Scanner) Scan() ([]ScanResult, error) {
	// 编译所有正则表达式
	compiledRules := make(map[string]*regexp.Regexp)
	for _, rule := range s.Rules {
		re, err := regexp.Compile(rule.RegexRule)
		if err != nil {
			fmt.Printf("警告: 规则 '%s' 的正则表达式编译失败: %v\n", rule.VulName, err)
			continue
		}
		compiledRules[rule.RegexRule] = re
	}

	// 计算排除目录的绝对路径
	excludePath := ""
	if s.ExcludeDir != "" {
		absExcludePath, err := filepath.Abs(s.ExcludeDir)
		if err == nil {
			excludePath = absExcludePath
			if s.Verbose {
				fmt.Printf("排除目录: %s\n", excludePath)
			}
		}
	}

	// 打印扫描信息
	fmt.Printf("开始扫描目录: %s\n", s.ScanDir)
	fmt.Printf("扫描文件类型: %s\n", strings.Join(s.Extensions, ", "))

	// 初始化计数器和结果
	var results []ScanResult
	var scannedFiles, matchedFiles int
	startTime := time.Now()

	// 创建工作池
	workerCount := s.WorkerCount // 使用配置的工作协程数
	fileChan := make(chan string, 100)
	resultChan := make(chan []ScanResult, 100)
	errChan := make(chan error, 100)
	var wg sync.WaitGroup

	// 启动工作协程
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				// 扫描文件
				fileResults, err := s.scanFile(path, compiledRules)
				if err != nil {
					errChan <- fmt.Errorf("警告: 扫描文件 '%s' 失败: %v", path, err)
					continue
				}
				resultChan <- fileResults
			}
		}()
	}

	// 启动结果收集协程
	done := make(chan struct{})
	go func() {
		for fileResults := range resultChan {
			results = append(results, fileResults...)
			if len(fileResults) > 0 {
				matchedFiles++
				if s.Verbose {
					fmt.Printf("发现 %d 个潜在漏洞\n", len(fileResults))
				}
			}
		}
		close(done)
	}()

	// 启动错误收集协程
	errDone := make(chan struct{})
	go func() {
		for err := range errChan {
			if s.Verbose {
				fmt.Println(err)
			}
		}
		close(errDone)
	}()

	// 遍历文件
	err := filepath.Walk(s.ScanDir, func(path string, info os.FileInfo, err error) error {
		// 检查目录深度
		if info.IsDir() && path != s.ScanDir {
			relPath, err := filepath.Rel(s.ScanDir, path)
			if err != nil {
				return nil
			}

			// 计算目录深度
			depth := len(strings.Split(relPath, string(os.PathSeparator)))
			if depth > s.MaxDepth {
				if s.Verbose {
					fmt.Printf("跳过超过最大深度的目录: %s (深度: %d)\n", path, depth)
				}
				return filepath.SkipDir
			}
		}
		if err != nil {
			if s.Verbose {
				fmt.Printf("无法访问: %s, 错误: %v\n", path, err)
			}
			return nil // 忽略无法访问的文件或目录
		}

		// 跳过目录
		if info.IsDir() {
			// 检查是否是排除目录
			if excludePath != "" {
				absPath, err := filepath.Abs(path)
				if err == nil && (absPath == excludePath || strings.HasPrefix(absPath, excludePath+string(os.PathSeparator))) {
					if s.Verbose {
						fmt.Printf("跳过目录: %s\n", path)
					}
					return filepath.SkipDir
				}
			}
			return nil
		}

		// 检查文件扩展名
		extMatch := false
		for _, ext := range s.Extensions {
			if strings.HasSuffix(strings.ToLower(path), strings.ToLower(ext)) {
				extMatch = true
				break
			}
		}

		if !extMatch {
			if s.Verbose {
				fmt.Printf("跳过不匹配的文件: %s\n", path)
			}
			return nil // 跳过不匹配扩展名的文件
		}

		// 更新扫描计数
		scannedFiles++
		if s.Verbose && scannedFiles%100 == 0 {
			fmt.Printf("已扫描 %d 个文件...\r", scannedFiles)
		}

		// 将文件路径发送到通道
		fileChan <- path

		return nil
	})

	// 关闭文件通道，等待所有工作协程完成
	close(fileChan)
	wg.Wait()

	// 关闭结果通道和错误通道，等待收集协程完成
	close(resultChan)
	close(errChan)
	<-done
	<-errDone

	// 打印扫描统计信息
	elapsedTime := time.Since(startTime)
	fmt.Printf("\n扫描完成! 耗时: %.2f秒\n", elapsedTime.Seconds())
	fmt.Printf("共扫描 %d 个文件, 发现 %d 个包含潜在漏洞的文件, 共 %d 个漏洞点\n\n",
		scannedFiles, matchedFiles, len(results))

	return results, err
}

// scanFile 扫描单个文件
func (s *Scanner) scanFile(filePath string, compiledRules map[string]*regexp.Regexp) ([]ScanResult, error) {
	var results []ScanResult

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 获取文件名（用于likeName匹配）
	fileName := filepath.Base(filePath)

	// 获取文件扩展名（不带点）
	ext := strings.TrimPrefix(filepath.Ext(filePath), ".")

	// 预先筛选适用于此文件的规则，提高性能
	var applicableRules []Rule
	var applicableRegexps []*regexp.Regexp
	for _, rule := range s.Rules {
		// 检查文件类型是否匹配
		if rule.FileType != "" && !strings.EqualFold(rule.FileType, ext) {
			continue
		}

		// 检查likeName是否匹配（如果有）
		if rule.LikeName != "" && !strings.Contains(strings.ToLower(fileName), strings.ToLower(rule.LikeName)) {
			continue
		}

		// 获取编译好的正则表达式
		re, ok := compiledRules[rule.RegexRule]
		if !ok {
			continue // 跳过编译失败的规则
		}

		applicableRules = append(applicableRules, rule)
		applicableRegexps = append(applicableRegexps, re)
	}

	// 如果没有适用的规则，直接返回
	if len(applicableRules) == 0 {
		return results, nil
	}

	// 创建扫描器
	scanner := bufio.NewScanner(file)
	lineNum := 0

	// 逐行扫描文件
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// 对每个适用的规则进行匹配
		for i, re := range applicableRegexps {
			// 执行正则匹配
			if re.MatchString(line) {
				results = append(results, ScanResult{
					FilePath:    filePath,
					LineNumber:  lineNum,
					MatchedLine: line,
					Rule:        applicableRules[i],
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// PrintResults 打印扫描结果
func PrintResults(results []ScanResult) {
	if len(results) == 0 {
		fmt.Println("未发现任何漏洞点")
		return
	}

	fmt.Printf("共发现 %d 个潜在漏洞点\n\n", len(results))

	// 按漏洞类型分组
	vulnGroups := make(map[string][]ScanResult)
	for _, result := range results {
		vulnGroups[result.Rule.VulName] = append(vulnGroups[result.Rule.VulName], result)
	}

	// 打印分组结果
	for vulnName, groupResults := range vulnGroups {
		// 打印漏洞类型
		color.New(color.FgRed, color.Bold).Printf("[%s] 发现 %d 处\n", vulnName, len(groupResults))

		// 打印每个结果
		for i, result := range groupResults {
			// 打印文件路径和行号
			color.New(color.FgYellow).Printf("[%d] %s:%d\n", i+1, result.FilePath, result.LineNumber)

			// 高亮显示匹配的内容
			highlightMatchedLine(result.MatchedLine, result.Rule.RegexRule)

			// 打印规则说明
			color.New(color.FgCyan).Printf("    说明: %s\n\n", result.Rule.Readme)
		}
	}
}

// ExportToCSV 将扫描结果导出为CSV文件，支持自适应列宽
func ExportToCSV(results []ScanResult, filePath string) error {
	// 如果没有结果，创建一个空的CSV文件
	if len(results) == 0 {
		file, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("创建CSV文件失败: %v", err)
		}
		defer file.Close()

		writer := bufio.NewWriter(file)
		_, err = writer.WriteString("漏洞类型,文件路径,行号,匹配内容,规则说明\n")
		if err != nil {
			return fmt.Errorf("写入CSV头失败: %v", err)
		}

		err = writer.Flush()
		if err != nil {
			return fmt.Errorf("刷新CSV缓冲区失败: %v", err)
		}

		fmt.Printf("扫描结果已成功导出到: %s\n", filePath)
		return nil
	}

	// 计算每列的最大宽度
	colWidths := calculateColumnWidths(results)

	// 创建CSV文件
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建CSV文件失败: %v", err)
	}
	defer file.Close()

	// 写入CSV头 - 使用计算的列宽
	writer := bufio.NewWriter(file)
	header := fmt.Sprintf("%s,%s,%s,%s,%s\n",
		padString("漏洞类型", colWidths[0]),
		padString("文件路径", colWidths[1]),
		padString("行号", colWidths[2]),
		padString("匹配内容", colWidths[3]),
		padString("规则说明", colWidths[4]))
	_, err = writer.WriteString(header)
	if err != nil {
		return fmt.Errorf("写入CSV头失败: %v", err)
	}

	// 写入每一行结果
	for _, result := range results {
		// 处理CSV中的特殊字符
		vulName := strings.ReplaceAll(result.Rule.VulName, "\"", "\"\"")
		filePath := strings.ReplaceAll(result.FilePath, "\"", "\"\"")
		matchedLine := strings.ReplaceAll(result.MatchedLine, "\"", "\"\"")
		readme := strings.ReplaceAll(result.Rule.Readme, "\"", "\"\"")

		// 使用计算的列宽格式化数据
		lineNumStr := fmt.Sprintf("%d", result.LineNumber)
		line := fmt.Sprintf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
			padString(vulName, colWidths[0]),
			padString(filePath, colWidths[1]),
			padString(lineNumStr, colWidths[2]),
			padString(matchedLine, colWidths[3]),
			padString(readme, colWidths[4]))
		_, err = writer.WriteString(line)
		if err != nil {
			return fmt.Errorf("写入CSV数据失败: %v", err)
		}
	}

	// 刷新缓冲区
	err = writer.Flush()
	if err != nil {
		return fmt.Errorf("刷新CSV缓冲区失败: %v", err)
	}

	fmt.Printf("扫描结果已成功导出到: %s\n", filePath)
	return nil
}

// padString 根据指定的宽度填充字符串
func padString(s string, width int) string {
	// 如果字符串长度已经大于或等于宽度，直接返回
	if len(s) >= width {
		return s
	}

	// 填充空格到指定宽度
	return s + strings.Repeat(" ", width-len(s))
}

// calculateColumnWidths 计算CSV文件每列的最大宽度
func calculateColumnWidths(results []ScanResult) []int {
	// 初始化列宽数组，对应：漏洞类型,文件路径,行号,匹配内容,规则说明
	colWidths := []int{10, 10, 5, 15, 20} // 默认最小宽度

	// 计算每列的最大宽度
	for _, result := range results {
		// 漏洞类型
		if len(result.Rule.VulName) > colWidths[0] {
			colWidths[0] = len(result.Rule.VulName)
		}

		// 文件路径
		if len(result.FilePath) > colWidths[1] {
			colWidths[1] = len(result.FilePath)
		}

		// 行号 - 转换为字符串计算长度
		lineNumStr := fmt.Sprintf("%d", result.LineNumber)
		if len(lineNumStr) > colWidths[2] {
			colWidths[2] = len(lineNumStr)
		}

		// 匹配内容
		if len(result.MatchedLine) > colWidths[3] {
			colWidths[3] = len(result.MatchedLine)
		}

		// 规则说明
		if len(result.Rule.Readme) > colWidths[4] {
			colWidths[4] = len(result.Rule.Readme)
		}
	}

	return colWidths
}

// highlightMatchedLine 高亮显示匹配的行内容
func highlightMatchedLine(line, regexPattern string) {
	// 编译正则表达式
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		// 如果正则表达式编译失败，直接打印原始行
		fmt.Printf("    %s\n", line)
		return
	}

	// 查找匹配项
	indices := re.FindStringIndex(line)
	if indices == nil {
		// 如果没有找到匹配项，直接打印原始行
		fmt.Printf("    %s\n", line)
		return
	}

	// 分割行内容，以便高亮显示匹配部分
	preMatch := line[:indices[0]]
	match := line[indices[0]:indices[1]]
	postMatch := line[indices[1]:]

	// 打印高亮的行内容
	fmt.Printf("    %s", preMatch)
	color.New(color.FgRed, color.Bold).Printf("%s", match)
	fmt.Printf("%s\n", postMatch)
}

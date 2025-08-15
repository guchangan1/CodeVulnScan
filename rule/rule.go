package rule

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Rule 定义了漏洞检测规则
type Rule struct {
	FileType  string `json:"FileType"`  // 文件类型，如java、php、net等
	RegexRule string `json:"RegexRule"` // 正则表达式规则
	Readme    string `json:"Readme"`    // 规则说明
	VulName   string `json:"VulName"`   // 漏洞名称
	LikeName  string `json:"likeName"`  // 可选，用于模糊匹配文件名
}

// RuleManager 管理规则加载和访问
type RuleManager struct {
	rules     map[string][]Rule // 按语言分类的规则
	ruleFiles map[string]string // 语言对应的规则文件
}

// NewRuleManager 创建一个新的规则管理器
func NewRuleManager() *RuleManager {
	return &RuleManager{
		rules: make(map[string][]Rule),
		ruleFiles: map[string]string{
			"java":   "JavaRule.json",
			"php":    "PhpRule.json",
			"net":    "DotNetRule.json",
			"python": "PythonRule.json",
			"leak":   "LeakRule.json",
		},
	}
}

// LoadRules 加载指定语言的规则
func (rm *RuleManager) LoadRules(language string) ([]Rule, error) {
	// 转换为小写以便统一处理
	language = strings.ToLower(language)

	// 检查是否已经加载过该语言的规则
	if rules, ok := rm.rules[language]; ok {
		return rules, nil
	}

	// 获取规则文件名
	ruleFile, ok := rm.ruleFiles[language]
	if !ok {
		return nil, fmt.Errorf("不支持的语言: %s", language)
	}

	// 构建规则文件路径
	rulePath := filepath.Join(getRulesDir(), ruleFile)

	// 检查规则文件是否存在
	if _, err := os.Stat(rulePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("规则文件不存在: %s", rulePath)
	}

	// 读取规则文件
	data, err := os.ReadFile(rulePath)
	if err != nil {
		return nil, fmt.Errorf("读取规则文件失败: %v", err)
	}

	// 解析JSON
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("解析规则文件失败: %v", err)
	}

	// 缓存规则
	rm.rules[language] = rules

	return rules, nil
}

// getRulesDir 获取规则文件所在目录
func getRulesDir() string {
	// 首先尝试从当前目录的rules子目录加载
	currentDir, err := os.Getwd()
	if err == nil {
		rulesDir := filepath.Join(currentDir, "rules")
		if _, err := os.Stat(rulesDir); err == nil {
			return rulesDir
		}
	}

	// 如果当前目录没有rules子目录，则尝试从可执行文件所在目录的rules子目录加载
	execPath, err := os.Executable()
	if err == nil {
		execDir := filepath.Dir(execPath)
		rulesDir := filepath.Join(execDir, "rules")
		if _, err := os.Stat(rulesDir); err == nil {
			return rulesDir
		}
	}

	// 如果都找不到，则返回当前目录
	fmt.Println("警告: 未找到规则目录，将使用当前目录")
	return currentDir
}

// GetRulesByLanguage 获取指定语言的所有规则
func (rm *RuleManager) GetRulesByLanguage(language string) ([]Rule, error) {
	return rm.LoadRules(language)
}

// GetRulesByFileType 获取指定文件类型的所有规则
func (rm *RuleManager) GetRulesByFileType(fileType string) ([]Rule, error) {
	// 加载所有支持的语言规则
	allRules := []Rule{}
	for lang := range rm.ruleFiles {
		rules, err := rm.LoadRules(lang)
		if err != nil {
			continue // 忽略加载失败的规则
		}
		allRules = append(allRules, rules...)
	}

	// 过滤出指定文件类型的规则
	result := []Rule{}
	for _, rule := range allRules {
		if strings.EqualFold(rule.FileType, fileType) {
			result = append(result, rule)
		}
	}

	return result, nil
}

#!/bin/bash

# 示例1：使用Java规则扫描src目录
echo "示例1：使用Java规则扫描src目录"
./CodeVulnScan -T java -d ./src -v

# 示例2：使用PHP规则扫描，排除vendor目录
echo "\n示例2：使用PHP规则扫描，排除vendor目录"
./CodeVulnScan -T php -d ./src -nd ./src/vendor -v

# 示例3：扫描配置文件中的敏感信息
echo "\n示例3：扫描配置文件中的敏感信息"
./CodeVulnScan -T leak -d ./config -e yml,properties,xml,json -v
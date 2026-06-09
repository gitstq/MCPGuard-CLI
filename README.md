<div align="center">

# 🛡️ MCPGuard-CLI

**轻量级终端MCP生态安全智能扫描引擎**
**Lightweight Terminal MCP Ecosystem Security Intelligent Scanning Engine**

[English](#english) | [简体中文](#简体中文) | [繁體中文](#繁體中文)

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-success.svg)]()
[![Scanners: 5](https://img.shields.io/badge/Scanners-5-orange.svg)]()

</div>

---

## 简体中文

### 🎉 项目介绍

**MCPGuard-CLI** 是一款专为 MCP（Model Context Protocol）生态打造的轻量级终端安全扫描工具。随着 AI Agent 和 MCP 服务器的爆发式增长，AI 编辑器扩展、MCP 服务器配置、依赖包等环节的安全风险日益凸显。MCPGuard-CLI 应运而生，帮助开发者在数秒内完成全量安全审计。

**解决的痛点**：
- 🔍 MCP 服务器配置中隐藏的危险命令和密钥泄露难以发现
- 📦 AI 编辑器扩展的过度权限请求缺乏有效审计手段
- 🔑 项目中意外提交的 API 密钥、Token、私钥等敏感信息
- 📋 JSON 配置文件中的不安全默认设置
- 🛒 依赖包中的已知漏洞和仿冒攻击

**自研差异化亮点**：
- **零外部依赖** — 纯 Python 标准库实现，无需安装任何第三方包
- **5 大安全扫描器** — 覆盖 MCP 配置、依赖安全、编辑器扩展、密钥泄露、JSON 配置全场景
- **多格式报告** — 支持终端彩色输出、JSON、Markdown 三种报告格式
- **智能分级** — 基于 CWE 标准的 5 级严重度分类（CRITICAL/HIGH/MEDIUM/LOW/INFO）
- **环境诊断** — 内置 `doctor` 命令，一键检测常见 MCP 配置路径

### ✨ 核心特性

| 特性 | 说明 |
|---|---|
| 🛡️ **MCP 服务器配置扫描** | 检测危险命令、未固定版本、硬编码密钥、不安全 URL、过度权限 |
| 📦 **依赖安全扫描** | 检测已知漏洞包、仿冒攻击、未固定版本、缺少锁文件 |
| 🧩 **AI 编辑器扩展扫描** | 审计 VS Code/Cursor/Windsurf 扩展的权限请求和安全隐患 |
| 🔑 **密钥泄露扫描** | 30+ 种正则模式检测 GitHub/AWS/OpenAI/Anthropic 等平台的密钥和 Token |
| ⚙️ **JSON 配置扫描** | 检测调试模式、SSL 禁用、认证关闭等不安全配置 |
| 📊 **风险评分系统** | 0-100 分量化评估，一目了然 |
| 🎨 **彩色终端输出** | 按严重度着色，快速定位关键问题 |
| 📄 **多格式报告** | 终端 / JSON / Markdown 三种输出格式 |

### 🚀 快速开始

**环境要求**：
- Python 3.8 或更高版本
- 无需安装任何第三方依赖

**安装与运行**：

```bash
# 克隆仓库
git clone https://github.com/gitstq/MCPGuard-CLI.git
cd MCPGuard-CLI

# 直接运行（无需安装）
python mcpguard.py scan <目标路径>

# 或使用 doctor 命令检查环境
python mcpguard.py doctor
```

**一键扫描示例**：

```bash
# 扫描当前目录
python mcpguard.py scan .

# 扫描指定目录，输出 JSON 报告
python mcpguard.py scan ./my-project --format json --output report.json

# 仅使用 MCP 和密钥扫描器
python mcpguard.py scan ./my-project --scanners mcp,secret

# 只显示高危及以上问题
python mcpguard.py scan ./my-project --severity high

# 扫描 Claude Desktop 配置
python mcpguard.py scan ~/.config/Claude

# 输出 Markdown 格式报告
python mcpguard.py scan ./my-project --format markdown --output security-report.md
```

### 📖 详细使用指南

#### 扫描器说明

| 扫描器 ID | 名称 | 扫描目标 |
|---|---|---|
| `mcp` | MCP 服务器配置扫描器 | `*.json`（MCP 配置文件） |
| `dependency` | 依赖安全扫描器 | `package.json`、`requirements.txt`、`pyproject.toml` 等 |
| `editor` | AI 编辑器扩展扫描器 | `package.json`（VS Code 扩展） |
| `secret` | 密钥泄露扫描器 | 所有文本文件（排除二进制文件） |
| `config` | JSON 配置扫描器 | `*.json`（通用配置文件） |

#### 命令行参数

```
usage: mcpguard scan [-h] [--format {terminal,json,markdown}]
                     [--output OUTPUT] [--scanners SCANNERS]
                     [--severity {critical,high,medium,low,info}]
                     [--no-color] [--quiet] [--version]
                     target
```

| 参数 | 说明 | 默认值 |
|---|---|---|
| `target` | 扫描目标路径 | 必填 |
| `--format, -f` | 输出格式：terminal/json/markdown | terminal |
| `--output, -o` | 输出文件路径（默认输出到终端） | stdout |
| `--scanners, -s` | 指定扫描器（逗号分隔） | 全部 |
| `--severity, -l` | 最低报告级别 | info |
| `--no-color` | 禁用彩色输出 | false |
| `--quiet, -q` | 安静模式 | false |

#### 严重度等级

| 等级 | 符号 | 说明 |
|---|---|---|
| 🔴 CRITICAL | 严重 | 必须立即修复，存在直接安全威胁 |
| 🟠 HIGH | 高危 | 应尽快修复，存在重大安全风险 |
| 🟡 MEDIUM | 中危 | 建议修复，存在潜在安全风险 |
| 🟢 LOW | 低危 | 可选修复，安全影响较小 |
| 🔵 INFO | 信息 | 安全建议，无直接风险 |

### 💡 设计思路与迭代规划

**设计理念**：
- **零依赖哲学** — 不引入任何第三方库，确保工具本身不会成为攻击面
- **只读安全** — 所有扫描操作均为只读，不会修改任何文件
- **快速反馈** — 扫描速度优先，秒级完成大型项目审计
- **CWE 标准** — 所有发现均关联 CWE（通用弱点枚举）编号

**技术选型原因**：
- Python 标准库：最广泛的开发者基础，跨平台兼容性最佳
- 正则表达式匹配：无需训练模型，零误报开销，离线可用
- 模块化架构：每个扫描器独立可插拔，便于扩展

**后续迭代计划**：
- [ ] 支持 SARIF 格式输出（集成 GitHub Code Scanning）
- [ ] 增加 CI/CD 集成模式（GitHub Actions / GitLab CI）
- [ ] 支持自定义扫描规则（YAML 配置文件）
- [ ] 增加增量扫描模式（仅扫描变更文件）
- [ ] 支持 MCP 协议本身的安全审计

### 📦 打包与部署指南

MCPGuard-CLI 是一个纯 Python 工具，无需打包即可直接运行。

**作为工具库集成**：

```python
from src.core.engine import ScanEngine
from src.scanners.mcp_scanner import MCPServerScanner
from src.scanners.secret_scanner import SecretLeakScanner

# 创建扫描引擎
engine = ScanEngine("/path/to/project")

# 注册扫描器
engine.register_scanner(MCPServerScanner("/path/to/project"))
engine.register_scanner(SecretLeakScanner("/path/to/project"))

# 执行扫描
report = engine.run()

# 获取结果
print(f"发现 {report.total_findings} 个安全问题")
print(f"风险评分: {report.overall_risk_score}/100")
```

**兼容环境**：
- ✅ Python 3.8+
- ✅ Linux / macOS / Windows
- ✅ 无需网络连接（完全离线运行）

### 🤝 贡献指南

欢迎贡献代码！请查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解详情。

**快速流程**：
1. Fork 本仓库
2. 创建特性分支：`git checkout -b feat/your-feature`
3. 提交更改：`git commit -m "feat: your feature description"`
4. 推送分支：`git push origin feat/your-feature`
5. 发起 Pull Request

### 📄 开源协议

本项目基于 [MIT License](LICENSE) 开源。

---

## 繁體中文

### 🎉 專案介紹

**MCPGuard-CLI** 是一款專為 MCP（Model Context Protocol）生態打造的輕量級終端安全掃描工具。隨著 AI Agent 和 MCP 伺服器的爆發式增長，AI 編輯器擴充套件、MCP 伺服器配置、依賴套件等環節的安全風險日益凸顯。MCPGuard-CLI 應運而生，幫助開發者在數秒內完成全量安全審計。

**解決的痛點**：
- 🔍 MCP 伺服器配置中隱藏的危險命令和密鑰洩露難以發現
- 📦 AI 編輯器擴充套件的過度權限請求缺乏有效審計手段
- 🔑 專案中意外提交的 API 密鑰、Token、私鑰等敏感資訊
- 📋 JSON 配置檔案中的不安全預設設定
- 🛒 依賴套件中的已知漏洞和仿冒攻擊

**自研差異化亮點**：
- **零外部依賴** — 純 Python 標準庫實現，無需安裝任何第三方套件
- **5 大安全掃描器** — 覆蓋 MCP 配置、依賴安全、編輯器擴充套件、密鑰洩露、JSON 配置全場景
- **多格式報告** — 支援終端彩色輸出、JSON、Markdown 三種報告格式
- **智慧分級** — 基於 CWE 標準的 5 級嚴重度分類（CRITICAL/HIGH/MEDIUM/LOW/INFO）
- **環境診斷** — 內建 `doctor` 指令，一鍵檢測常見 MCP 配置路徑

### ✨ 核心特性

| 特性 | 說明 |
|---|---|
| 🛡️ **MCP 伺服器配置掃描** | 偵測危險指令、未固定版本、硬編碼密鑰、不安全 URL、過度權限 |
| 📦 **依賴安全掃描** | 偵測已知漏洞套件、仿冒攻擊、未固定版本、缺少鎖定檔案 |
| 🧩 **AI 編輯器擴充套件掃描** | 審計 VS Code/Cursor/Windsurf 擴充套件的權限請求和安全隱患 |
| 🔑 **密鑰洩露掃描** | 30+ 種正則模式偵測 GitHub/AWS/OpenAI/Anthropic 等平台的密鑰和 Token |
| ⚙️ **JSON 配置掃描** | 偵測除錯模式、SSL 停用、認證關閉等不安全配置 |
| 📊 **風險評分系統** | 0-100 分量化評估，一目了然 |
| 🎨 **彩色終端輸出** | 按嚴重度著色，快速定位關鍵問題 |
| 📄 **多格式報告** | 終端 / JSON / Markdown 三種輸出格式 |

### 🚀 快速開始

**環境要求**：
- Python 3.8 或更高版本
- 無需安裝任何第三方依賴

**安裝與執行**：

```bash
# 克隆倉庫
git clone https://github.com/gitstq/MCPGuard-CLI.git
cd MCPGuard-CLI

# 直接執行（無需安裝）
python mcpguard.py scan <目標路徑>

# 或使用 doctor 指令檢查環境
python mcpguard.py doctor
```

**一鍵掃描範例**：

```bash
# 掃描當前目錄
python mcpguard.py scan .

# 掃描指定目錄，輸出 JSON 報告
python mcpguard.py scan ./my-project --format json --output report.json

# 僅使用 MCP 和密鑰掃描器
python mcpguard.py scan ./my-project --scanners mcp,secret

# 只顯示高危及以上問題
python mcpguard.py scan ./my-project --severity high

# 掃描 Claude Desktop 配置
python mcpguard.py scan ~/.config/Claude

# 輸出 Markdown 格式報告
python mcpguard.py scan ./my-project --format markdown --output security-report.md
```

### 📖 詳細使用指南

#### 掃描器說明

| 掃描器 ID | 名稱 | 掃描目標 |
|---|---|---|
| `mcp` | MCP 伺服器配置掃描器 | `*.json`（MCP 配置檔案） |
| `dependency` | 依賴安全掃描器 | `package.json`、`requirements.txt`、`pyproject.toml` 等 |
| `editor` | AI 編輯器擴充套件掃描器 | `package.json`（VS Code 擴充套件） |
| `secret` | 密鑰洩露掃描器 | 所有文字檔案（排除二進位檔案） |
| `config` | JSON 配置掃描器 | `*.json`（通用配置檔案） |

#### 嚴重度等級

| 等級 | 符號 | 說明 |
|---|---|---|
| 🔴 CRITICAL | 嚴重 | 必須立即修復，存在直接安全威脅 |
| 🟠 HIGH | 高危 | 應盡快修復，存在重大安全風險 |
| 🟡 MEDIUM | 中危 | 建議修復，存在潛在安全風險 |
| 🟢 LOW | 低危 | 可選修復，安全影響較小 |
| 🔵 INFO | 資訊 | 安全建議，無直接風險 |

### 💡 設計思路與迭代規劃

**設計理念**：
- **零依賴哲學** — 不引入任何第三方庫，確保工具本身不會成為攻擊面
- **唯讀安全** — 所有掃描操作均為唯讀，不會修改任何檔案
- **快速回饋** — 掃描速度優先，秒級完成大型專案審計
- **CWE 標準** — 所有發現均關聯 CWE（通用弱點列舉）編號

**後續迭代計畫**：
- [ ] 支援 SARIF 格式輸出（整合 GitHub Code Scanning）
- [ ] 增加 CI/CD 整合模式（GitHub Actions / GitLab CI）
- [ ] 支援自訂掃描規則（YAML 配置檔案）
- [ ] 增加增量掃描模式（僅掃描變更檔案）

### 🤝 貢獻指南

歡迎貢獻程式碼！請查看 [CONTRIBUTING.md](CONTRIBUTING.md) 了解詳情。

### 📄 開源協議

本專案基於 [MIT License](LICENSE) 開源。

---

## English

### 🎉 Introduction

**MCPGuard-CLI** is a lightweight terminal security scanning tool purpose-built for the MCP (Model Context Protocol) ecosystem. As AI Agents and MCP servers experience explosive growth, security risks in AI editor extensions, MCP server configurations, and dependency packages have become increasingly prominent. MCPGuard-CLI helps developers perform comprehensive security audits in seconds.

**Pain Points Solved**:
- 🔍 Dangerous commands and leaked secrets hidden in MCP server configs are hard to detect
- 📦 Excessive permission requests from AI editor extensions lack effective auditing tools
- 🔑 Accidentally committed API keys, tokens, and private keys in projects
- 📋 Insecure default settings in JSON configuration files
- 🛒 Known vulnerabilities and typosquatting attacks in dependency packages

**Differentiated Advantages**:
- **Zero External Dependencies** — Built entirely with Python standard library, no third-party packages needed
- **5 Security Scanners** — Covers MCP configs, dependency security, editor extensions, secret leaks, and JSON configs
- **Multi-format Reports** — Terminal (colored), JSON, and Markdown output formats
- **Intelligent Severity Classification** — 5-level severity system based on CWE standards (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- **Environment Diagnostics** — Built-in `doctor` command to detect common MCP config paths

### ✨ Core Features

| Feature | Description |
|---|---|
| 🛡️ **MCP Server Config Scanner** | Detects dangerous commands, unpinned versions, hardcoded secrets, insecure URLs, excessive permissions |
| 📦 **Dependency Security Scanner** | Detects known vulnerable packages, typosquatting, unpinned versions, missing lock files |
| 🧩 **AI Editor Extension Scanner** | Audits permission requests and security risks in VS Code/Cursor/Windsurf extensions |
| 🔑 **Secret Leak Scanner** | 30+ regex patterns to detect keys and tokens from GitHub, AWS, OpenAI, Anthropic, and more |
| ⚙️ **JSON Config Scanner** | Detects debug mode, disabled SSL, disabled authentication, and other insecure configurations |
| 📊 **Risk Scoring System** | Quantified 0-100 risk assessment at a glance |
| 🎨 **Colored Terminal Output** | Color-coded by severity for quick identification of critical issues |
| 📄 **Multi-format Reports** | Terminal / JSON / Markdown output formats |

### 🚀 Quick Start

**Requirements**:
- Python 3.8 or higher
- No third-party dependencies required

**Installation & Usage**:

```bash
# Clone the repository
git clone https://github.com/gitstq/MCPGuard-CLI.git
cd MCPGuard-CLI

# Run directly (no installation needed)
python mcpguard.py scan <target_path>

# Or use the doctor command to check your environment
python mcpguard.py doctor
```

**Quick Scan Examples**:

```bash
# Scan current directory
python mcpguard.py scan .

# Scan a specific directory, output JSON report
python mcpguard.py scan ./my-project --format json --output report.json

# Use only MCP and secret scanners
python mcpguard.py scan ./my-project --scanners mcp,secret

# Show only high severity and above
python mcpguard.py scan ./my-project --severity high

# Scan Claude Desktop configuration
python mcpguard.py scan ~/.config/Claude

# Output Markdown format report
python mcpguard.py scan ./my-project --format markdown --output security-report.md
```

### 📖 Detailed Usage Guide

#### Scanner Overview

| Scanner ID | Name | Scan Targets |
|---|---|---|
| `mcp` | MCP Server Config Scanner | `*.json` (MCP configuration files) |
| `dependency` | Dependency Security Scanner | `package.json`, `requirements.txt`, `pyproject.toml`, etc. |
| `editor` | AI Editor Extension Scanner | `package.json` (VS Code extensions) |
| `secret` | Secret Leak Scanner | All text files (excludes binary files) |
| `config` | JSON Config Scanner | `*.json` (general configuration files) |

#### CLI Arguments

```
usage: mcpguard scan [-h] [--format {terminal,json,markdown}]
                     [--output OUTPUT] [--scanners SCANNERS]
                     [--severity {critical,high,medium,low,info}]
                     [--no-color] [--quiet] [--version]
                     target
```

| Argument | Description | Default |
|---|---|---|
| `target` | Target path to scan | Required |
| `--format, -f` | Output format: terminal/json/markdown | terminal |
| `--output, -o` | Output file path (default: stdout) | stdout |
| `--scanners, -s` | Comma-separated scanner list | all |
| `--severity, -l` | Minimum severity level to report | info |
| `--no-color` | Disable colored output | false |
| `--quiet, -q` | Quiet mode | false |

#### Severity Levels

| Level | Symbol | Description |
|---|---|---|
| 🔴 CRITICAL | Critical | Must fix immediately — direct security threat |
| 🟠 HIGH | High | Should fix soon — significant security risk |
| 🟡 MEDIUM | Medium | Recommended to fix — potential security risk |
| 🟢 LOW | Low | Optional fix — minor security impact |
| 🔵 INFO | Informational | Security suggestion — no direct risk |

### 💡 Design Philosophy & Roadmap

**Design Principles**:
- **Zero Dependency Philosophy** — No third-party libraries, ensuring the tool itself cannot become an attack surface
- **Read-Only Safety** — All scanning operations are read-only, never modifying any files
- **Fast Feedback** — Scan speed prioritized, completing large project audits in seconds
- **CWE Standards** — All findings linked to CWE (Common Weakness Enumeration) identifiers

**Why These Tech Choices**:
- Python standard library: Widest developer base, best cross-platform compatibility
- Regex pattern matching: No model training needed, zero false-positive overhead, works offline
- Modular architecture: Each scanner is independently pluggable and extensible

**Roadmap**:
- [ ] SARIF format output (GitHub Code Scanning integration)
- [ ] CI/CD integration mode (GitHub Actions / GitLab CI)
- [ ] Custom scanning rules (YAML configuration)
- [ ] Incremental scan mode (scan only changed files)
- [ ] MCP protocol security auditing

### 📦 Integration Guide

MCPGuard-CLI is a pure Python tool that runs without installation.

**Use as a Library**:

```python
from src.core.engine import ScanEngine
from src.scanners.mcp_scanner import MCPServerScanner
from src.scanners.secret_scanner import SecretLeakScanner

# Create scan engine
engine = ScanEngine("/path/to/project")

# Register scanners
engine.register_scanner(MCPServerScanner("/path/to/project"))
engine.register_scanner(SecretLeakScanner("/path/to/project"))

# Run scan
report = engine.run()

# Get results
print(f"Found {report.total_findings} security issues")
print(f"Risk Score: {report.overall_risk_score}/100")
```

**Compatible Environments**:
- ✅ Python 3.8+
- ✅ Linux / macOS / Windows
- ✅ No network connection required (fully offline)

### 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

**Quick Workflow**:
1. Fork this repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit your changes: `git commit -m "feat: your feature description"`
4. Push the branch: `git push origin feat/your-feature`
5. Open a Pull Request

### 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**Made with 🦞 by LobsterDev**

</div>

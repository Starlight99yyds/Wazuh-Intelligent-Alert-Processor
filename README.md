# Wazuh 智能告警处理与优化系统 (Wazuh Intelligent Alert Processor)

## 📖 项目简介 (Introduction)
`Wazuh-AI-Processor` 是一个面向企业级安全运维的高性能告警处理中间件。它结合了 **LLM (大语言模型)** 和 **自动化工程策略**，通过智能分析、时间窗口聚合和格式标准化，有效解决安全运维中的“告警疲劳”问题。

---

## ✨ 核心特性 (Key Features)
- 🤖 **AI 智能决策**：集成 [Microsoft AutoGen](https://github.com/microsoft/autogen) 框架，利用大语言模型（如 DeepSeek/OpenAI）对告警进行语义分析，过滤无效误报。
- 📦 **高效告警聚合**：实现基于 **Gap-Window (间隔窗口)** 的聚合算法，自动收口重复或关联告警，极大地降低冗余。
- 📊 **多维评估体系**：自研评估模块，实时计算 **Precision, Recall, F1-Score** 及 **告警减少率**，量化 AI 模型性能。
- 🚀 **云原生集成**：原生对接 **Prometheus Alertmanager**，支持告警的分级推送与自动化生命周期管理。
- ⚙️ **配置驱动**：全功能通过 `config.yaml` 灵活配置，支持本地文件处理与远程服务接入。

---

## 🏗️ 系统架构 (Architecture)
1. **数据输入 (Input)**: 支持 Wazuh 本地 NDJSON 文件或 Elasticsearch 实时流。
2. **核心处理 (Process)**:
   - `Parser`: 格式标准化与清洗（XML to JSON）。
   - `Aggregator`: 时间窗口聚合（降噪第一层）。
   - `AI Agent`: 基于 AutoGen 的 LLM 智能分析（降噪第二层）。
3. **输出推送 (Output)**: 推送至 Alertmanager API 或生成本地详细分析报告。

---

## 🚀 快速开始 (Quick Start)

### 1. 环境准备
```bash
git clone https://github.com/Starlight99yyds/Wazuh-Intelligent-Alert-Processor.git
cd WWazuh-Intelligent-Alert-Processor
pip install -r requirements.txt
```

### 2. 配置 AI 密钥
在项目根目录创建 `OAI_CONFIG_LIST` 文件：
```json
[
    {
        "model": "deepseek-chat",
        "api_key": "YOUR_DEEPSEEK_API_KEY",
        "base_url": "https://api.deepseek.com"
    }
]
```

### 3. 修改配置
编辑 `config.yaml` 调整数据路径或 Alertmanager 地址：
```yaml
local_files:
    file_pattern: "data/your_alerts.ndjson"
output:
    alertmanager_url: "http://localhost:9093"
```

### 4. 运行项目
```bash
python wazuh_alert_processor.py
```

我们也提供直接发送所有告警的文件 `send_all_alerts.py`
```bash
python send_all_alerts.py
```

和纯 AI 判断告警是否值得发送的文件 `ai_direct_alert.py`
```bash
python ai_direct_alert.py
```

来比较不同思路的效果。

---

## 🛡️ 技术细节 (Technical Deep Dive)
- **决策鲁棒性**：通过 `normalize_decision` 逻辑强制校验 AI 输出，确保安全级别（Severity）与处理逻辑的严谨性。
- **异步处理**：利用 `asyncio` 提升数据推送阶段的并发能力，减少 IO 阻塞。
- **规则兜底**：内置 `apply_severity_cap_by_rule_level` 机制，防止 AI 对低风险规则产生过度反应。

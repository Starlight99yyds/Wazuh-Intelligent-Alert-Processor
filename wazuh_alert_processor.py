#!/usr/bin/env python3
"""
Wazuh 报警信息处理器
功能：
1. 从本地 ndjson 文件读取 Wazuh 报警信息
2. 通过时间窗口聚合相同类型的告警
3. 通过 autogen 进行智能判断
4. 将需要告警的信息推送至 Alertmanager
"""
import asyncio
import glob
import json
import logging
import os
import sys
import yaml
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List

import requests


@dataclass
class EvaluationMetrics:
    """
    评价指标数据类
    用于统计和计算告警处理的各项评价指标
    """
    # 基础计数
    tp: int = 0  # True Positive: 该发送且AI判断发送
    fp: int = 0  # False Positive: 不该发送但AI发送（误报）
    fn: int = 0  # False Negative: 该发送但AI没发（漏报）
    tn: int = 0  # True Negative: 不该发送且AI没发
    
    # 原始统计
    total_original_alerts: int = 0  # 原始告警总数
    ai_sent_alerts: int = 0  # AI发送的告警数
    
    # 具体告警信息
    tp_alerts: List[Dict] = field(default_factory=list)  # TP 告警列表
    fp_alerts: List[Dict] = field(default_factory=list)  # FP 告警列表
    fn_alerts: List[Dict] = field(default_factory=list)  # FN 告警列表
    tn_alerts: List[Dict] = field(default_factory=list)  # TN 告警列表
    
    def calculate_precision(self) -> float:
        """
        精确率（Precision）= TP / (TP + FP)
        对应误报率控制能力
        """
        denominator = self.tp + self.fp
        return self.tp / denominator if denominator > 0 else 0.0
    
    def calculate_recall(self) -> float:
        """
        召回率（Recall / Sensitivity）= TP / (TP + FN)
        对应漏报率控制能力
        """
        denominator = self.tp + self.fn
        return self.tp / denominator if denominator > 0 else 0.0
    
    def calculate_f1_score(self) -> float:
        """
        F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
        """
        precision = self.calculate_precision()
        recall = self.calculate_recall()
        denominator = precision + recall
        return 2 * precision * recall / denominator if denominator > 0 else 0.0
    
    def calculate_reduction_rate(self) -> float:
        """
        平均告警减少率（Alert Reduction Rate）= 1 - (AI发送告警数 / 原始告警数)
        """
        if self.total_original_alerts > 0:
            return 1 - (self.ai_sent_alerts / self.total_original_alerts)
        return 0.0
    
    def calculate_fnr(self) -> float:
        """
        漏报率（False Negative Rate）= FN / (TP + FN)
        """
        denominator = self.tp + self.fn
        return self.fn / denominator if denominator > 0 else 0.0
    
    def to_dict(self) -> Dict:
        """将指标转换为字典格式"""
        return {
            '基础统计': {
                'TP (该发送且AI发送)': self.tp,
                'FP (不该发送但AI发送/误报)': self.fp,
                'FN (该发送但AI没发/漏报)': self.fn,
                'TN (不该发送且AI没发)': self.tn,
                '原始告警总数': self.total_original_alerts,
                'AI发送告警数': self.ai_sent_alerts,
            },
            '评价指标': {
                '精确率 (Precision)': f"{self.calculate_precision():.4f} ({self.calculate_precision()*100:.2f}%)",
                '召回率 (Recall)': f"{self.calculate_recall():.4f} ({self.calculate_recall()*100:.2f}%)",
                'F1 Score': f"{self.calculate_f1_score():.4f}",
                '告警减少率 (Reduction)': f"{self.calculate_reduction_rate():.4f} ({self.calculate_reduction_rate()*100:.2f}%)",
                '漏报率 (FNR)': f"{self.calculate_fnr():.4f} ({self.calculate_fnr()*100:.2f}%)",
            }
        }
    
    def print_report(self):
        """打印评价指标报告"""
        print("\n" + "=" * 80)
        print("告警处理评价指标报告")
        print("=" * 80)
        
        print("\n【基础统计】")
        print(f"  TP (True Positive, 该发送且AI发送):     {self.tp}")
        print(f"  FP (False Positive, 不该发送但AI发送/误报): {self.fp}")
        print(f"  FN (False Negative, 该发送但AI没发/漏报): {self.fn}")
        print(f"  TN (True Negative, 不该发送且AI没发):     {self.tn}")
        print(f"  原始告警总数: {self.total_original_alerts}")
        print(f"  AI发送告警数: {self.ai_sent_alerts}")
        
        print("\n【评价指标】")
        print(f"  精确率 (Precision):      {self.calculate_precision():.4f} ({self.calculate_precision()*100:.2f}%)")
        print(f"    └─ 误报率控制能力: 高精确率表示AI较少产生误报")
        print(f"  召回率 (Recall):         {self.calculate_recall():.4f} ({self.calculate_recall()*100:.2f}%)")
        print(f"    └─ 漏报率控制能力: 高召回率表示AI较少漏掉应发送的告警")
        print(f"  F1 Score:                {self.calculate_f1_score():.4f}")
        print(f"    └─ 精确率和召回率的调和平均，综合评估模型性能")
        print(f"  告警减少率 (Reduction):  {self.calculate_reduction_rate():.4f} ({self.calculate_reduction_rate()*100:.2f}%)")
        print(f"    └─ AI过滤掉的告警比例，越高表示降噪效果越好")
        print(f"  漏报率 (FNR):            {self.calculate_fnr():.4f} ({self.calculate_fnr()*100:.2f}%)")
        print(f"    └─ 应发送但AI未发送的比例，越低越好")
        
        # 打印具体告警信息
        if self.tp_alerts:
            print("\n【TP 告警详情】")
            print("-" * 60)
            for i, alert in enumerate(self.tp_alerts):
                print(f"[{i}] 规则ID: {alert['rule_id']} | 级别: {alert['level']}")
                print(f"   描述: {alert['description']}")
                print(f"   时间: {alert['timestamp']}")
                print(f"   理由: {alert.get('reason', 'No reason')}")
                print("-" * 60)
        
        if self.fp_alerts:
            print("\n【FP 告警详情】")
            print("-" * 60)
            for i, alert in enumerate(self.fp_alerts):
                print(f"[{i}] 规则ID: {alert['rule_id']} | 级别: {alert['level']}")
                print(f"   描述: {alert['description']}")
                print(f"   时间: {alert['timestamp']}")
                print(f"   理由: {alert.get('reason', 'No reason')}")
                print("-" * 60)
        
        if self.fn_alerts:
            print("\n【FN 告警详情】")
            print("-" * 60)
            for i, alert in enumerate(self.fn_alerts):
                print(f"[{i}] 规则ID: {alert['rule_id']} | 级别: {alert['level']}")
                print(f"   描述: {alert['description']}")
                print(f"   时间: {alert['timestamp']}")
                print(f"   理由: {alert.get('reason', 'No reason')}")
                print("-" * 60)
        
        if self.tn_alerts:
            print("\n【TN 告警详情】")
            print("-" * 60)
            for i, alert in enumerate(self.tn_alerts):
                print(f"[{i}] 规则ID: {alert['rule_id']} | 级别: {alert['level']}")
                print(f"   描述: {alert['description']}")
                print(f"   时间: {alert['timestamp']}")
                print(f"   理由: {alert.get('reason', 'No reason')}")
                print("-" * 60)
        
        print("\n【指标说明】")
        print("  • 精确率公式: Precision = TP / (TP + FP)")
        print("  • 召回率公式: Recall = TP / (TP + FN)")
        print("  • F1 Score公式: F1 = 2 × (Precision × Recall) / (Precision + Recall)")
        print("  • 告警减少率公式: Reduction = 1 - (AI发送告警数 / 原始告警数)")
        print("  • 漏报率公式: FNR = FN / (TP + FN)")
        print("=" * 80)


# 全局评价指标实例
evaluation_metrics = EvaluationMetrics()

# 配置日志
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# 限制第三方库的日志输出
for logger_name in ['autogen', 'openai', 'requests', 'urllib3']:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.WARNING)

# 加载配置
try:
    cfg = yaml.safe_load(open('config.yaml'))
except Exception as e:
    logging.error(f"Failed to load config.yaml: {e}")
    sys.exit(1)

# 聚合配置：超过 N 分钟未触发则收口当前组
DEFAULT_GAP_MINUTES = cfg.get('aggregation', {}).get('gap_minutes', 5)
MIN_ALERT_COUNT = cfg.get('aggregation', {}).get('min_alert_count', 1)
# 决策理由最大长度（字符），用于 normalize_decision 截断
REASON_MAX_LENGTH = cfg.get('decision', {}).get('reason_max_length', 80)


# 辅助函数：解析时间戳
def parse_timestamp(timestamp_str):
    """
    解析 Wazuh 告警的时间戳字符串
    """
    try:
        # 尝试解析 ISO 格式时间戳
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except Exception as e:
        logging.error(f"Failed to parse timestamp: {e}")
        return datetime.now()


def normalize_decision(decision):
    """
    强制 should_alert 与 severity 符合真值表，并限制 reason 长度。
    真值表：false+info 合法；true+warning/critical 合法；其余组合一律修正。
    """
    if not decision or not isinstance(decision, dict):
        return {"should_alert": False, "severity": "info", "reason": ""}
    should_alert = bool(decision.get("should_alert", False))
    severity = (decision.get("severity") or "info").strip().lower()
    if severity not in ("critical", "warning", "info"):
        severity = "info"
    # 真值表：info 不告警，warning/critical 必告警
    if severity == "info":
        should_alert = False
    elif severity in ("warning", "critical"):
        should_alert = True
    if not should_alert:
        severity = "info"
    elif severity == "info":
        severity = "warning"
    reason = (decision.get("reason") or "")[:REASON_MAX_LENGTH]
    return {"should_alert": should_alert, "severity": severity, "reason": reason}


def apply_severity_cap_by_rule_level(decision, rule_level):
    """
    规则级别兜底：rule_level < 12 时不得为 critical，降为 warning，避免低级别规则被 LLM 判为 critical。
    """
    if not decision or not isinstance(decision, dict):
        return decision
    sev = (decision.get("severity") or "info").strip().lower()
    if rule_level is not None and rule_level < 12 and sev == "critical":
        decision = {**decision, "severity": "warning"}
    return decision


# 告警聚合函数（gap 逻辑：同一规则+同一代理超过 N 分钟未触发则收口，下一笔同类告警归入新组）
def aggregate_alerts(alerts, gap_minutes=DEFAULT_GAP_MINUTES):
    """
    按「超过 N 分钟未触发就收口」的 gap 逻辑聚合告警：先按规则+描述+代理分组，组内按时间排序，
    相邻两条告警间隔若超过 gap_minutes 则收口当前段、开启新段；每段输出为一个 window（window_start/end 为段的首尾时间）。
    """
    if not alerts:
        logging.info("No alerts to aggregate")
        return []

    logging.info(f"Starting to aggregate {len(alerts)} alerts with gap: {gap_minutes} minutes (close group when no trigger for N min)")

    # 按时间排序
    sorted_alerts = sorted(alerts, key=lambda x: x.get('timestamp', ''))

    # 先按聚合键分组（规则 id + 描述 + 代理名）
    key_to_alerts = {}
    for alert in sorted_alerts:
        rule = alert.get('rule', {})
        agent = alert.get('agent', {})
        key = f"{rule.get('id', 'unknown')}_{rule.get('description', 'unknown')}_{agent.get('name', 'unknown')}"
        if key not in key_to_alerts:
            key_to_alerts[key] = []
        key_to_alerts[key].append(alert)

    gap_delta = timedelta(minutes=gap_minutes)
    aggregated_results = []

    for aggregation_key, key_alerts in key_to_alerts.items():
        # 组内已按全局时间有序，按时间切分为多段：相邻间隔 > gap_minutes 则新开一段
        segments = []
        current_segment = [key_alerts[0]]

        for i in range(1, len(key_alerts)):
            prev_time = parse_timestamp(key_alerts[i - 1].get('timestamp', ''))
            curr_time = parse_timestamp(key_alerts[i].get('timestamp', ''))
            if (curr_time - prev_time) > gap_delta:
                segments.append(current_segment)
                current_segment = [key_alerts[i]]
            else:
                current_segment.append(key_alerts[i])
        segments.append(current_segment)

        for segment in segments:
            if not segment:
                continue
            first_ts = segment[0].get('timestamp', '')
            last_ts = segment[-1].get('timestamp', '')
            window_start_dt = parse_timestamp(first_ts)
            window_end_dt = parse_timestamp(last_ts)

            rule = segment[0].get('rule', {})
            agent = segment[0].get('agent', {})

            sample_logs = []
            for a in segment[:3]:
                sample_logs.append((a.get('full_log') or '')[:500])

            # 计算实际触发次数：使用segment中最大的rule.firedtimes值
            max_firedtimes = 1
            for a in segment:
                firedtimes = a.get('rule', {}).get('firedtimes', 1)
                if firedtimes > max_firedtimes:
                    max_firedtimes = firedtimes
            
            agg_one = {
                'rule': {
                    'id': rule.get('id', 'unknown'),
                    'level': rule.get('level', 0),
                    'description': rule.get('description', 'No description'),
                    'groups': (rule.get('groups') or [])[:5],
                },
                'agent': {
                    'id': agent.get('id', 'unknown'),
                    'name': agent.get('name', 'unknown'),
                },
                'count': max_firedtimes,
                'first_seen': first_ts,
                'last_seen': last_ts,
                'sample_logs': sample_logs,
                'window_start': window_start_dt.isoformat(),
                'window_end': window_end_dt.isoformat(),
            }

            window_result = {
                'window_start': window_start_dt.isoformat(),
                'window_end': window_end_dt.isoformat(),
                'alerts': [agg_one],
            }
            aggregated_results.append(window_result)

    total_segments = len(aggregated_results)
    total_count_in_segments = sum(agg['count'] for w in aggregated_results for agg in w['alerts'])
    logging.info(
        f"Aggregation completed (gap-based). Total segments: {total_segments}, Sum(count): {total_count_in_segments}")

    return aggregated_results


# 尝试导入 autogen，如果失败则使用默认判断逻辑
try:
    from autogen_agentchat.agents import AssistantAgent
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    # 启用 autogen
    autogen_available = True
    logging.info("AutoGen enabled")

    # 加载环境变量
    def load_env_vars():
        env_vars = {}

        # 首先尝试从 OAI_CONFIG_LIST 文件加载
        oai_config_path = os.path.join(os.path.dirname(__file__), "OAI_CONFIG_LIST")
        if os.path.exists(oai_config_path):
            try:
                with open(oai_config_path, 'r', encoding='utf-8') as f:
                    oai_config = json.load(f)
                if oai_config and isinstance(oai_config, list):
                    # 取第一个配置
                    first_config = oai_config[0]
                    if 'api_key' in first_config:
                        env_vars['DEEPSEEK_API_KEY'] = first_config['api_key']
                        logging.info("Loaded API key from OAI_CONFIG_LIST file")
                        return env_vars
            except Exception as e:
                logging.warning(f"Error loading OAI_CONFIG_LIST: {e}")

        # 也从系统环境变量中读取
        for key in ['DEEPSEEK_API_KEY']:
            if key in os.environ:
                env_vars[key] = os.environ[key]
                logging.info(f"Loading {key} from system environment variables")
                return env_vars

        # 验证 API 密钥
        if 'DEEPSEEK_API_KEY' in env_vars:
            logging.info("DEEPSEEK_API_KEY found in environment variables")
        else:
            logging.error("DEEPSEEK_API_KEY not found in any environment variables")

        return env_vars


    env_vars = load_env_vars()
    deepseek_api_key = env_vars.get("DEEPSEEK_API_KEY")

    if not deepseek_api_key:
        raise Exception("DEEPSEEK_API_KEY not found in environment variables")

    # 创建模型客户端，使用 deepseek-chat 模型
    model_client = OpenAIChatCompletionClient(
        model="deepseek-chat",
        api_key=deepseek_api_key,
        base_url="https://api.deepseek.com",
        model_info={
            "name": "deepseek-chat",
            "base_url": "https://api.deepseek.com",
            "api_type": "openai",
            "vision": False,
            "function_calling": True,
            "json_output": False,
            "structured_output": False,
            "family": "unknown"
        }
    )
    logging.info("Using deepseek-chat model")

    # 创建 autogen 代理
    assistant = AssistantAgent(
        "assistant",
        model_client=model_client,
        system_message="你是一个经验丰富的安全告警分析师，负责判断 Wazuh 报警信息是否需要发送告警。\n\n你的任务是：\n1. 深入分析告警内容，理解其安全含义\n2. 根据告警的实际情况，自主判断是否需要发送告警\n3. 给出合理的判断理由\n\n判断原则（仅供参考，请根据具体告警灵活判断）：\n- 考虑告警的实际安全风险，而非仅依赖规则级别\n- 关注攻击/入侵类、权限提升、数据泄露等严重安全事件\n- 对于认证失败、登录异常等，结合频率和上下文判断\n- 对于系统维护、常规更新等低敏感事件，可酌情不告警\n- 当无法确定时，可根据直觉和经验做出判断\n\n输出格式要求：\n- should_alert: true/false（是否发送告警）\n- severity: critical/warning/info（告警级别）\n- reason: 判断理由（30字以内）\n\n注意：\n- should_alert=true 时，severity 必须是 warning 或 critical\n- should_alert=false 时，severity 必须是 info\n- 回复使用纯文本，不要markdown格式\n- 不要包含Unicode编码"
    )

    logging.info("Successfully initialized autogen with DeepSeek API configuration")
except Exception as e:
    logging.warning(f"Failed to initialize autogen: {e}. Will use default rule-based judgment.")
    autogen_available = False
    model_client = None
    
def get_alertmanager_api_url():
    """
    根据配置或默认值返回 Alertmanager API 地址，兼容带 '#/alerts' 的 UI 地址
    """
    # 从配置中读取 Alertmanager 地址；如果未配置，则使用本地默认地址
    am_url = cfg.get('output', {}).get('alertmanager_url')
    if not am_url:
        # 默认推送到本地 Alertmanager
        return "http://localhost:9093/api/v2/alerts"
    
    # 如果用户配置的是 Web UI 地址（例如 http://localhost:9093/#/alerts），转换为 v2 API 地址
    if '#/alerts' in am_url:
        base = am_url.split('#', 1)[0].rstrip('/')
        return f"{base}/api/v2/alerts"
    
    # 如果用户显式配置了 v1 API，自动升级到 v2 API
    if "/api/v1/alerts" in am_url:
        return am_url.replace("/api/v1/alerts", "/api/v2/alerts")
    
    return am_url
    
    
def push_to_alertmanager(wazuh_output):
    """
    将 Wazuh 结果转换为 Alertmanager 格式并推送
    Returns: True if success, False if failed
    """
    am_url = get_alertmanager_api_url()
    if not am_url:
        return False

    try:
        rule = wazuh_output.get('rule', {})
        agent = wazuh_output.get('agent', {})
        data_content = wazuh_output.get('data', {})

        rule_id = rule.get('id', 'unknown')
        rule_level = rule.get('level', 0)
        rule_desc = rule.get('description', 'No description')

        if rule_level >= 12:
            severity = 'critical'
        elif rule_level >= 7:
            severity = 'warning'
        else:
            severity = 'info'

        # 动态构建 annotations
        annotations = {
            "summary": rule_desc,
            "description": f"Agent: {agent.get('id')} - {agent.get('name')}\n"
                           f"Groups: {','.join(rule.get('groups', []))}\n"
                           f"Full Log: {wazuh_output.get('full_log', 'N/A')}"
        }

        # 递归扁平化处理 data_content 并加入 annotations
        def flatten_dict(d, parent_key='', sep='_'):
            items = []
            for k, v in d.items():
                new_key = f"{parent_key}{sep}{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(flatten_dict(v, new_key, sep=sep).items())
                else:
                    items.append((new_key, str(v)))
            return dict(items)

        if data_content:
            flat_data = flatten_dict(data_content)
            # 过滤掉过长的字段以防 Alertmanager 拒绝
            for k, v in flat_data.items():
                if len(v) < 1024:  # 限制单个字段长度
                    annotations[k] = v

        payload = [{
            "labels": {
                "alertname": f"Wazuh Rule {rule_id}",
                "severity": severity,
                "wazuh_rule_id": str(rule_id),
                "wazuh_level": str(rule_level),
                "agent_name": agent.get('name', 'unknown'),
                "source": "wazuh_alert_processor"
            },
            "annotations": annotations,
            "generatorURL": f"http://{cfg['server']['host']}:5601"
        }]

        timeout = cfg['output'].get('alertmanager_timeout', 3)

        # 强制不使用代理
        resp = requests.post(
            am_url,
            json=payload,
            timeout=timeout,
            proxies={"http": None, "https": None}
        )

        if resp.status_code in [200, 202]:
            return True
        else:
            logging.warning(f"Alertmanager push failed: {resp.status_code} - {resp.text}")
            return False

    except Exception as e:
        logging.error(f"Error pushing to Alertmanager: {e}")
        return False


async def process_wazuh_alert(alert):
    """
    处理单个 Wazuh 报警信息，判断是否需要告警
    - 规则级别 level ≥ 8 时，必须发送告警
    - 规则级别 level < 8 时，由 AI 根据告警信息具体判断
    """
    rule_level = alert.get('rule', {}).get('level', 0)
    rule_id = alert.get('rule', {}).get('id', 'unknown')

    # 所有告警都由 AI 根据告警信息具体判断
    if autogen_available:
        try:
            # 提取告警的关键信息
            rule = alert.get('rule', {})
            agent = alert.get('agent', {})

            # 构建简化的告警信息
            simplified_alert = {
                'rule': {
                    'id': rule.get('id', 'unknown'),
                    'level': rule.get('level', 0),
                    'description': rule.get('description', 'No description'),
                    'groups': rule.get('groups', [])[:5]
                },
                'agent': {
                    'id': agent.get('id', 'unknown'),
                    'name': agent.get('name', 'unknown')
                },
                'firedtimes': alert.get('firedtimes', 1),
                'timestamp': alert.get('timestamp', 'unknown'),
                'full_log': alert.get('full_log', '')[:500]
            }

            prompt = """你是一个高级SOC安全分析专家。

请对以下告警进行多维度聚合分析，而不是单条判断。

告警详情：
{}

分析要求：
1. 频率分析
- 统计 firedtimes
- 判断是否超过正常基线
- 判断是否为爆发式增长

2. 横向关联分析
- 是否存在同一IP多次行为
- 是否存在同一账号被多次尝试
- 是否存在同一主机多种异常

3. 纵向关联分析
- 是否出现不同日志类型的关联异常
- 是否形成攻击链（扫描 → 爆破 → 成功登录 → 横向移动）

4. 资产风险分析
- 目标账号是否为高价值账号（如 oracle、root、admin）
- 目标主机是否为数据库服务器/域控

5. MITRE映射
- 是否符合 T1110 (Brute Force)
- 是否符合 T1078 (Valid Accounts)
- 是否符合 T1550 (Use of Alternate Auth)

6. 噪音识别
- 是否为常见系统错误
- 是否为配置类问题
- 是否为周期性业务异常

输出必须包含：
- 是否为真实攻击
- 是否值得发送安全告警
- 风险等级（低/中/高）
- 是否需要响应
- 简要理由

注意：
高 firedtimes 不等于攻击。
必须结合 IP、账号、资产价值、日志类型综合判断。
请模拟一名经验5年以上的SOC分析师，
如果这是你值班，你会不会升级为安全事件？

输出格式（JSON）：
{{
  "should_alert": true/false,
  "severity": "critical/warning/info",
  "reason": "判断理由（30字以内）"
}}

约束条件：
- should_alert=true 时，severity 必须是 warning 或 critical
- should_alert=false 时，severity 必须是 info
- reason 请控制在30字以内，简洁明了
""".format(json.dumps(simplified_alert, ensure_ascii=False, indent=2))

            # 与 autogen 代理交互
            result = await assistant.run(task=prompt)
            response = result.messages[-1].content

            # 提取 JSON 响应
            import re
            json_match = re.search(r'\{[^}]*should_alert[^}]*\}', response, re.DOTALL)
            if json_match:
                decision = json.loads(json_match.group(0))
                # 直接返回AI的决策
                return {
                    "should_alert": decision.get('should_alert', False),
                    "severity": decision.get('severity', 'info'),
                    "reason": decision.get('reason', 'AI判断')[:REASON_MAX_LENGTH]
                }
        except Exception as e:
            logging.error(f"Error processing with autogen: {e}")
            pass

    # AI不可用时，使用简化的默认判断
    logging.warning(f"AI not available for rule_id={rule_id}, using simplified default judgment")
    # 基于规则级别和触发次数进行判断
    if rule_level >= 12:
        # 严重级别，倾向发送
        return {"should_alert": True, "severity": "critical", "reason": f"规则级别较高({rule_level})"}
    elif rule_level >= 8:
        # 中等级别，根据触发次数判断
        firedtimes = alert.get('firedtimes', 1)
        if firedtimes >= 5:
            return {"should_alert": True, "severity": "warning", "reason": f"规则级别中等({rule_level})，触发次数较多({firedtimes})"}
        else:
            return {"should_alert": False, "severity": "info", "reason": f"规则级别中等({rule_level})，触发次数较少({firedtimes})"}
    else:
        # 低级别，默认不发送
        return {"should_alert": False, "severity": "info", "reason": f"规则级别较低({rule_level})"}


async def process_aggregated_alert(aggregated_alert):
    """
    处理聚合后的 Wazuh 报警信息，判断是否需要告警
    - 规则级别 level ≥ 8 时，必须发送告警
    - 规则级别 level < 8 时，由 AI 根据告警信息具体判断
    """
    rule_level = aggregated_alert.get('rule', {}).get('level', 0)
    count = aggregated_alert.get('count', 1)
    rule_id = aggregated_alert.get('rule', {}).get('id', 'unknown')
    description = aggregated_alert.get('rule', {}).get('description', 'No description')

    logging.info(f"Processing aggregated alert: rule_id={rule_id}, count={count}, level={rule_level}")

    # 所有告警都由 AI 根据告警信息具体判断
    if autogen_available:
        try:
            logging.info(f"Using AutoGen to analyze aggregated alert: {description} (count: {count})")
            # 构建提示信息，包含聚合告警的关键信息
            rule = aggregated_alert.get('rule', {})
            agent = aggregated_alert.get('agent', {})
            count = aggregated_alert.get('count', 1)
            first_seen = aggregated_alert.get('first_seen', '')
            last_seen = aggregated_alert.get('last_seen', '')
            sample_logs = aggregated_alert.get('sample_logs', [])

            # 限制样本日志：只取1条，每条最多200字符
            limited_sample_logs = []
            for log in sample_logs[:1]:  # 只取1条
                limited_sample_logs.append(log[:200])  # 最多200字符

            # 构建提示信息，让AI自主判断
            escaped_description = rule.get('description', 'No description').replace('\\', '\\\\').replace('"', '\\"')
            rule_groups = rule.get('groups') or []
            groups_str = ', '.join(rule_groups[:8]) if rule_groups else '无'
            
            # 构建样本日志信息
            sample_logs_str = ""
            if sample_logs:
                sample_logs_str = "\n样本日志:\n" + "\n".join([f"- {log[:150]}" for log in sample_logs[:2]])
            
            prompt = f"""你是一名拥有5年以上经验的SOC高级分析师。

禁止直接下结论。
必须按照以下步骤逐项推理后再做最终判断。

======================
【告警信息】
- 描述: {escaped_description[:120]}
- 规则ID: {rule.get('id', 'unknown')}
- 规则级别: {rule.get('level', 0)}
- 规则分组: {groups_str}
- 触发次数: {count}
- 代理: {agent.get('name', 'unknown')}
- 首次触发: {first_seen}
- 最后触发: {last_seen}
{sample_logs_str}
======================

【第一步：客观事实提取】
- 是否存在重复IP？
- 是否存在高价值账号？
- 是否存在认证失败关键词？
- 是否存在成功登录？
- 是否存在权限提升？
- 是否存在跨主机行为？
- 是否存在多种不同错误类型？

【第二步：攻击特征判断】
- 是否符合暴力破解特征？
- 是否符合横向移动特征？
- 是否符合异常提权特征？
- 是否形成攻击链？
- 是否存在异常密度（同一主机5分钟内多种不同错误）？

【第三步：噪音可能性判断】
- 是否可能为系统错误？
- 是否可能为配置问题？
- 是否可能为正常运维行为？
- 是否可能为周期性业务异常？

【第四步：风险权重评估】
结合以下原则：
- firedtimes高 ≠ 必然攻击
- 默认立场：中性。仅当证据明确为噪音时才抑制。
- level ≥ 9 且 firedtimes ≥ 5 时，提高攻击概率权重
- 针对root/admin/oracle需提高敏感度
- 单条错误日志默认噪音

【系统错误例外机制】
系统错误默认视为噪音，除非满足以下任一条件：
- firedtimes ≥ 20
- 时间窗口 < 2分钟
- 同时伴随认证失败
- 同时伴随权限变更

【Windows错误精准判断】
对于 Windows application/system error 类规则（如61061、61110、60602）：
- 若无异常IP、无登录行为、无权限行为、无网络连接异常，则判定为info

【sudo提权精准判断】
对于 sudo 提权类规则（如5402、5403）：
- 默认warning但不升级为安全事件
- 仅当满足以下任一条件时才升级为critical：
  * 与爆破或异常登录关联
  * 非工作时间
  * 普通业务账号（非运维账号）
  * 短时间内多次不同账号提权
- 运维账号在工作时间正常服务器上的sudo→root为正常行为

【认证失败精准判断】
对于认证失败类规则（如5710、5503）：
- 单次或少量（firedtimes ≤ 3）认证失败默认视为噪音
- 仅当满足以下任一条件时才告警：
  * firedtimes ≥ 5
  * 针对高价值账号
  * 与其他攻击行为关联（如暴力破解、异常登录）
  * 短时间内多次不同账号认证失败
  
======================

最后输出 JSON：

{{
  "should_alert": true/false,
  "severity": "critical/warning/info",
  "confidence": "high/medium/low",
  "reason": "不超过30字，必须基于具体证据"
}}

规则：
- should_alert=true → severity必须为warning或critical
- should_alert=false → severity必须为info
- 禁止模糊表述（如"可能"、"疑似"）
- 禁止凭空猜测
- 必须基于日志中出现的具体信息
            """

            # 与 autogen 代理交互
            logging.debug("Sending prompt to AutoGen agent")
            
            # 创建临时代理实例，避免对话历史累积
            temp_assistant = AssistantAgent(
                "temp_assistant",
                model_client=model_client,
                system_message="你是一个高级SOC安全分析专家，拥有5年以上的安全事件分析经验。请对告警进行多维度聚合分析，而不是单条判断。请结合频率分析、横向关联分析、纵向关联分析、资产风险分析、MITRE映射和噪音识别等多个维度进行综合判断。注意：高firedtimes不等于攻击，必须结合IP、账号、资产价值、日志类型等因素综合判断。如果这是你值班，你会不会升级为安全事件？输出时：severity 为一级输出，决定是否告警；should_alert 必须由 severity 推导（info→false，warning/critical→true），不可与 severity 矛盾。reason 控制在 30 字以内。\n\n重要要求：\n1. 所有回复必须使用纯文本格式，绝对不要使用markdown格式（如**加粗**、##标题、```代码块等）\n2. 回复内容必须是完整的中文，不要包含Unicode编码（如\u53d1\u9001）\n3. 分析结果要清晰、结构化，使用普通文本的列表和段落格式\n4. 直接输出分析内容，不要添加任何前缀或引言\n5. 确保回复内容易于阅读和理解"
            )
            
            result = await temp_assistant.run(task=prompt)

            # 获取 autogen 的回复
            response = result.messages[-1].content
            logging.debug(f"Received response from AutoGen: {response[:200]}...")
            
            # 清理临时代理
            del temp_assistant

            # 提取 JSON 响应
            import re
            json_match = re.search(r'\{[^}]*should_alert[^}]*\}', response, re.DOTALL)
            if json_match:
                decision = json.loads(json_match.group(0))
                logging.info(
                    f"AutoGen analysis result: should_alert={decision.get('should_alert')}, severity={decision.get('severity')}")
                # 直接返回AI的决策，减少规则干预
                return {
                    "should_alert": decision.get('should_alert', False),
                    "severity": decision.get('severity', 'info'),
                    "reason": decision.get('reason', 'AI判断')[:REASON_MAX_LENGTH]
                }
        except Exception as e:
            logging.error(f"Error processing aggregated alert with autogen: {e}")
            # 出错时使用保守的默认判断
            pass

    # AI不可用时，使用简化的默认判断
    logging.warning(f"AI not available, using simplified default judgment for rule_id={rule_id}")
    # 基于规则级别和触发次数进行判断
    if rule_level >= 12:
        # 严重级别，倾向发送
        return {"should_alert": True, "severity": "critical", "reason": f"规则级别较高({rule_level})"}
    elif rule_level >= 8:
        # 中等级别，根据触发次数判断
        count = aggregated_alert.get('count', 1)
        if count >= 5:
            return {"should_alert": True, "severity": "warning", "reason": f"规则级别中等({rule_level})，触发次数较多({count})"}
        else:
            return {"should_alert": False, "severity": "info", "reason": f"规则级别中等({rule_level})，触发次数较少({count})"}
    else:
        # 低级别，默认不发送
        return {"should_alert": False, "severity": "info", "reason": f"规则级别较低({rule_level})"}


def read_ndjson_files():
    """
    读取当前目录下的所有 ndjson 文件
    """
    ndjson_files = []
    # 从配置中获取文件模式
    file_pattern = cfg.get('local_files', {}).get('file_pattern', '*.ndjson')
    # 使用 glob 查找文件
    for file in glob.glob(file_pattern):
        ndjson_files.append(file)
    return ndjson_files


async def list_alerts(processed_alerts):
    """
    列出所有告警
    """
    print("\n告警列表：")
    print("-" * 80)
    for i, alert_info in enumerate(processed_alerts):
        alert = alert_info['alert']
        decision = alert_info['decision']
        rule = alert.get('rule', {})
        print(f"[{i}] 描述: {rule.get('description', 'No description')}")
        print(f"   规则ID: {rule.get('id', 'unknown')} | 级别: {rule.get('level', 0)}")
        print(f"   建议级别: {decision.get('severity', 'info')} | 发送: {decision.get('should_alert', False)}")
        print(f"   理由: {decision.get('reason', 'No reason')}")
        print(f"   触发次数: {alert.get('count', 1)}")
        print("-" * 80)


async def list_filtered_alerts(processed_alerts, indices):
    """
    列出过滤后的告警
    """
    print("\n过滤后的告警列表：")
    print("-" * 80)
    for i in indices:
        if 0 <= i < len(processed_alerts):
            alert_info = processed_alerts[i]
            alert = alert_info['alert']
            decision = alert_info['decision']
            rule = alert.get('rule', {})
            print(f"[{i}] 描述: {rule.get('description', 'No description')}")
            print(f"   规则ID: {rule.get('id', 'unknown')} | 级别: {rule.get('level', 0)}")
            print(f"   建议级别: {decision.get('severity', 'info')} | 发送: {decision.get('should_alert', False)}")
            print(f"   理由: {decision.get('reason', 'No reason')}")
            print(f"   触发次数: {alert.get('count', 1)}")
            print("-" * 80)


async def filter_alerts(processed_alerts, condition):
    """
    根据条件过滤告警信息
    """
    filtered_indices = []
    print(f"\n根据条件过滤告警: {condition}")
    print("-" * 80)

    # 简单的条件过滤实现
    for i, alert_info in enumerate(processed_alerts):
        alert = alert_info['alert']
        decision = alert_info['decision']
        rule = alert.get('rule', {})

        # 检查条件是否匹配
        if condition.lower() in str(rule.get('description', '')).lower() or \
                condition.lower() in str(rule.get('id', '')).lower() or \
                condition.lower() in str(decision.get('severity', '')).lower():
            filtered_indices.append(i)
            print(f"[{i}] 描述: {rule.get('description', 'No description')}")
            print(f"   规则ID: {rule.get('id', 'unknown')} | 级别: {rule.get('level', 0)}")
            print(f"   建议级别: {decision.get('severity', 'info')} | 发送: {decision.get('should_alert', False)}")
            print("-" * 80)

    print(f"\n过滤完成，找到 {len(filtered_indices)} 条匹配的告警。")
    return filtered_indices


async def send_alert(processed_alerts, index):
    """
    发送指定索引的告警到 Alertmanager
    """
    if 0 <= index < len(processed_alerts):
        alert_info = processed_alerts[index]
        aggregated_alert = alert_info['alert']

        # 构建发送到Alertmanager的告警信息
        alert_to_send = {
            'rule': aggregated_alert['rule'],
            'agent': aggregated_alert['agent'],
            'data': {},
            'full_log': f"Aggregated alert: {aggregated_alert['count']} occurrences from {aggregated_alert['first_seen']} to {aggregated_alert['last_seen']}\nSample logs: {chr(10).join(aggregated_alert['sample_logs'][:2])}"
        }

        if push_to_alertmanager(alert_to_send):
            print(f"[聚合告警 #{index}] 成功发送: {aggregated_alert['rule'].get('description', 'No description')}")
        else:
            print(f"[聚合告警 #{index}] 发送失败: {aggregated_alert['rule'].get('description', 'No description')}")
    else:
        print("无效的索引，请输入正确的告警编号。")


async def send_all_alerts(processed_alerts):
    """
    发送所有告警到 Alertmanager
    """
    success_count = 0
    failure_count = 0

    for i, alert_info in enumerate(processed_alerts):
        aggregated_alert = alert_info['alert']

        # 构建发送到Alertmanager的告警信息
        alert_to_send = {
            'rule': aggregated_alert['rule'],
            'agent': aggregated_alert['agent'],
            'data': {},
            'full_log': f"Aggregated alert: {aggregated_alert['count']} occurrences from {aggregated_alert['first_seen']} to {aggregated_alert['last_seen']}\nSample logs: {chr(10).join(aggregated_alert['sample_logs'][:2])}"
        }

        if push_to_alertmanager(alert_to_send):
            print(f"[聚合告警 #{i}] 成功发送: {aggregated_alert['rule'].get('description', 'No description')}")
            success_count += 1
        else:
            print(f"[聚合告警 #{i}] 发送失败: {aggregated_alert['rule'].get('description', 'No description')}")
            failure_count += 1

    print(f"\n发送完成: 成功 {success_count} 条，失败 {failure_count} 条。")


async def send_filtered_alerts(processed_alerts, filtered_indices):
    """
    发送过滤后的告警到 Alertmanager
    """
    success_count = 0
    failure_count = 0

    for i in filtered_indices:
        if 0 <= i < len(processed_alerts):
            alert_info = processed_alerts[i]
            aggregated_alert = alert_info['alert']

            # 构建发送到Alertmanager的告警信息
            alert_to_send = {
                'rule': aggregated_alert['rule'],
                'agent': aggregated_alert['agent'],
                'data': {},
                'full_log': f"Aggregated alert: {aggregated_alert['count']} occurrences from {aggregated_alert['first_seen']} to {aggregated_alert['last_seen']}\nSample logs: {chr(10).join(aggregated_alert['sample_logs'][:2])}"
            }

            if push_to_alertmanager(alert_to_send):
                print(f"[聚合告警 #{i}] 成功发送: {aggregated_alert['rule'].get('description', 'No description')}")
                success_count += 1
            else:
                print(f"[聚合告警 #{i}] 发送失败: {aggregated_alert['rule'].get('description', 'No description')}")
                failure_count += 1

    print(f"\n发送完成: 成功 {success_count} 条，失败 {failure_count} 条。")


async def interactive_mode(processed_alerts):
    """
    交互式模式，允许用户与 autogen 交互，选择哪些告警信息发送到 alertmanager
    """
    # 存储过滤后的告警索引
    filtered_indices = []

    # 命令缩写映射
    command_aliases = {
        'ls': 'list',
        's': 'send',
        'd': 'delete',
        'f': 'filter',
        'r': 'reset filter',
        'g': 'group',
        'so': 'sort',
        'e': 'export',
        'h': 'help',
        'm': 'metrics'
    }

    print("\n=== 交互式告警管理模式 ===")
    print("可用命令:")
    print("1. 告警查看与摘要:")
    print("   - list (ls) [page <n>] [critical|warning|info] - 列出告警（支持分页和级别过滤）")
    print("   - summary - 显示告警聚合摘要")
    print("   - metrics (m) - 显示评价指标报告")
    print("2. 告警过滤:")
    print("   - filter (f) <条件> - 根据条件过滤告警信息")
    print("   - reset filter (r) - 重置过滤状态")
    print("3. 告警发送:")
    print("   - send (s) <索引> - 发送指定索引的告警到 Alertmanager")
    print("   - send (s) <范围> - 发送指定范围的告警（如 1-5 或 1,3,5）")
    print("   - send (s) all - 发送所有告警到 Alertmanager")
    print("   - send (s) filtered - 发送过滤后的告警到 Alertmanager")
    print("4. 告警删除:")
    print("   - delete (d) <索引> - 删除指定索引的告警")
    print("   - delete (d) all - 删除所有告警")
    print("   - delete (d) filtered - 删除过滤后的告警")
    print("   - delete (d) not filtered - 删除未被过滤的告警")
    print("5. 告警组织:")
    print("   - group (g) by <维度> - 按维度分组显示告警（severity, rule_id, agent）")
    print("   - sort (so) by <字段> - 按字段排序告警（count, timestamp, level）")
    print("6. 告警导出:")
    print("   - export (e) <file_path> [--filtered] [--format <format>] - 导出告警到文件")
    print("7. 其他:")
    print("   - help (h) [command] - 显示命令帮助")
    print("   - exit - 退出交互式模式")

    while True:
        try:
            # 显示当前状态
            total_alerts = len(processed_alerts)
            filtered_count = len(filtered_indices)
            filter_status = "已过滤" if filtered_indices else "未过滤"

            prompt = f"\n[当前状态: {filter_status} | 总告警: {total_alerts} | 过滤后: {filtered_count}]\n请输入命令: "
            user_input = input(prompt).strip()

            if not user_input:
                continue

            # 处理命令缩写
            parts = user_input.split()
            if parts and parts[0] in command_aliases:
                parts[0] = command_aliases[parts[0]]
                user_input = ' '.join(parts)

            if user_input.lower() == "exit":
                print("退出交互式模式...")
                break

            elif user_input.lower().startswith("list"):
                # 处理 list 命令，支持分页和级别过滤
                parts = user_input.split()
                if len(parts) == 1:
                    # 基本 list 命令
                    if filtered_indices:
                        await list_filtered_alerts(processed_alerts, filtered_indices)
                    else:
                        await list_alerts(processed_alerts)
                elif len(parts) >= 2:
                    # 处理 list page <n> 或 list <severity>
                    if parts[1].lower() == "page":
                        # 分页功能（简化实现，只显示前20条）
                        try:
                            page = int(parts[2]) if len(parts) >= 3 else 1
                            page_size = 20
                            start = (page - 1) * page_size
                            end = start + page_size

                            if filtered_indices:
                                # 对过滤后的告警分页
                                paginated_indices = filtered_indices[start:end]
                                if paginated_indices:
                                    await list_filtered_alerts(processed_alerts, paginated_indices)
                                else:
                                    print("当前页无告警数据。")
                            else:
                                # 对所有告警分页
                                total_pages = (len(processed_alerts) + page_size - 1) // page_size
                                print(f"第 {page} 页，共 {total_pages} 页")

                                for i in range(start, min(end, len(processed_alerts))):
                                    alert_info = processed_alerts[i]
                                    alert = alert_info['alert']
                                    decision = alert_info['decision']
                                    rule = alert.get('rule', {})
                                    agent = alert.get('agent', {})

                                    print(f"\n[{i}]")
                                    print(f"描述: {rule.get('description', 'No description')}")
                                    print(f"规则级别: {rule.get('level', 0)}")
                                    print(f"建议级别: {decision.get('severity', 'info')}")
                                    print(f"是否发送: {decision.get('should_alert', False)}")
                                    print(f"理由: {decision.get('reason', 'No reason')}")
                        except ValueError:
                            print("无效的页码，请输入数字。")
                    elif parts[1].lower() in ["critical", "warning", "info"]:
                        # 按严重级别过滤
                        severity = parts[1].lower()
                        filtered_by_severity = []

                        if filtered_indices:
                            # 对过滤后的告警按级别过滤
                            for index in filtered_indices:
                                if 0 <= index < len(processed_alerts):
                                    alert_info = processed_alerts[index]
                                    if alert_info['decision'].get('severity', 'info') == severity:
                                        filtered_by_severity.append(index)
                        else:
                            # 对所有告警按级别过滤
                            for i, alert_info in enumerate(processed_alerts):
                                if alert_info['decision'].get('severity', 'info') == severity:
                                    filtered_by_severity.append(i)

                        if filtered_by_severity:
                            await list_filtered_alerts(processed_alerts, filtered_by_severity)
                        else:
                            print(f"没有找到 {severity} 级别的告警。")

            elif user_input.lower() == "summary":
                # 显示告警聚合摘要
                total_alerts = len(processed_alerts)
                severity_counts = {'critical': 0, 'warning': 0, 'info': 0}
                rule_id_counts = {}
                should_alert_count = 0

                for i, alert_info in enumerate(processed_alerts):
                    if filtered_indices and i not in filtered_indices:
                        continue

                    alert = alert_info['alert']
                    decision = alert_info['decision']
                    rule = alert.get('rule', {})
                    rule_id = rule.get('id', 'unknown')
                    severity = decision.get('severity', 'info')

                    # 统计严重级别
                    if severity in severity_counts:
                        severity_counts[severity] += 1

                    # 统计规则ID
                    if rule_id not in rule_id_counts:
                        rule_id_counts[rule_id] = 0
                    rule_id_counts[rule_id] += 1

                    # 统计推荐发送的告警
                    if decision.get('should_alert', False):
                        should_alert_count += 1

                print("\n" + "=" * 60)
                print("告警聚合摘要")
                print("=" * 60)
                print(f"总告警数: {total_alerts}")
                if filtered_indices:
                    print(f"当前过滤范围: {len(filtered_indices)} 条告警")
                print("严重级别分布:")
                for severity, count in severity_counts.items():
                    print(f"- {severity.capitalize()}: {count}")
                print(f"推荐发送: {should_alert_count}")

                # 输出按规则ID聚合的统计
                if rule_id_counts:
                    print("按规则ID聚合 (前10个):")
                    sorted_rules = sorted(rule_id_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                    for rule_id, count in sorted_rules:
                        print(f"- 规则{rule_id}: {count}条")
                print("=" * 60)

            elif user_input.lower().startswith("filter"):
                condition = user_input[7:].strip()
                if condition:
                    filtered_indices = await filter_alerts(processed_alerts, condition)
                else:
                    print("请指定过滤条件。")

            elif user_input.lower().startswith("send"):
                parts = user_input.split()
                if len(parts) >= 2:
                    if parts[1].lower() == "all":
                        await send_all_alerts(processed_alerts)
                    elif parts[1].lower() == "filtered":
                        await send_filtered_alerts(processed_alerts, filtered_indices)
                    else:
                        # 处理单个索引、范围或逗号分隔的索引
                        target = parts[1]
                        if '-' in target:
                            # 处理范围输入，如 "send 1-5"
                            try:
                                start, end = target.split('-')
                                start_idx = int(start)
                                end_idx = int(end)

                                if filtered_indices:
                                    # 确保索引在过滤范围内
                                    if start_idx >= 0 and end_idx < len(filtered_indices):
                                        for i in range(start_idx, end_idx + 1):
                                            original_index = filtered_indices[i]
                                            await send_alert(processed_alerts, original_index)
                                    else:
                                        print("无效的索引范围，请输入在过滤范围内的数字。")
                                else:
                                    # 确保索引在有效范围内
                                    if start_idx >= 0 and end_idx < len(processed_alerts):
                                        for i in range(start_idx, end_idx + 1):
                                            await send_alert(processed_alerts, i)
                                    else:
                                        print("无效的索引范围，请输入有效的数字范围。")
                            except ValueError:
                                print("无效的索引格式，请输入数字或数字范围。")
                        elif ',' in target:
                            # 处理逗号分隔的索引，如 "send 1,3,5"
                            try:
                                indices = [int(idx.strip()) for idx in target.split(',')]

                                if filtered_indices:
                                    # 确保索引在过滤范围内
                                    for i in indices:
                                        if 0 <= i < len(filtered_indices):
                                            original_index = filtered_indices[i]
                                            await send_alert(processed_alerts, original_index)
                                        else:
                                            print(f"无效的索引 {i}，请输入在过滤范围内的数字。")
                                else:
                                    # 确保索引在有效范围内
                                    for i in indices:
                                        if 0 <= i < len(processed_alerts):
                                            await send_alert(processed_alerts, i)
                                        else:
                                            print(f"无效的索引 {i}，请输入有效的数字。")
                            except ValueError:
                                print("无效的索引格式，请输入数字或逗号分隔的数字。")
                        else:
                            # 处理单个索引
                            try:
                                index = int(target)
                                # 如果有过滤状态，使用过滤后的索引映射
                                if filtered_indices:
                                    if 0 <= index < len(filtered_indices):
                                        original_index = filtered_indices[index]
                                        await send_alert(processed_alerts, original_index)
                                    else:
                                        print("无效的索引，请输入在过滤范围内的数字。")
                                else:
                                    await send_alert(processed_alerts, index)
                            except ValueError:
                                print("无效的索引，请输入数字。")

            elif user_input.lower().startswith("delete"):
                parts = user_input.split()
                if len(parts) >= 2:
                    if parts[1].lower() == "all":
                        # 删除所有告警
                        processed_alerts.clear()
                        filtered_indices.clear()
                        print("已删除所有告警。")
                    elif parts[1].lower() == "filtered":
                        # 删除过滤后的告警
                        if filtered_indices:
                            # 按降序删除，避免索引偏移
                            for i in sorted(filtered_indices, reverse=True):
                                if 0 <= i < len(processed_alerts):
                                    processed_alerts.pop(i)
                            # 更新过滤后的索引
                            filtered_indices.clear()
                            print("已删除过滤后的告警。")
                        else:
                            print("没有过滤后的告警可删除。")
                    elif parts[1].lower() == "not" and len(parts) >= 3 and parts[2].lower() == "filtered":
                        # 删除未被过滤的告警
                        if filtered_indices:
                            # 构建未过滤的索引列表
                            not_filtered = [i for i in range(len(processed_alerts)) if i not in filtered_indices]
                            # 按降序删除
                            for i in sorted(not_filtered, reverse=True):
                                processed_alerts.pop(i)
                            # 更新过滤后的索引
                            # 重新映射过滤后的索引
                            new_filtered = []
                            for i in filtered_indices:
                                # 计算新索引（原索引之前有多少个未过滤的告警被删除）
                                offset = sum(1 for j in not_filtered if j < i)
                                new_index = i - offset
                                if new_index >= 0:
                                    new_filtered.append(new_index)
                            filtered_indices = new_filtered
                            print("已删除未被过滤的告警。")
                        else:
                            print("没有未被过滤的告警可删除。")
                    else:
                        # 删除指定索引的告警
                        try:
                            index = int(parts[1])
                            if filtered_indices:
                                if 0 <= index < len(filtered_indices):
                                    original_index = filtered_indices[index]
                                    if 0 <= original_index < len(processed_alerts):
                                        processed_alerts.pop(original_index)
                                        # 更新过滤后的索引
                                        filtered_indices.pop(index)
                                        # 调整过滤后的索引（如果删除的是前面的元素）
                                        for i in range(len(filtered_indices)):
                                            if filtered_indices[i] > original_index:
                                                filtered_indices[i] -= 1
                                        print(f"已删除告警 #{original_index}。")
                                    else:
                                        print("无效的告警索引。")
                                else:
                                    print("无效的索引，请输入在过滤范围内的数字。")
                            else:
                                if 0 <= index < len(processed_alerts):
                                    processed_alerts.pop(index)
                                    print(f"已删除告警 #{index}。")
                                else:
                                    print("无效的索引，请输入正确的告警编号。")
                        except ValueError:
                            print("无效的索引，请输入数字。")
                else:
                    print("请指定要删除的告警索引或范围。")

            elif user_input.lower().startswith("group"):
                parts = user_input.split()
                if len(parts) >= 3 and parts[1].lower() == "by":
                    dimension = parts[2].lower()

                    if dimension not in ["severity", "rule_id", "agent"]:
                        print("无效的分组维度，请使用 severity、rule_id 或 agent。")
                        continue

                    # 按维度分组告警
                    groups = {}
                    target_alerts = filtered_indices if filtered_indices else range(len(processed_alerts))

                    for i in target_alerts:
                        if 0 <= i < len(processed_alerts):
                            alert_info = processed_alerts[i]
                            alert = alert_info['alert']
                            decision = alert_info['decision']

                            if dimension == "severity":
                                key = decision.get('severity', 'info')
                            elif dimension == "rule_id":
                                key = alert.get('rule', {}).get('id', 'unknown')
                            elif dimension == "agent":
                                key = alert.get('agent', {}).get('name', 'unknown')

                            if key not in groups:
                                groups[key] = []
                            groups[key].append(i)

                    # 显示分组结果
                    print(f"\n按 {dimension} 分组的告警：")
                    print("-" * 80)

                    for key, indices in groups.items():
                        print(f"分组: {key} (共 {len(indices)} 条告警)")
                        print("-" * 40)
                        for i in indices[:5]:  # 只显示前5条
                            if 0 <= i < len(processed_alerts):
                                alert_info = processed_alerts[i]
                                alert = alert_info['alert']
                                rule = alert.get('rule', {})
                                print(f"[{i}] 描述: {rule.get('description', 'No description')}")
                                print(f"   规则ID: {rule.get('id', 'unknown')} | 级别: {rule.get('level', 0)}")
                        if len(indices) > 5:
                            print(f"   ... 还有 {len(indices) - 5} 条告警未显示")
                        print("-" * 80)
                else:
                    print("无效的 group 命令格式，请使用 'group by <dimension>'。")

            elif user_input.lower().startswith("sort"):
                parts = user_input.split()
                if len(parts) >= 3 and parts[1].lower() == "by":
                    field = parts[2].lower()

                    if field not in ["count", "timestamp", "level"]:
                        print("无效的排序字段，请使用 count、timestamp 或 level。")
                        continue

                    # 按字段排序告警
                    if filtered_indices:
                        # 对过滤后的告警排序
                        sorted_indices = sorted(filtered_indices, key=lambda i: {
                            'count': processed_alerts[i]['alert'].get('count', 1),
                            'timestamp': processed_alerts[i]['alert'].get('first_seen', ''),
                            'level': processed_alerts[i]['alert'].get('rule', {}).get('level', 0)
                        }[field], reverse=True)
                        await list_filtered_alerts(processed_alerts, sorted_indices)
                    else:
                        # 对所有告警排序并显示
                        sorted_alerts = sorted(enumerate(processed_alerts), key=lambda x: {
                            'count': x[1]['alert'].get('count', 1),
                            'timestamp': x[1]['alert'].get('first_seen', ''),
                            'level': x[1]['alert'].get('rule', {}).get('level', 0)
                        }[field], reverse=True)

                        print("\n排序后的告警列表：")
                        print("-" * 80)
                        for i, (original_index, alert_info) in enumerate(sorted_alerts):
                            alert = alert_info['alert']
                            decision = alert_info['decision']
                            rule = alert.get('rule', {})
                            print(f"[{original_index}] 描述: {rule.get('description', 'No description')}")
                            print(f"   规则ID: {rule.get('id', 'unknown')} | 级别: {rule.get('level', 0)}")
                            print(
                                f"   建议级别: {decision.get('severity', 'info')} | 发送: {decision.get('should_alert', False)}")
                            print(f"   触发次数: {alert.get('count', 1)}")
                            print("-" * 80)
                else:
                    print("无效的 sort 命令格式，请使用 'sort by <field>'。")

            elif user_input.lower().startswith("analyze"):
                parts = user_input.split()
                if len(parts) >= 2:
                    if parts[1].lower() == "all":
                        # 分析所有告警
                        print("\n正在分析所有告警...")
                        analyzed_count = 0
                        severity_counts = {'critical': 0, 'warning': 0, 'info': 0}
                        should_alert_count = 0

                        for i, alert_info in enumerate(processed_alerts):
                            aggregated_alert = alert_info['alert']
                            decision = await process_aggregated_alert(aggregated_alert)
                            alert_info['decision'] = decision
                            analyzed_count += 1

                            # 统计分析结果
                            severity = decision.get('severity', 'info')
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                            if decision.get('should_alert', False):
                                should_alert_count += 1

                        print("所有告警分析完成。")
                        print(f"共分析了 {analyzed_count} 条告警")
                        print("分析结果统计:")
                        for severity, count in severity_counts.items():
                            print(f"- {severity.capitalize()}: {count}")
                        print(f"推荐发送: {should_alert_count}")
                        print(f"不推荐发送: {analyzed_count - should_alert_count}")
                    elif parts[1].lower() == "filtered":
                        # 分析过滤后的告警
                        if filtered_indices:
                            print("\n正在分析过滤后的告警...")
                            analyzed_count = 0
                            severity_counts = {'critical': 0, 'warning': 0, 'info': 0}
                            should_alert_count = 0

                            for i in filtered_indices:
                                if 0 <= i < len(processed_alerts):
                                    alert_info = processed_alerts[i]
                                    aggregated_alert = alert_info['alert']
                                    decision = await process_aggregated_alert(aggregated_alert)
                                    alert_info['decision'] = decision
                                    analyzed_count += 1

                                    # 统计分析结果
                                    severity = decision.get('severity', 'info')
                                    if severity in severity_counts:
                                        severity_counts[severity] += 1
                                    if decision.get('should_alert', False):
                                        should_alert_count += 1

                            print("过滤后的告警分析完成。")
                            print(f"共分析了 {analyzed_count} 条告警")
                            print("分析结果统计:")
                            for severity, count in severity_counts.items():
                                print(f"- {severity.capitalize()}: {count}")
                            print(f"推荐发送: {should_alert_count}")
                            print(f"不推荐发送: {analyzed_count - should_alert_count}")
                        else:
                            print("没有过滤后的告警可分析。")
                    else:
                        # 分析指定索引的告警
                        try:
                            index = int(parts[1])
                            if 0 <= index < len(processed_alerts):
                                alert_info = processed_alerts[index]
                                aggregated_alert = alert_info['alert']

                                # 检查是否需要深度分析
                                deep_analysis = len(parts) >= 3 and parts[2] == "--deep"

                                # 重新分析该告警
                                decision = await process_aggregated_alert(aggregated_alert)

                                # 更新决策结果
                                alert_info['decision'] = decision

                                # 显示分析结果
                                print("\n分析结果：")
                                print("-" * 80)
                                rule = aggregated_alert.get('rule', {})
                                print(f"描述: {rule.get('description', 'No description')}")
                                print(f"规则ID: {rule.get('id', 'unknown')} | 级别: {rule.get('level', 0)}")
                                print(
                                    f"建议级别: {decision.get('severity', 'info')} | 发送: {decision.get('should_alert', False)}")
                                print(f"理由: {decision.get('reason', 'No reason')}")
                                print(f"触发次数: {aggregated_alert.get('count', 1)}")
                                if deep_analysis:
                                    print(f"首次触发: {aggregated_alert.get('first_seen', 'unknown')}")
                                    print(f"最后触发: {aggregated_alert.get('last_seen', 'unknown')}")
                                    print(f"代理: {aggregated_alert.get('agent', {}).get('name', 'unknown')}")
                                print("-" * 80)
                            else:
                                print("无效的索引，请输入正确的告警编号。")
                        except ValueError:
                            print("无效的索引，请输入数字。")
                else:
                    print("请指定要分析的告警索引或范围。")

            elif user_input.lower().startswith("export"):
                parts = user_input.split()
                if len(parts) >= 2:
                    file_path = parts[1]
                    filtered = len(parts) >= 3 and parts[2] == "--filtered"
                    format = "json"  # 默认格式

                    # 检查是否指定了格式
                    for i, part in enumerate(parts):
                        if part == "--format" and i + 1 < len(parts):
                            format = parts[i + 1].lower()
                            if format not in ["json", "csv", "alertmanager"]:
                                print("无效的导出格式，请使用 json、csv 或 alertmanager。")
                                format = "json"

                    # 确定要导出的告警
                    alerts_to_export = []
                    if filtered and filtered_indices:
                        for i in filtered_indices:
                            if 0 <= i < len(processed_alerts):
                                alerts_to_export.append(processed_alerts[i])
                    else:
                        alerts_to_export = processed_alerts

                    # 导出到文件
                    try:
                        if format == "json":
                            # 导出为 JSON
                            export_data = []
                            for alert_info in alerts_to_export:
                                export_item = {
                                    'alert': alert_info['alert'],
                                    'decision': alert_info['decision']
                                }
                                export_data.append(export_item)

                            # 写入文件（使用NDJSON格式，每行一个JSON对象）
                            with open(file_path, 'w', encoding='utf-8') as f:
                                for item in export_data:
                                    json.dump(item, f, ensure_ascii=False)
                                    f.write('\n')

                        elif format == "csv":
                            # 导出为 CSV
                            import csv
                            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                                writer = csv.writer(f)
                                # 写入表头
                                writer.writerow(
                                    ['索引', '描述', '规则ID', '级别', '建议级别', '发送', '理由', '触发次数',
                                     '首次触发', '最后触发', '代理'])
                                # 写入数据
                                for i, alert_info in enumerate(alerts_to_export):
                                    alert = alert_info['alert']
                                    decision = alert_info['decision']
                                    rule = alert.get('rule', {})
                                    agent = alert.get('agent', {})

                                    writer.writerow([
                                        i,
                                        rule.get('description', 'No description'),
                                        rule.get('id', 'unknown'),
                                        rule.get('level', 0),
                                        decision.get('severity', 'info'),
                                        decision.get('should_alert', False),
                                        decision.get('reason', 'No reason'),
                                        alert.get('count', 1),
                                        alert.get('first_seen', 'unknown'),
                                        alert.get('last_seen', 'unknown'),
                                        agent.get('name', 'unknown')
                                    ])
                        elif format == "alertmanager":
                            # 导出为 Alertmanager 格式的 JSON
                            export_data = []
                            for alert_info in alerts_to_export:
                                alert = alert_info['alert']
                                decision = alert_info['decision']
                                rule = alert.get('rule', {})
                                agent = alert.get('agent', {})

                                rule_id = rule.get('id', 'unknown')
                                rule_level = rule.get('level', 0)
                                rule_desc = rule.get('description', 'No description')
                                severity = decision.get('severity', 'info')

                                # 动态构建 annotations
                                # 使用英文描述，不包含任何中文
                                annotations = {
                                    "summary": rule_desc,
                                    "description": f"Alert Description: {rule_desc}\n"
                                                   f"Rule ID: {rule_id}\n"
                                                   f"Rule Level: {rule_level}\n"
                                                   f"Severity: {severity}\n"
                                                   f"Agent: {agent.get('name', 'unknown')}\n"
                                                   f"Count: {alert.get('count', 1)}\n"
                                                   f"First Seen: {alert.get('first_seen', 'unknown')}\n"
                                                   f"Last Seen: {alert.get('last_seen', 'unknown')}\n"
                                }

                                # 构建 payload
                                payload_item = {
                                    "labels": {
                                        "alertname": f"Wazuh Rule {rule_id}",
                                        "severity": severity,
                                        "wazuh_rule_id": str(rule_id),
                                        "wazuh_level": str(rule_level),
                                        "agent_name": agent.get('name', 'unknown'),
                                        "source": "wazuh_alert_processor"
                                    },
                                    "annotations": annotations,
                                    "generatorURL": f"http://{cfg['server']['host']}:5601"
                                }
                                export_data.append(payload_item)

                            # 确保output文件夹存在
                            import os
                            output_dir = "output"
                            if not os.path.exists(output_dir):
                                os.makedirs(output_dir)

                            # 调整文件路径到output文件夹
                            if not file_path.startswith(output_dir):
                                import os.path
                                file_name = os.path.basename(file_path)
                                file_path = os.path.join(output_dir, file_name)

                            # 写入文件（使用NDJSON格式，每行一个JSON对象）
                            with open(file_path, 'w', encoding='utf-8') as f:
                                for item in export_data:
                                    json.dump(item, f, ensure_ascii=False)
                                    f.write('\n')

                    except Exception as e:
                        print(f"导出文件失败: {e}")
                    else:
                        print(f"成功导出 {len(alerts_to_export)} 条告警到 {file_path} (格式: {format})。")
                else:
                    print("请指定导出文件路径。")

            elif user_input.lower() == "reset filter":
                filtered_indices = []
                print("过滤状态已重置。")

            elif user_input.lower() == "metrics" or user_input.lower() == "m":
                # 显示评价指标报告
                # 注意：交互式模式下无法获取原始告警列表，因此 Ground Truth 匹配可能不准确
                # 这里会尝试从聚合告警中反推原始告警数量
                update_evaluation_metrics(processed_alerts)
                evaluation_metrics.print_report()

            elif user_input.lower().startswith("help"):
                parts = user_input.split()
                if len(parts) == 1:
                    # 显示所有命令的简要说明
                    print("\n=== 命令帮助 ===")
                    print("list (ls) - 列出告警")
                    print("summary - 显示告警聚合摘要")
                    print("filter (f) <条件> - 根据条件过滤告警")
                    print("send (s) <索引> - 发送指定索引的告警")
                    print("send (s) <范围> - 发送指定范围的告警（如 1-5 或 1,3,5）")
                    print("send (s) all - 发送所有告警")
                    print("send (s) filtered - 发送过滤后的告警")
                    print("delete (d) <索引> - 删除指定索引的告警")
                    print("delete (d) all - 删除所有告警")
                    print("delete (d) filtered - 删除过滤后的告警")
                    print("delete (d) not filtered - 删除未被过滤的告警")
                    print("group (g) by <维度> - 按维度分组显示告警")
                    print("sort (so) by <字段> - 按字段排序告警")
                    print("export (e) <file_path> [--filtered] [--format <format>] - 导出告警到文件")
                    print("reset filter (r) - 重置过滤状态")
                    print("metrics (m) - 显示评价指标报告")
                    print("help (h) [command] - 显示命令帮助")
                    print("exit - 退出交互式模式")
                else:
                    # 显示指定命令的详细说明
                    command = parts[1].lower()
                    print(f"\n=== {command} 命令帮助 ===")

                    if command in ['list', 'ls']:
                        print("功能: 列出告警信息")
                        print("用法:")
                        print("  list - 列出所有告警")
                        print("  list page <n> - 分页显示告警（每页20条）")
                        print("  list <severity> - 按严重级别过滤显示告警（critical/warning/info）")
                    elif command in ['filter', 'f']:
                        print("功能: 根据条件过滤告警信息")
                        print("用法:")
                        print("  filter <条件> - 过滤包含指定条件的告警")
                        print("示例:")
                        print("  filter ssh - 过滤包含 'ssh' 的告警")
                    elif command in ['send', 's']:
                        print("功能: 发送告警到 Alertmanager")
                        print("用法:")
                        print("  send <索引> - 发送指定索引的告警")
                        print("  send <范围> - 发送指定范围的告警（如 1-5 或 1,3,5）")
                        print("  send all - 发送所有告警")
                        print("  send filtered - 发送过滤后的告警")
                    elif command in ['delete', 'd']:
                        print("功能: 删除不需要的告警")
                        print("用法:")
                        print("  delete <索引> - 删除指定索引的告警")
                        print("  delete all - 删除所有告警")
                        print("  delete filtered - 删除过滤后的告警")
                        print("  delete not filtered - 删除未被过滤的告警")
                    elif command in ['group', 'g']:
                        print("功能: 按不同维度分组显示告警")
                        print("用法:")
                        print("  group by severity - 按严重级别分组")
                        print("  group by rule_id - 按规则ID分组")
                        print("  group by agent - 按代理名称分组")
                    elif command in ['sort', 'so']:
                        print("功能: 按不同字段排序告警")
                        print("用法:")
                        print("  sort by count - 按触发次数排序")
                        print("  sort by timestamp - 按时间戳排序")
                        print("  sort by level - 按规则级别排序")
                    elif command in ['export', 'e']:
                        print("功能: 导出告警信息到文件")
                        print("用法:")
                        print("  export <file_path> - 导出所有告警到指定文件")
                        print("  export <file_path> --filtered - 导出过滤后的告警到指定文件")
                        print("  export <file_path> --format <format> - 指定导出格式（json/csv）")
                        print("示例:")
                        print("  export alerts.json - 导出所有告警到 alerts.json 文件（默认JSON格式）")
                        print("  export filtered_alerts.csv --filtered --format csv - 导出过滤后的告警到CSV文件")
                        print("  export analysis_result.json --format json - 导出所有告警到JSON文件")
                    elif command in ['reset', 'r']:
                        print("功能: 重置过滤状态")
                        print("用法:")
                        print("  reset filter - 重置所有过滤条件")
                    elif command in ['metrics', 'm']:
                        print("功能: 显示告警处理的评价指标报告")
                        print("说明:")
                        print("  基于 should.txt 中的 Ground Truth 计算以下指标:")
                        print("  - should.txt 中 1 表示该发送，0 表示不该发送")
                        print("  - 精确率 (Precision): TP / (TP + FP)，误报率控制能力")
                        print("  - 召回率 (Recall): TP / (TP + FN)，漏报率控制能力")
                        print("  - F1 Score: 精确率和召回率的调和平均")
                        print("  - 告警减少率: 1 - (AI发送告警数 / 原始告警数)")
                        print("  - 漏报率 (FNR): FN / (TP + FN)")
                        print("用法:")
                        print("  metrics - 显示完整的评价指标报告")
                    else:
                        print("未知命令，请查看可用命令列表。")

            else:
                print("无效的命令，请尝试以下命令：")
                print(
                    "list (ls), summary, metrics (m), filter (f), send (s), delete (d), group (g), sort (so), export (e), reset filter (r), help (h), exit")
        except Exception as e:
            print(f"命令执行出错: {e}")
            continue


async def process_file_with_collection(file_path):
    """
    处理单个 ndjson 文件并收集告警信息
    """
    logging.info(f"Processing file: {file_path}")

    count = 0
    alert_count = 0
    pushed_count = 0
    collected_alerts = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    alert = json.loads(line)
                    count += 1
                    collected_alerts.append(alert)
                except json.JSONDecodeError:
                    continue
        return collected_alerts
    except Exception as e:
        logging.error(f"Error processing file {file_path}: {e}")
        return []


def load_ground_truth_from_file(file_path: str = None) -> List[int]:
    """
    从 should.txt 文件加载 Ground Truth
    
    Args:
        file_path: should.txt 文件路径，如果为 None 则从配置文件读取
    
    Returns:
        包含 0/1 的列表，0 代表不该发送，1 代表该发送
    """
    if file_path is None:
        # 优先从配置文件读取 should_file
        should_file = cfg.get('local_files', {}).get('should_file')
        if should_file:
            file_path = should_file
        else:
            # 兼容旧版本：根据 file_pattern 推断 should.txt 路径
            file_pattern = cfg.get('local_files', {}).get('file_pattern', 'data/people.ndjson')
            base_dir = os.path.dirname(file_pattern)
            if not base_dir:
                base_dir = 'data'
            file_path = os.path.join(base_dir, 'should.txt')
    
    ground_truth = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    ground_truth.append(int(line))
        logging.info(f"成功加载 Ground Truth 文件: {file_path}，共 {len(ground_truth)} 条记录")
        return ground_truth
    except FileNotFoundError:
        logging.error(f"Ground Truth 文件未找到: {file_path}")
        return []
    except Exception as e:
        logging.error(f"加载 Ground Truth 文件失败: {e}")
        return []


def update_evaluation_metrics(processed_alerts: List[Dict], all_alerts: List[Dict] = None):
    """
    更新评价指标
    
    Args:
        processed_alerts: 处理后的告警列表（聚合后），每个元素包含 'alert' 和 'decision'
        all_alerts: 原始告警列表（聚合前），用于与 should.txt 的行数对应
    
    说明:
        - Ground Truth: 从 should.txt 文件读取，每行对应 people.ndjson 中同一行的告警
          0 代表不该发送，1 代表该发送
        - AI Prediction: AI判断结果
          - should_alert=True: AI判断发送 (Predicted Positive)
          - should_alert=False: AI判断不发送 (Predicted Negative)
    """
    global evaluation_metrics
    
    # 重置指标
    evaluation_metrics = EvaluationMetrics()
    
    # 加载 Ground Truth
    ground_truth = load_ground_truth_from_file()
    
    # 校验行数是否匹配
    if len(ground_truth) == 0:
        logging.error("无法加载 Ground Truth，评价指标计算失败")
        return evaluation_metrics
    
    if all_alerts is None:
        logging.error("无法获取原始告警列表，评价指标计算失败")
        return evaluation_metrics
    
    if len(ground_truth) != len(all_alerts):
        logging.warning(f"Ground Truth 行数 ({len(ground_truth)}) 与原始告警数 ({len(all_alerts)}) 不匹配")
        # 使用较小的值进行计算
        min_len = min(len(ground_truth), len(all_alerts))
        ground_truth = ground_truth[:min_len]
        all_alerts = all_alerts[:min_len]
    
    # 统计原始告警总数（使用实际处理的原始告警数量）
    evaluation_metrics.total_original_alerts = len(ground_truth)
    
    # 为每个原始告警计算 AI 的判断结果
    # 首先构建原始告警到聚合告警的映射
    # 由于我们没有直接的映射关系，这里简化处理：
    # 1. 按时间排序聚合告警
    # 2. 为每个原始告警找到对应的聚合告警
    
    # 按时间排序聚合告警
    sorted_processed_alerts = sorted(processed_alerts, key=lambda x: x['alert'].get('first_seen', ''))
    
    # 为每个原始告警计算 AI 的判断结果
    ai_sent_list = []
    for alert in all_alerts:
        # 找到对应的聚合告警
        matched = False
        for alert_info in sorted_processed_alerts:
            agg_alert = alert_info['alert']
            # 简单匹配：如果原始告警的时间在聚合告警的时间范围内，则认为是同一个告警
            first_seen = agg_alert.get('first_seen', '')
            last_seen = agg_alert.get('last_seen', '')
            alert_time = alert.get('timestamp', '')
            if first_seen <= alert_time <= last_seen:
                # 找到了对应的聚合告警，使用其决策
                ai_sent = alert_info['decision'].get('should_alert', False)
                ai_sent_list.append(ai_sent)
                matched = True
                break
        if not matched:
            # 没有找到对应的聚合告警，默认不发送
            ai_sent_list.append(False)
    
    # 统计 AI 发送的告警数
    evaluation_metrics.ai_sent_alerts = sum(ai_sent_list)
    
    # 计算 TP/FP/FN/TN
    evaluation_metrics.tp = 0
    evaluation_metrics.fp = 0
    evaluation_metrics.fn = 0
    evaluation_metrics.tn = 0
    
    # 清空告警列表
    evaluation_metrics.tp_alerts = []
    evaluation_metrics.fp_alerts = []
    evaluation_metrics.fn_alerts = []
    evaluation_metrics.tn_alerts = []
    
    for i, should_send_gt in enumerate(ground_truth):
        if i >= len(ai_sent_list) or i >= len(all_alerts):
            break
        ai_sent = ai_sent_list[i]
        alert = all_alerts[i]
        
        # 构建告警信息字典
        # 尝试获取AI判断的理由（如果有）
        reason = "No reason"
        # 找到对应的聚合告警，获取理由
        for alert_info_item in sorted_processed_alerts:
            agg_alert = alert_info_item['alert']
            first_seen = agg_alert.get('first_seen', '')
            last_seen = agg_alert.get('last_seen', '')
            alert_time = alert.get('timestamp', '')
            if first_seen <= alert_time <= last_seen:
                reason = alert_info_item['decision'].get('reason', 'No reason')
                break
        
        alert_info = {
            'rule_id': alert.get('rule', {}).get('id', 'unknown'),
            'description': alert.get('rule', {}).get('description', 'No description'),
            'level': alert.get('rule', {}).get('level', 0),
            'timestamp': alert.get('timestamp', 'unknown'),
            'should_send_gt': should_send_gt,
            'ai_sent': ai_sent,
            'reason': reason
        }
        
        if should_send_gt == 1 and ai_sent:
            # TP: 该发送且AI发送
            evaluation_metrics.tp += 1
            evaluation_metrics.tp_alerts.append(alert_info)
        elif should_send_gt == 0 and ai_sent:
            # FP: 不该发送但AI发送（误报）
            # 直接计算，不进行噪音过滤，确保统计基于原始告警状态
            evaluation_metrics.fp += 1
            evaluation_metrics.fp_alerts.append(alert_info)
        elif should_send_gt == 1 and not ai_sent:
            # FN: 该发送但AI没发（漏报）
            evaluation_metrics.fn += 1
            evaluation_metrics.fn_alerts.append(alert_info)
        else:
            # TN: 不该发送且AI没发
            evaluation_metrics.tn += 1
            evaluation_metrics.tn_alerts.append(alert_info)
    
    return evaluation_metrics


async def main():
    """
    主函数
    """
    global evaluation_metrics
    
    try:
        # 读取 ndjson 文件
        ndjson_files = read_ndjson_files()
        if not ndjson_files:
            print("未找到 ndjson 文件，请确保配置文件中的文件模式正确。")
            return

        # 处理每个文件
        all_alerts = []
        for file_path in ndjson_files:
            alerts = await process_file_with_collection(file_path)
            all_alerts.extend(alerts)

        if not all_alerts:
            print("未找到告警信息，请确保 ndjson 文件格式正确。")
            return

        print(f"成功读取 {len(all_alerts)} 条告警信息。")

        # 聚合告警
        aggregated_results = aggregate_alerts(all_alerts)

        if not aggregated_results:
            print("告警聚合失败，请检查日志获取详细信息。")
            return

        # 校验：所有聚合段的数量应等于源告警分组数量
        total_segments = len(aggregated_results)
        print(f"聚合完成：共生成 {total_segments} 个告警段。")

        # 处理聚合后的告警
        processed_alerts = []
        for window in aggregated_results:
            for alert in window['alerts']:
                decision = await process_aggregated_alert(alert)
                processed_alerts.append({
                    'alert': alert,
                    'decision': decision
                })

        print(f"成功处理 {len(processed_alerts)} 条聚合告警。")

        # 计算评价指标（传递原始告警列表以正确匹配 should.txt）
        update_evaluation_metrics(processed_alerts, all_alerts)

        # 显示聚合告警统计摘要
        print("\n" + "=" * 80)
        print("聚合告警统计摘要")
        print("=" * 80)
        print(f"总告警数: {len(processed_alerts)}")

        # 统计严重级别
        severity_counts = {'critical': 0, 'warning': 0, 'info': 0}
        should_alert_count = 0
        not_should_alert_count = 0

        for alert_info in processed_alerts:
            decision = alert_info['decision']
            severity = decision.get('severity', 'info')
            if severity in severity_counts:
                severity_counts[severity] += 1
            if decision.get('should_alert', False):
                should_alert_count += 1
            else:
                not_should_alert_count += 1

        print("严重级别分布:")
        for severity, count in severity_counts.items():
            print(f"- {severity.capitalize()}: {count}")
        print(f"推荐发送: {should_alert_count}")
        print(f"不推荐发送: {not_should_alert_count}")
        print("=" * 80)

        # 始终导出全部聚合告警 NDJSON（该文件内 sum(count)=源告警总数）
        import datetime
        import os
        output_dir = "output"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        all_ndjson_path = os.path.join(output_dir, f"all_aggregated_alerts_{timestamp}.ndjson")
        try:
            with open(all_ndjson_path, 'w', encoding='utf-8') as f:
                for alert_info in processed_alerts:
                    alert = alert_info['alert']
                    decision = alert_info['decision']
                    rule = alert.get('rule', {})
                    agent = alert.get('agent', {})
                    rule_id = rule.get('id', 'unknown')
                    rule_level = rule.get('level', 0)
                    rule_desc = rule.get('description', 'No description')
                    severity = decision.get('severity', 'info')
                    item = {
                        "labels": {
                            "alertname": f"Wazuh Rule {rule_id}",
                            "severity": severity,
                            "wazuh_rule_id": str(rule_id),
                            "wazuh_level": str(rule_level),
                            "agent_name": agent.get('name', 'unknown'),
                            "source": "wazuh_alert_processor"
                        },
                        "annotations": {
                            "summary": rule_desc,
                            "description": f"Alert Description: {rule_desc}\nRule ID: {rule_id}\nRule Level: {rule_level}\nSeverity: {severity}\nAgent: {agent.get('name', 'unknown')}\nCount: {alert.get('count', 1)}\nFirst Seen: {alert.get('first_seen', 'unknown')}\nLast Seen: {alert.get('last_seen', 'unknown')}\n"
                        },
                        "generatorURL": f"http://{cfg['server']['host']}:5601"
                    }
                    json.dump(item, f, ensure_ascii=False)
                    f.write('\n')
            total_count_in_export = sum(a['alert'].get('count', 1) for a in processed_alerts)
            print(f"\n全部聚合告警已导出: {all_ndjson_path}（条数: {len(processed_alerts)}，count 之和: {total_count_in_export} = 源告警数）")
        except Exception as e:
            print(f"导出全部聚合告警失败: {e}")

        # 显示Autogen智能分析结果
        print("\n" + "=" * 80)
        print("Autogen智能分析结果")
        print("=" * 80)

        # 显示推荐发送的告警
        recommended_alerts = []
        for i, alert_info in enumerate(processed_alerts):
            decision = alert_info['decision']
            if decision.get('should_alert', False):
                recommended_alerts.append(i)

        # 显示评价指标报告
        evaluation_metrics.print_report()

        if recommended_alerts:
            print("\n推荐发送的告警:")
            print("-" * 60)
            for i in recommended_alerts:
                alert_info = processed_alerts[i]
                alert = alert_info['alert']
                decision = alert_info['decision']
                rule = alert.get('rule', {})
                print(f"[{i}] 描述: {rule.get('description', 'No description')}")
                print(f"   规则ID: {rule.get('id', 'unknown')} | 级别: {rule.get('level', 0)}")
                print(f"   推荐级别: {decision.get('severity', 'info')}")
                print(f"   理由: {decision.get('reason', 'No reason')}")
                print("-" * 60)

            # 自动导出推荐告警为 Alertmanager 格式（全部聚合告警已在上面导出）
            print("\nAutomatically exporting recommended alerts to Alertmanager format...")
            try:
                recommended_alert_infos = []
                for i in recommended_alerts:
                    recommended_alert_infos.append(processed_alerts[i])

                json_file_path = os.path.join(output_dir, f"alertmanager_alerts_{timestamp}.json")
                ndjson_file_path = os.path.join(output_dir, f"alertmanager_alerts_{timestamp}.ndjson")

                # 导出为Alertmanager格式
                export_data = []
                for alert_info in recommended_alert_infos:
                    alert = alert_info['alert']
                    decision = alert_info['decision']
                    rule = alert.get('rule', {})
                    agent = alert.get('agent', {})

                    rule_id = rule.get('id', 'unknown')
                    rule_level = rule.get('level', 0)
                    rule_desc = rule.get('description', 'No description')
                    severity = decision.get('severity', 'info')

                    # 动态构建 annotations
                    # 使用英文描述，不包含任何中文
                    annotations = {
                        "summary": rule_desc,
                        "description": f"Alert Description: {rule_desc}\n"
                                       f"Rule ID: {rule_id}\n"
                                       f"Rule Level: {rule_level}\n"
                                       f"Severity: {severity}\n"
                                       f"Agent: {agent.get('name', 'unknown')}\n"
                                       f"Count: {alert.get('count', 1)}\n"
                                       f"First Seen: {alert.get('first_seen', 'unknown')}\n"
                                       f"Last Seen: {alert.get('last_seen', 'unknown')}\n"
                    }

                    # 构建 payload
                    payload_item = {
                        "labels": {
                            "alertname": f"Wazuh Rule {rule_id}",
                            "severity": severity,
                            "wazuh_rule_id": str(rule_id),
                            "wazuh_level": str(rule_level),
                            "agent_name": agent.get('name', 'unknown'),
                            "source": "wazuh_alert_processor"
                        },
                        "annotations": annotations,
                        "generatorURL": f"http://{cfg['server']['host']}:5601"
                    }
                    export_data.append(payload_item)

                # 写入JSON格式文件（数组格式）
                with open(json_file_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, ensure_ascii=False, indent=2)

                # 写入NDJSON格式文件（每行一个JSON对象）
                with open(ndjson_file_path, 'w', encoding='utf-8') as f:
                    for item in export_data:
                        json.dump(item, f, ensure_ascii=False)
                        f.write('\n')

                print(
                    f"Successfully exported {len(recommended_alert_infos)} recommended alerts to {json_file_path} (Alertmanager JSON format).")
                print(
                    f"Successfully exported {len(recommended_alert_infos)} recommended alerts to {ndjson_file_path} (Alertmanager NDJSON format).")
            except Exception as e:
                print(f"Failed to export recommended alerts: {e}")

        else:
            print("\n无推荐发送的告警")
            print("不推荐发送的原因（前5条）:")
            print("-" * 60)
            not_recommended_alerts = []
            for i, alert_info in enumerate(processed_alerts):
                decision = alert_info['decision']
                if not decision.get('should_alert', False):
                    not_recommended_alerts.append(i)
                    if len(not_recommended_alerts) <= 5:
                        alert = alert_info['alert']
                        rule = alert.get('rule', {})
                        print(f"[{i}] 描述: {rule.get('description', 'No description')}")
                        print(f"   规则ID: {rule.get('id', 'unknown')} | 级别: {rule.get('level', 0)}")
                        print(f"   理由: {decision.get('reason', 'No reason')}")
                        print("-" * 60)

            if len(not_recommended_alerts) > 5:
                print(f"... 还有 {len(not_recommended_alerts) - 5} 条不推荐发送的告警")
            print("=" * 80)

        # 让用户判断是否发送推荐的告警
        if recommended_alerts:
            print("\nAutogen 推荐发送以上告警到 Alertmanager。")
            user_input = input("是否发送推荐的告警？(y/n): ").strip().lower()
            if user_input == 'y':
                print("\n正在发送推荐的告警...")
                success_count = 0
                failure_count = 0
                for i in recommended_alerts:
                    alert_info = processed_alerts[i]
                    aggregated_alert = alert_info['alert']

                    # 构建发送到Alertmanager的告警信息
                    alert_to_send = {
                        'rule': aggregated_alert['rule'],
                        'agent': aggregated_alert['agent'],
                        'data': {},
                        'full_log': f"Aggregated alert: {aggregated_alert['count']} occurrences from {aggregated_alert['first_seen']} to {aggregated_alert['last_seen']}\nSample logs: {chr(10).join(aggregated_alert['sample_logs'][:2])}"
                    }

                    if push_to_alertmanager(alert_to_send):
                        print(f"[聚合告警 #{i}] 成功发送: {aggregated_alert['rule'].get('description', 'No description')}")
                        success_count += 1
                    else:
                        print(f"[聚合告警 #{i}] 发送失败: {aggregated_alert['rule'].get('description', 'No description')}")
                        failure_count += 1

                print(f"\n发送完成: 成功 {success_count} 条，失败 {failure_count} 条。")
            else:
                print("已取消发送推荐的告警。")

        # 进入交互式管理模式
        await interactive_mode(processed_alerts)
    except Exception as e:
        logging.error(f"程序执行出错: {e}")
        print(f"程序执行出错: {e}")

if __name__ == "__main__":
    asyncio.run(main())

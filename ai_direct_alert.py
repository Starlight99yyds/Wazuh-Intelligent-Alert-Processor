#!/usr/bin/env python3
"""
纯AI判断评估脚本：对每条告警单独进行AI判断，不进行聚合预处理
直接与 should.txt 中的 Ground Truth 进行比较
"""
import asyncio
import json
import logging
import os
import re
import sys
import yaml
from typing import Dict, List

import requests

# 配置日志
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# 限制第三方库的日志输出
for logger_name in ['autogen', 'openai', 'requests', 'urllib3']:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.ERROR)

# 加载配置
try:
    cfg = yaml.safe_load(open('config.yaml'))
except Exception as e:
    logging.error(f"Failed to load config.yaml: {e}")
    sys.exit(1)

# 决策理由最大长度
REASON_MAX_LENGTH = cfg.get('decision', {}).get('reason_max_length', 80)


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
                "source": "ai_direct_alert"
            },
            "annotations": annotations,
            "generatorURL": f"http://{cfg.get('server', {}).get('host', 'localhost')}:5601"
        }]

        timeout = cfg.get('output', {}).get('alertmanager_timeout', 3)

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





# 尝试导入 autogen
try:
    from autogen_agentchat.agents import AssistantAgent
    from autogen_ext.models.openai import OpenAIChatCompletionClient

    autogen_available = True
    logging.info("AutoGen enabled")

    def load_env_vars():
        env_vars = {}
        oai_config_path = os.path.join(os.path.dirname(__file__), "OAI_CONFIG_LIST")
        if os.path.exists(oai_config_path):
            try:
                with open(oai_config_path, 'r', encoding='utf-8') as f:
                    oai_config = json.load(f)
                if oai_config and isinstance(oai_config, list):
                    first_config = oai_config[0]
                    if 'api_key' in first_config:
                        env_vars['DEEPSEEK_API_KEY'] = first_config['api_key']
                        logging.info("Loaded API key from OAI_CONFIG_LIST file")
                        return env_vars
            except Exception as e:
                logging.warning(f"Error loading OAI_CONFIG_LIST: {e}")

        for key in ['DEEPSEEK_API_KEY']:
            if key in os.environ:
                env_vars[key] = os.environ[key]
                logging.info(f"Loading {key} from system environment variables")
                return env_vars

        return env_vars

    env_vars = load_env_vars()
    deepseek_api_key = env_vars.get("DEEPSEEK_API_KEY")

    if not deepseek_api_key:
        raise Exception("DEEPSEEK_API_KEY not found in environment variables")

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

    assistant = AssistantAgent(
        "assistant",
        model_client=model_client,
        system_message="你是一个安全告警分析师，负责判断 Wazuh 报警信息是否需要发送告警。请根据规则级别、敏感信息、安全事件类型等因素进行综合判断。若无法明确判断为严重安全事件，默认倾向于不发送告警（should_alert=false）。输出时：should_alert=false 则 severity 必须为 info；should_alert=true 则 severity 必须为 warning 或 critical；reason 控制在 30 字以内。\n\n重要要求：\n1. 所有回复必须使用纯文本格式，绝对不要使用markdown格式（如**加粗**、##标题、```代码块等）\n2. 回复内容必须是完整的中文，不要包含Unicode编码（如\\u53d1\\u9001）\n3. 分析结果要清晰、结构化，使用普通文本的列表和段落格式\n4. 直接输出分析内容，不要添加任何前缀或引言\n5. 确保回复内容易于阅读和理解"
    )

except Exception as e:
    logging.error(f"Failed to initialize autogen: {e}. Pure AI judgment requires AutoGen to be available.")
    autogen_available = False


async def process_single_alert_with_ai(alert: Dict) -> Dict:
    """使用AI处理单个告警（纯AI判断）"""
    if not autogen_available:
        # 纯AI模式下，如果autogen不可用，返回默认值
        logging.error("AutoGen not available, cannot perform pure AI judgment")
        return {"should_alert": False, "severity": "info", "reason": "AutoGen不可用"}
    
    try:
        # 直接使用完整的告警信息
        prompt = """
你是一个高级SOC安全分析专家。

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
""".format(json.dumps(alert, ensure_ascii=False, indent=2))

        result = await assistant.run(task=prompt)
        response = result.messages[-1].content

        # 提取 JSON 响应
        # 尝试多种方式提取JSON
        json_match = re.search(r'\{[\s\S]*?should_alert[\s\S]*?\}', response)
        if not json_match:
            # 尝试另一种模式
            json_match = re.search(r'\{[\s\S]*?\}', response)
        
        if json_match:
            try:
                decision = json.loads(json_match.group(0))
                # 构建返回结果
                return {
                    "should_alert": decision.get('should_alert', False),
                    "severity": decision.get('severity', 'info'),
                    "reason": decision.get('reason', 'AI判断')[:REASON_MAX_LENGTH]
                }
            except json.JSONDecodeError:
                logging.warning("Failed to decode JSON from AI response")
                return {"should_alert": False, "severity": "info", "reason": "AI响应格式错误"}
        else:
            logging.warning("Failed to extract JSON from AI response")
            return {"should_alert": False, "severity": "info", "reason": "AI响应格式错误"}
    except Exception as e:
        logging.error(f"Error processing with autogen: {e}")
        return {"should_alert": False, "severity": "info", "reason": f"处理错误: {str(e)[:20]}"}


def load_ground_truth(file_path: str = None) -> List[int]:
    """加载 Ground Truth
    
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
            # 兼容旧版本：使用默认路径
            file_path = 'data/should.txt'
    
    ground_truth = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    ground_truth.append(int(line))
        logging.warning(f"成功加载 Ground Truth: {file_path}，共 {len(ground_truth)} 条")
        return ground_truth
    except Exception as e:
        logging.error(f"加载 Ground Truth 失败: {e}")
        return []


def calculate_metrics(alerts: List[Dict], ground_truth: List[int], decisions: List[Dict]) -> Dict:
    """计算评价指标"""
    tp = fp = fn = tn = 0
    ai_sent_count = 0
    
    # 存储具体告警信息
    tp_alerts = []
    fp_alerts = []
    fn_alerts = []
    tn_alerts = []
    
    for i, gt in enumerate(ground_truth):
        if i >= len(alerts) or i >= len(decisions):
            break
        
        alert = alerts[i]
        decision = decisions[i]
        ai_sent = decision.get('should_alert', False)
        should_send_gt = gt == 1
        
        if ai_sent:
            ai_sent_count += 1
        
        # 构建告警信息字典
        alert_info = {
            'rule_id': alert.get('rule', {}).get('id', 'unknown'),
            'description': alert.get('rule', {}).get('description', 'No description'),
            'level': alert.get('rule', {}).get('level', 0),
            'timestamp': alert.get('timestamp', 'unknown'),
            'should_send_gt': should_send_gt,
            'ai_sent': ai_sent,
            'reason': decision.get('reason', '')
        }
        
        if should_send_gt and ai_sent:
            tp += 1
            tp_alerts.append(alert_info)
        elif not should_send_gt and ai_sent:
            fp += 1
            fp_alerts.append(alert_info)
        elif should_send_gt and not ai_sent:
            fn += 1
            fn_alerts.append(alert_info)
        else:
            tn += 1
            tn_alerts.append(alert_info)
    
    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    reduction = 1 - (ai_sent_count / total) if total > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    
    return {
        'tp': tp,
        'fp': fp,
        'fn': fn,
        'tn': tn,
        'total_original_alerts': total,
        'ai_sent_alerts': ai_sent_count,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'reduction_rate': reduction,
        'fnr': fnr,
        'tp_alerts': tp_alerts,
        'fp_alerts': fp_alerts,
        'fn_alerts': fn_alerts,
        'tn_alerts': tn_alerts
    }


def print_report(metrics: Dict):
    """打印评价指标报告"""
    print("\n" + "=" * 80)
    print("纯AI判断评价指标报告（无聚合预处理）")
    print("=" * 80)
    
    print("\n【基础统计】")
    print(f"  TP (该发送且AI发送):     {metrics['tp']}")
    print(f"  FP (不该发送但AI发送/误报): {metrics['fp']}")
    print(f"  FN (该发送但AI没发/漏报): {metrics['fn']}")
    print(f"  TN (不该发送且AI没发):     {metrics['tn']}")
    print(f"  原始告警总数: {metrics['total_original_alerts']}")
    print(f"  AI发送告警数: {metrics['ai_sent_alerts']}")
    
    # 打印具体告警信息
    if 'tp_alerts' in metrics and metrics['tp_alerts']:
        print("\n【TP 告警详情】")
        print("-" * 60)
        for i, alert in enumerate(metrics['tp_alerts']):
            print(f"[{i}] 规则ID: {alert['rule_id']} | 级别: {alert['level']}")
            print(f"   描述: {alert['description']}")
            print(f"   时间: {alert['timestamp']}")
            print(f"   理由: {alert['reason']}")
            print("-" * 60)
    
    if 'fp_alerts' in metrics and metrics['fp_alerts']:
        print("\n【FP 告警详情】")
        print("-" * 60)
        for i, alert in enumerate(metrics['fp_alerts']):
            print(f"[{i}] 规则ID: {alert['rule_id']} | 级别: {alert['level']}")
            print(f"   描述: {alert['description']}")
            print(f"   时间: {alert['timestamp']}")
            print(f"   理由: {alert['reason']}")
            print("-" * 60)
    
    if 'fn_alerts' in metrics and metrics['fn_alerts']:
        print("\n【FN 告警详情】")
        print("-" * 60)
        for i, alert in enumerate(metrics['fn_alerts']):
            print(f"[{i}] 规则ID: {alert['rule_id']} | 级别: {alert['level']}")
            print(f"   描述: {alert['description']}")
            print(f"   时间: {alert['timestamp']}")
            print(f"   理由: {alert['reason']}")
            print("-" * 60)
    
    if 'tn_alerts' in metrics and metrics['tn_alerts']:
        print("\n【TN 告警详情】")
        print("-" * 60)
        for i, alert in enumerate(metrics['tn_alerts']):
            print(f"[{i}] 规则ID: {alert['rule_id']} | 级别: {alert['level']}")
            print(f"   描述: {alert['description']}")
            print(f"   时间: {alert['timestamp']}")
            print(f"   理由: {alert['reason']}")
            print("-" * 60)
    
    print("\n【评价指标】")
    print(f"  精确率 (Precision):      {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
    print(f"    └─ 误报率控制能力: 高精确率表示AI较少产生误报")
    print(f"  召回率 (Recall):         {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
    print(f"    └─ 漏报率控制能力: 高召回率表示AI较少漏掉应发送的告警")
    print(f"  F1 Score:                {metrics['f1_score']:.4f}")
    print(f"    └─ 精确率和召回率的调和平均，综合评估模型性能")
    print(f"  告警减少率 (Reduction):  {metrics['reduction_rate']:.4f} ({metrics['reduction_rate']*100:.2f}%)")
    print(f"    └─ AI过滤掉的告警比例，越高表示降噪效果越好")
    print(f"  漏报率 (FNR):            {metrics['fnr']:.4f} ({metrics['fnr']*100:.2f}%)")
    print(f"    └─ 应发送但AI未发送的比例，越低越好")
    
    print("\n【指标说明】")
    print("  • 精确率公式: Precision = TP / (TP + FP)")
    print("  • 召回率公式: Recall = TP / (TP + FN)")
    print("  • F1 Score公式: F1 = 2 × (Precision × Recall) / (Precision + Recall)")
    print("  • 告警减少率公式: Reduction = 1 - (AI发送告警数 / 原始告警数)")
    print("  • 漏报率公式: FNR = FN / (TP + FN)")
    print("=" * 80)


async def main():
    """主函数"""
    # 获取文件路径
    file_pattern = cfg.get('local_files', {}).get('file_pattern', 'data/people.ndjson')
    
    # 加载告警
    alerts = []
    try:
        with open(file_pattern, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        alert = json.loads(line)
                        alerts.append(alert)
                    except json.JSONDecodeError:
                        continue
        logging.warning(f"成功加载告警文件: {file_pattern}，共 {len(alerts)} 条")
    except Exception as e:
        logging.error(f"加载告警文件失败: {e}")
        return
    
    # 加载 Ground Truth
    ground_truth = load_ground_truth()
    if not ground_truth:
        return
    
    if len(ground_truth) != len(alerts):
        logging.warning(f"Ground Truth 行数 ({len(ground_truth)}) 与告警数 ({len(alerts)}) 不匹配")
        min_len = min(len(ground_truth), len(alerts))
        ground_truth = ground_truth[:min_len]
        alerts = alerts[:min_len]
    
    print(f"\n开始对 {len(alerts)} 条告警进行纯AI判断（无聚合预处理）...")
    
    # 对每条告警进行AI判断
    decisions = []
    sent_alert_count = 0
    for i, alert in enumerate(alerts):
        decision = await process_single_alert_with_ai(alert)
        decisions.append(decision)
        
        # 如果AI判断需要发送告警，则推送到Alertmanager
        if decision.get('should_alert', False):
            success = push_to_alertmanager(alert)
            if success:
                sent_alert_count += 1
                logging.warning(f"已发送告警 {i + 1}/{len(alerts)}")
        
        if (i + 1) % 10 == 0 or i == len(alerts) - 1:
            logging.warning(f"已处理 {i + 1}/{len(alerts)} 条告警")
    
    print(f"\nAI判断完成，共处理 {len(decisions)} 条告警")
    print(f"已成功发送 {sent_alert_count} 条告警到Alertmanager")
    
    # 计算并显示评价指标
    metrics = calculate_metrics(alerts, ground_truth, decisions)
    print_report(metrics)
    
    # 导出详细结果
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 导出评价指标
    metrics_file = os.path.join(output_dir, f"pure_ai_metrics_{timestamp}.json")
    with open(metrics_file, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)
    
    # 导出详细判断结果
    detailed_results = []
    for i, (alert, decision) in enumerate(zip(alerts, decisions)):
        if i >= len(ground_truth):
            break
        detailed_results.append({
            'index': i,
            'ground_truth': ground_truth[i],
            'ai_decision': 1 if decision.get('should_alert', False) else 0,
            'severity': decision.get('severity', 'info'),
            'reason': decision.get('reason', ''),
            'rule_id': alert.get('rule', {}).get('id', 'unknown'),
            'rule_description': alert.get('rule', {}).get('description', 'No description'),
            'rule_level': alert.get('rule', {}).get('level', 0)
        })
    
    details_file = os.path.join(output_dir, f"pure_ai_detailed_results_{timestamp}.json")
    with open(details_file, 'w', encoding='utf-8') as f:
        json.dump(detailed_results, f, ensure_ascii=False, indent=2)
    
    print(f"\n评价指标已导出到: {metrics_file}")
    print(f"详细结果已导出到: {details_file}")


if __name__ == "__main__":
    asyncio.run(main())

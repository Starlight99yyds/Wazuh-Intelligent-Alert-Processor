#!/usr/bin/env python3
"""
直接发送所有告警到 Alertmanager
不进行AI判断，作为基线测试
"""
import json
import logging
import os
import sys
import yaml
from typing import Dict, List

import requests

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# 加载配置
try:
    cfg = yaml.safe_load(open('config.yaml'))
except Exception as e:
    logging.error(f"Failed to load config.yaml: {e}")
    sys.exit(1)


def get_alertmanager_api_url():
    """获取 Alertmanager API 地址"""
    am_url = cfg.get('output', {}).get('alertmanager_url')
    if not am_url:
        return "http://localhost:9093/api/v2/alerts"
    
    if '#/alerts' in am_url:
        base = am_url.split('#', 1)[0].rstrip('/')
        return f"{base}/api/v2/alerts"
    
    if "/api/v1/alerts" in am_url:
        return am_url.replace("/api/v1/alerts", "/api/v2/alerts")
    
    return am_url


def push_to_alertmanager(alert: Dict) -> bool:
    """将告警发送到 Alertmanager"""
    am_url = get_alertmanager_api_url()
    if not am_url:
        return False

    try:
        rule = alert.get('rule', {})
        agent = alert.get('agent', {})
        data_content = alert.get('data', {})

        rule_id = rule.get('id', 'unknown')
        rule_level = rule.get('level', 0)
        rule_desc = rule.get('description', 'No description')

        if rule_level >= 12:
            severity = 'critical'
        elif rule_level >= 7:
            severity = 'warning'
        else:
            severity = 'info'

        annotations = {
            "summary": rule_desc,
            "description": f"Agent: {agent.get('id')} - {agent.get('name')}\n"
                           f"Groups: {','.join(rule.get('groups', []))}\n"
                           f"Full Log: {alert.get('full_log', 'N/A')}"
        }

        # 递归扁平化处理 data_content
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
            for k, v in flat_data.items():
                if len(v) < 1024:
                    annotations[k] = v

        payload = [{
            "labels": {
                "alertname": f"Wazuh Rule {rule_id}",
                "severity": severity,
                "wazuh_rule_id": str(rule_id),
                "wazuh_level": str(rule_level),
                "agent_name": agent.get('name', 'unknown'),
                "source": "send_all_alerts"
            },
            "annotations": annotations,
            "generatorURL": f"http://{cfg['server']['host']}:5601"
        }]

        timeout = cfg['output'].get('alertmanager_timeout', 3)

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
        logging.info(f"成功加载 Ground Truth: {file_path}，共 {len(ground_truth)} 条")
        return ground_truth
    except Exception as e:
        logging.error(f"加载 Ground Truth 失败: {e}")
        return []


def calculate_metrics(alerts: List[Dict], ground_truth: List[int], sent_count: int) -> Dict:
    """
    计算评价指标
    
    基线策略：所有告警都发送到 Alertmanager
    - TP: Ground Truth=1 且 已发送
    - FP: Ground Truth=0 但 已发送
    - FN: Ground Truth=1 但 未发送（基线策略下应为0）
    - TN: Ground Truth=0 且 未发送（基线策略下应为0）
    """
    tp = fp = fn = tn = 0
    
    for i, gt in enumerate(ground_truth):
        if i >= len(alerts):
            break
        
        # 基线策略：所有告警都发送
        ai_sent = True
        should_send_gt = gt == 1
        
        if should_send_gt and ai_sent:
            tp += 1
        elif not should_send_gt and ai_sent:
            fp += 1
        elif should_send_gt and not ai_sent:
            fn += 1
        else:
            tn += 1
    
    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    reduction = 1 - (sent_count / total) if total > 0 else 0.0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
    
    return {
        'tp': tp,
        'fp': fp,
        'fn': fn,
        'tn': tn,
        'total_original_alerts': total,
        'sent_alerts': sent_count,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'reduction_rate': reduction,
        'fnr': fnr
    }


def print_report(metrics: Dict):
    """打印评价指标报告"""
    print("\n" + "=" * 80)
    print("基线测试评价指标报告（直接发送所有告警到 Alertmanager）")
    print("=" * 80)
    
    print("\n【基础统计】")
    print(f"  TP (该发送且已发送):     {metrics['tp']}")
    print(f"  FP (不该发送但已发送/误报): {metrics['fp']}")
    print(f"  FN (该发送但未发送/漏报): {metrics['fn']}")
    print(f"  TN (不该发送且未发送):     {metrics['tn']}")
    print(f"  原始告警总数: {metrics['total_original_alerts']}")
    print(f"  成功发送告警数: {metrics['sent_alerts']}")
    
    print("\n【评价指标】")
    print(f"  精确率 (Precision):      {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
    print(f"    └─ 误报率控制能力")
    print(f"  召回率 (Recall):         {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
    print(f"    └─ 漏报率控制能力")
    print(f"  F1 Score:                {metrics['f1_score']:.4f}")
    print(f"    └─ 精确率和召回率的调和平均")
    print(f"  告警减少率 (Reduction):  {metrics['reduction_rate']:.4f} ({metrics['reduction_rate']*100:.2f}%)")
    print(f"    └─ 过滤掉的告警比例")
    print(f"  漏报率 (FNR):            {metrics['fnr']:.4f} ({metrics['fnr']*100:.2f}%)")
    print(f"    └─ 应发送但未发送的比例")
    
    print("\n【指标说明】")
    print("  • 精确率公式: Precision = TP / (TP + FP)")
    print("  • 召回率公式: Recall = TP / (TP + FN)")
    print("  • F1 Score公式: F1 = 2 × (Precision × Recall) / (Precision + Recall)")
    print("  • 告警减少率公式: Reduction = 1 - (发送告警数 / 原始告警数)")
    print("  • 漏报率公式: FNR = FN / (TP + FN)")
    print("=" * 80)


def main():
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
        logging.info(f"成功加载告警文件: {file_pattern}，共 {len(alerts)} 条")
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
    
    # 发送所有告警到 Alertmanager
    print("\n开始发送告警到 Alertmanager...")
    success_count = 0
    failure_count = 0
    
    for i, alert in enumerate(alerts):
        if push_to_alertmanager(alert):
            success_count += 1
            logging.info(f"[{i+1}/{len(alerts)}] 发送成功")
        else:
            failure_count += 1
            logging.warning(f"[{i+1}/{len(alerts)}] 发送失败")
    
    print(f"\n发送完成: 成功 {success_count} 条，失败 {failure_count} 条")
    
    # 计算并显示评价指标
    metrics = calculate_metrics(alerts, ground_truth, success_count)
    print_report(metrics)
    
    # 导出结果到文件
    output_dir = "output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    import datetime
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = os.path.join(output_dir, f"baseline_metrics_{timestamp}.json")
    
    with open(result_file, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)
    
    print(f"\n评价指标已导出到: {result_file}")


if __name__ == "__main__":
    main()

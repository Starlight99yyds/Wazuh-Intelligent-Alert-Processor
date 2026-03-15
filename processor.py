#!/usr/bin/env python3
"""
TCP Client version of logprocessor (Enhanced with Alertmanager & Proxy Fix)
修复内容：
1. 禁用 requests 的自动代理 (解决 SOCKSHTTPConnectionPool 报错)
2. 修复推送失败仍然计数的 Bug
"""
import os, sys, json, yaml, logging, datetime, pathlib, re, socket
import xml.etree.ElementTree as ET
from elasticsearch import Elasticsearch
import requests

# 设置日志格式
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

# 加载配置
try:
    cfg = yaml.safe_load(open('config.yaml'))
except Exception as e:
    logging.error(f"Failed to load config.yaml: {e}")
    sys.exit(1)

def out_file():
    """生成输出文件名"""
    idx = cfg['es_source']['index'].replace('*', 'ALL').replace(':', '-').replace(',', '-').replace(' ', '')
    gte = datetime.datetime.fromisoformat(cfg['time_range']['gte']).strftime('%Y%m%d_%H%M%S')
    lte = datetime.datetime.fromisoformat(cfg['time_range']['lte']).strftime('%Y%m%d_%H%M%S')
    
    mode_suffix = "alerts" if cfg['output'].get('only_alerts', False) else "full"
    
    pathlib.Path(cfg['output']['dir']).mkdir(exist_ok=True, parents=True)
    return pathlib.Path(cfg['output']['dir']) / f"{idx}_{gte}-{lte}_{mode_suffix}.ndjson"

def ensure_newline(raw: str) -> str:
    """清洗普通字符串日志"""
    if not isinstance(raw, str): return ''
    raw = re.sub(r'[\x00-\x08\x0b-\x1f]', '', raw) 
    raw = raw.replace('\r\n', '\n').rstrip('\n')
    if not raw: return ''
    return raw + '\n'

def parse_windows_xml(xml_string):
    """Windows XML 转 JSON (保留 severityValue 逻辑)"""
    try:
        xml_string = xml_string.strip()
        if not xml_string.startswith('<'): return None
        
        root = ET.fromstring(xml_string)
        
        def get_clean_tag(tag):
            return tag.split('}')[-1] if '}' in tag else tag

        wazuh_event = { "win": { "system": {}, "eventdata": {} } }
        
        for child in root:
            tag_name = get_clean_tag(child.tag)
            
            if tag_name == 'System':
                for item in child:
                    key = get_clean_tag(item.tag)
                    json_key = key[0].lower() + key[1:] if key else key
                    
                    if item.text:
                        wazuh_event['win']['system'][json_key] = item.text
                    
                    if item.attrib:
                        for attr_name, attr_val in item.attrib.items():
                            if key == 'TimeCreated' and attr_name == 'SystemTime':
                                wazuh_event['win']['system']['systemTime'] = attr_val
                            elif key == 'Provider' and attr_name == 'Name':
                                wazuh_event['win']['system']['providerName'] = attr_val
                            elif key == 'Provider' and attr_name == 'Guid':
                                wazuh_event['win']['system']['providerGuid'] = attr_val
                            else:
                                k = attr_name[0].lower() + attr_name[1:]
                                wazuh_event['win']['system'][k] = attr_val

            elif tag_name == 'EventData':
                for item in child:
                    if 'Name' in item.attrib:
                        wazuh_event['win']['eventdata'][item.attrib['Name']] = item.text
                    elif item.text and not item.attrib:
                         wazuh_event['win']['eventdata']['Data'] = item.text

            elif tag_name == 'UserData':
                for user_item in child:
                    for sub_item in user_item:
                        sub_tag = get_clean_tag(sub_item.tag)
                        if sub_item.text:
                            wazuh_event['win']['eventdata'][sub_tag] = sub_item.text
        
        sys_obj = wazuh_event['win']['system']
        kw = sys_obj.get('keywords', '')
        lvl = sys_obj.get('level', '')
        channel = sys_obj.get('channel', '').lower()

        if 'security' in channel or kw.startswith('0x8020') or kw.startswith('0x8010'):
            if kw.startswith('0x8020'): sys_obj['severityValue'] = 'AUDIT_SUCCESS'
            elif kw.startswith('0x8010'): sys_obj['severityValue'] = 'AUDIT_FAILURE'
        else:
            LVL_MAP = {"1":"CRITICAL", "2":"ERROR", "3":"WARNING", "4":"INFORMATION", "5":"VERBOSE"}
            if lvl in LVL_MAP:
                sys_obj['severityValue'] = LVL_MAP[lvl]

        if not sys_obj.get('eventID'): return None
        return wazuh_event

    except Exception:
        return None

def push_to_alertmanager(wazuh_output):
    """
    将 Wazuh 结果转换为 Alertmanager 格式并推送
    Returns: True if success, False if failed
    """
    am_url = cfg['output'].get('alertmanager_url')
    if not am_url: return False

    try:
        rule = wazuh_output.get('rule', {})
        agent = wazuh_output.get('agent', {})
        data_content = wazuh_output.get('data', {})
        
        rule_id = rule.get('id', 'unknown')
        rule_level = rule.get('level', 0)
        rule_desc = rule.get('description', 'No description')
        
        if rule_level >= 12: severity = 'critical'
        elif rule_level >= 7: severity = 'warning'
        else: severity = 'info'

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
                "source": "wazuh_logprocessor"
            },
            "annotations": annotations,
            "generatorURL": f"http://{cfg['server']['host']}:5601"
        }]

        timeout = cfg['output'].get('alertmanager_timeout', 3)
        
        # === [核心修复 1] 强制不使用代理 ===
        # 使用空的 proxies 字典，告诉 requests 不要查找环境变量中的 http_proxy/all_proxy
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

def scroll_source():
    """从 ES 滚动读取数据"""
    es = Elasticsearch(cfg['es_source']['hosts'])
    body = {
        "query": {
            "bool": {
                "must": [{"range": {"@timestamp": cfg['time_range']}}]
            }
        },
        "_source": True,
        "sort": ["@timestamp"],
        "size": cfg['es_source']['batch_size']
    }
    
    try:
        resp = es.search(index=cfg['es_source']['index'], body=body, scroll=cfg['es_source']['scroll_ttl'])
    except Exception as e:
        logging.error(f"ES Connection Failed: {e}")
        return

    sid = resp['_scroll_id']
    total = resp['hits']['total']
    fetched = 0
    
    logging.info(f"Start scrolling ES. Total hits: {total}")

    while True:
        hits = resp['hits']['hits']
        if not hits: break
        fetched += len(hits)
        
        docs = [h['_source'] for h in hits if h.get('_source')]
        yield docs

        logging.info('ES scroll: %d / %d  (%.1f%%)', fetched, total, fetched*100.0/total)
        
        try:
            resp = es.scroll(scroll_id=sid, scroll=cfg['es_source']['scroll_ttl'])
            sid = resp['_scroll_id']
        except Exception as e:
            logging.warning(f"ES Scroll Error: {e}, stopping early.")
            break

def main():
    out_cfg = cfg['output']
    enable_file = out_cfg.get('save_to_file', True)
    enable_am = out_cfg.get('send_to_alertmanager', False)
    
    if not enable_am and not enable_file:
        logging.warning("配置警告: 'send_to_alertmanager' 为 false。强制开启本地落盘 (save_to_file=True) 以防止数据丢失。")
        enable_file = True

    fout = None
    if enable_file:
        output_path = out_file()
        logging.info(f"Local file logging enabled: {output_path}")
        fout = open(output_path, 'w', buffering=1, encoding='utf-8')
    else:
        logging.info("Local file logging disabled.")

    if enable_am:
        logging.info(f"Alertmanager push enabled: {out_cfg.get('alertmanager_url')}")

    server_host = cfg['server']['host']
    server_port = cfg['server']['port']
    only_alerts = out_cfg.get('only_alerts', False)
    
    do_convert_xml = cfg.get('transform', {}).get('convert_windows_xml', False)
    msg_field_name = cfg['es_source']['message_field'] 

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        logging.info(f"Connecting to {server_host}:{server_port}...")
        sock.connect((server_host, server_port))
    except Exception as e:
        logging.error(f"Connection Failed: {e}")
        if fout: fout.close()
        return

    sock_file = sock.makefile('r', buffering=1, encoding='utf-8')

    count = 0
    saved_count = 0 
    pushed_count = 0 
    
    try:
        for batch in scroll_source():
            if not batch: continue
            
            for es_doc in batch:
                msg_to_send = ""
                raw_content = es_doc.get(msg_field_name)

                if raw_content and isinstance(raw_content, str) and raw_content.strip():
                    converted = False
                    if do_convert_xml:
                        stripped_msg = raw_content.strip()
                        if stripped_msg.startswith('<Event') and stripped_msg.endswith('>'):
                            json_obj = parse_windows_xml(stripped_msg)
                            if json_obj:
                                msg_to_send = json.dumps(json_obj, ensure_ascii=False) + '\n'
                                converted = True
                    if not converted:
                        msg_to_send = ensure_newline(raw_content)
                else:
                    msg_to_send = json.dumps(es_doc, ensure_ascii=False) + '\n'

                try:
                    if not msg_to_send.strip(): continue

                    sock.sendall(msg_to_send.encode('utf-8'))
                    
                    resp_line = sock_file.readline()
                    if not resp_line: break
                    
                    raw_resp = json.loads(resp_line)
                    is_alert = raw_resp.get('alert') is True
                    
                    if only_alerts and not is_alert:
                        count += 1
                        continue 

                    final_obj = raw_resp.get('output', {})
                    
                    if enable_file and fout:
                        fout.write(json.dumps(final_obj, ensure_ascii=False) + '\n')
                        saved_count += 1

                    if enable_am and is_alert:
                        # === [核心修复 2] 只有返回 True 时才计数 ===
                        if push_to_alertmanager(final_obj):
                            pushed_count += 1
                    
                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    logging.error(f"Process Error: {e}")
                
                count += 1
                if count % 2000 == 0:
                    logging.info(f"Processed: {count}, Saved: {saved_count}, PushedToAM: {pushed_count}")
                    
    except KeyboardInterrupt:
        logging.info("Interrupted.")
    finally:
        sock.close()
        if fout: fout.close()
        logging.info(f"Finished. Total: {count}, Saved: {saved_count}, PushedToAM: {pushed_count}")

if __name__ == '__main__':
    main()


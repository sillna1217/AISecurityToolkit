
from flask import Flask, render_template, request,redirect,session
from collections import Counter
BLACKLIST_IPS = {
    "192.168.1.100",
    "10.0.0.66",
}
import ipaddress


def add_blacklist_ip(ip):
    ip = ip.strip()

    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        return False

    BLACKLIST_IPS.add(ip)
    return True
from datetime import datetime, timedelta


def detect_repeated_failures(logs, window_seconds=60, threshold=3):
    """检测同一 IP 在指定时间窗口内连续登录失败的行为。"""
    events = []

    for line in logs.splitlines():
        parts = line.split()

        if len(parts) < 4 or "LOGIN_FAILED" not in line:
            continue

        try:
            event_time = datetime.strptime(
                parts[0] + " " + parts[1],
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            continue

        ip = None
        for part in parts[2:]:
            if part.startswith("ip="):
                ip = part[3:]
                break

        if ip:
            events.append((event_time, ip))

    events.sort()

    alerts = []
    ip_events = {}

    for event_time, ip in events:
        ip_events.setdefault(ip, [])
        ip_events[ip] = [
            t for t in ip_events[ip]
            if (event_time - t).total_seconds() <= window_seconds
        ]
        ip_events[ip].append(event_time)

        if len(ip_events[ip]) == threshold:
            alerts.append({
                "ip": ip,
                "count": threshold,
                "window_seconds": window_seconds,
                "time": event_time.strftime("%Y-%m-%d %H:%M:%S")
            })

    return alerts

app = Flask(__name__)
app.secret_key="请替换成你自己的随机密钥"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


@app.route("/")
def home():
    return render_template("index.html")
@app.route("/add_blacklist", methods=["POST"])
def add_blacklist():
    ip = request.form.get("ip", "").strip()

    if add_blacklist_ip(ip):
        message = f"成功添加黑名单 IP：{ip}"
    else:
        message = "IP 地址格式无效，请重新输入。"

    return f"""
    <h2>IP 黑名单管理</h2>
    <p>{message}</p>
    <p>当前黑名单：{', '.join(sorted(BLACKLIST_IPS))}</p>
    <a href="/">返回首页</a>
    """



@app.route("/download_report")
def download_report():
    from flask import Response

    report_text = session.get("report_text")

    if not report_text:
        return redirect("/analyze")

    response = Response(
        report_text.encode("utf-8-sig"),
        content_type="text/plain; charset=utf-8"
    )
    response.headers["Content-Disposition"] = (
        'attachment; filename="AISecurityToolkit_report.txt"'
    )
    return response




@app.route("/analyze", methods=["GET", "POST"])
def analyze():

    if request.method == "GET":
        return """
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>登录日志分析</title>
            <style>
                * {
                    box-sizing: border-box;
                }

                body {
                    margin: 0;
                    padding: 40px 20px;
                    font-family: "Microsoft YaHei", Arial, sans-serif;
                    background: #f3f6fb;
                    color: #1e293b;
                }

                .card {
                    max-width: 760px;
                    margin: 40px auto;
                    padding: 32px;
                    background: white;
                    border: 1px solid #e2e8f0;
                    border-radius: 16px;
                    box-shadow: 0 8px 24px rgba(16, 35, 63, 0.06);
                }

                h1 {
                    margin-top: 0;
                    color: #10233f;
                    font-size: 30px;
                }

                p {
                    line-height: 1.8;
                    color: #64748b;
                }

                textarea {
                    width: 100%;
                    min-height: 220px;
                    padding: 14px;
                    border: 1px solid #cbd5e1;
                    border-radius: 10px;
                    font-family: Consolas, monospace;
                    font-size: 14px;
                    resize: vertical;
                }

                textarea:focus {
                    outline: none;
                    border-color: #2563eb;
                    box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
                }

                button {
                    margin-top: 18px;
                    padding: 12px 24px;
                    border: none;
                    border-radius: 8px;
                    background: #2563eb;
                    color: white;
                    font-size: 16px;
                    cursor: pointer;
                }

                button:hover {
                    background: #1d4ed8;
                }

                a {
                    display: inline-block;
                    margin-top: 20px;
                    color: #2563eb;
                    text-decoration: none;
                }

                a:hover {
                    text-decoration: underline;
                }
            </style>
        </head>
        <body>
            <div class="card">
                <h1>登录日志分析器</h1>
                <p>粘贴登录日志，统计登录成功与失败次数，并识别可疑 IP。</p>

                <form action="/analyze" method="POST" enctype="multipart/form-data">
    <textarea name="logs" rows="10"
        placeholder="在这里粘贴日志，每行一条记录..."></textarea>

    <p>或者直接上传日志文件（.log / .txt）：</p>
    <input type="file" name="log_file" accept=".log,.txt,text/plain">

    <br>
    <button type="submit">分析日志 →</button>
</form>

                <a href="/">← 返回首页</a>
            </div>
        </body>
        </html>
        """


    logs = request.form.get("logs", "")
    file = request.files.get("log_file")

    if file and file.filename:
        logs = file.read().decode("utf-8", errors="replace")
    success_count = 0
    failed_count = 0
    failed_ips = Counter()
    blacklist_hits = set()

    for line in logs.splitlines():
        parts = line.split()

        if len(parts) < 2:
            continue

        if "LOGIN_SUCCESS" in line:
            success_count += 1

        elif "LOGIN_FAILED" in line:
            failed_count += 1

            for part in parts:
                if part.startswith("ip="):
                    ip = part[3:]
                    failed_ips[ip] += 1

                    if ip in BLACKLIST_IPS:
                        blacklist_hits.add(ip)

                elif part.count(".") == 3 and part[0].isdigit():
                    failed_ips[part] += 1

                    if part in BLACKLIST_IPS:
                        blacklist_hits.add(part)

    suspicious_ips = {
        ip: count
        for ip, count in failed_ips.items()
        if count >= 3
    }
    time_alerts = detect_repeated_failures(logs)
    if blacklist_hits:
        blacklist_message = "发现黑名单 IP：" + "、".join(sorted(blacklist_hits))
    else:
        blacklist_message = "未发现黑名单 IP"

    if any(count >= 10 for count in failed_ips.values()):
        risk_level = "高风险"
        risk_message = "发现某个 IP 登录失败达到 10 次或以上，请重点检查。"
    elif time_alerts:
        risk_level = "高风险"
        risk_message = "检测到同一 IP 在 60 秒内登录失败达到 3 次，请重点检查。"
    elif suspicious_ips:
        risk_level = "中风险"
        risk_message = "发现某个 IP 登录失败达到 3 次或以上，建议进一步检查。"
    else:
        risk_level = "低风险"
        risk_message = "暂未发现达到告警阈值的异常登录。"

    if time_alerts:
        time_alert_text = "\n".join(
            f"异常 IP：{alert['ip']}，失败次数：{alert['count']} 次，检测时间：{alert['time']}"
            for alert in time_alerts
        )
    else:
        time_alert_text = "未发现短时间连续登录失败告警"

    report_text = f"""AISecurityToolkit - 日志分析报告
    ========================================
    登录成功次数：{success_count}
    登录失败次数：{failed_count}

    安全风险等级：{risk_level}
    风险说明：{risk_message}
    
    
    时间窗口检测告警：
    {time_alert_text}
    IP 黑名单检测：
    {blacklist_message}



    各 IP 登录失败次数：
    """

    for ip, count in sorted(
            failed_ips.items(),
            key=lambda item: item[1],
            reverse=True
    ):
        if count >= 10:
            ip_risk = "高风险"
        elif count >= 3:
            ip_risk = "中风险"
        else:
            ip_risk = "低风险"

        report_text += f"{ip}：{count} 次（{ip_risk}）\n"

    if not failed_ips:
        report_text += "没有发现登录失败记录\n"
    session["report_text"] = report_text
    result_html = f"""
    
<div class="chart-card">
    <h2>短时间连续失败检测</h2>
    {''.join(
        f'<p style="color: #b91c1c; font-weight: bold;">'
        f'异常 IP：{alert["ip"]}，'
        f'失败次数：{alert["count"]} 次，'
        f'检测时间：{alert["time"]}</p>'
        for alert in time_alerts
    ) or '<p style="color: #15803d;">暂未发现短时间连续失败行为</p>'}
</div>
<div class="chart-card">
    <h2>IP 黑名单检测</h2>
    <p style="color: #b91c1c; font-weight: bold;">
        {blacklist_message}
    </p>
</div>

    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>分析结果</title>
        <style>
            
* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    font-family: "Microsoft YaHei", Arial, sans-serif;
    background: #f3f6fb;
    color: #1e293b;
    padding: 40px 20px;
}}

.card {{
    max-width: 760px;
    margin: auto;
    padding: 32px;
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 16px;
    box-shadow: 0 8px 24px #10233f0a;
}}

h1 {{
    color: #10233f;
}}

h2 {{
    margin-top: 28px;
    color: #1d4ed8;
}}

.number {{
    font-size: 26px;
    font-weight: bold;
    color: #2563eb;
}}

li {{
    margin: 12px 0;
    line-height: 1.6;
}}

a {{
    color: #2563eb;
    text-decoration: none;
}}

a:hover {{
    text-decoration: underline;
}}

.risk-panel {{
    margin-top: 24px;
    padding: 20px;
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-radius: 12px;
}}

.risk-level {{
    font-size: 24px;
    font-weight: bold;
    color: #2563eb;
}}

.risk-panel.低风险 {{
    background: #f0fdf4;
    border-color: #86efac;
}}

.risk-panel.低风险 .risk-level {{
    color: #15803d;
}}

.risk-panel.中风险 {{
    background: #fffbeb;
    border-color: #fcd34d;
}}

.risk-panel.中风险 .risk-level {{
    color: #b45309;
}}

.risk-panel.高风险 {{
    background: #fef2f2;
    border-color: #fca5a5;
}}

.risk-panel.高风险 .risk-level {{
    color: #b91c1c;
}}

.stats {{
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
    margin: 24px 0;
}}

.stat-card {{
    padding: 20px;
    border-radius: 12px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
}}

.stat-card p {{
    margin: 0 0 10px;
    color: #64748b;
}}

.stat-number {{
    font-size: 28px;
    font-weight: bold;
}}

.success-card .stat-number {{ color: #15803d; }}
.failed-card .stat-number {{ color: #b91c1c; }}
.ip-card .stat-number {{ color: #b45309; }}

@media (max-width: 600px) {{
    .stats {{ grid-template-columns: 1fr; }}
}}

.chart-card {{
    margin: 24px 0;
    padding: 24px;
    border-radius: 14px;
    background: #ffffff;
    border: 1px solid #e2e8f0;
}}

.chart-card h2 {{
    margin-top: 0;
    color: #0f172a;
}}

.chart-card p {{
    margin-bottom: 8px;
    color: #475569;
}}

.bar-bg {{
    width: 100%;
    height: 18px;
    background: #e2e8f0;
    border-radius: 999px;
    overflow: hidden;
    margin-bottom: 18px;
}}

.bar-success {{
    height: 100%;
    background: #16a34a;
    border-radius: 999px;
    transition: width 0.5s ease;
}}

.bar-failed {{
    height: 100%;
    background: #dc2626;
    border-radius: 999px;
    transition: width 0.5s ease;
}}

.chart-note {{
    font-size: 14px;
    color: #64748b;
}}





        </style>
    </head>
    <body>
        <div class="card">
            <h1>日志分析结果</h1>
        
<div style="margin: 20px 0;">
    <a href="/download_report"
       style="display: inline-block;
              padding: 12px 20px;
              background: #2563eb;
              color: white;
              text-decoration: none;
              border-radius: 8px;
              font-weight: bold;">
        下载 TXT 报告
    </a>
</div>

            
        <div class="stats">
    <div class="stat-card success-card">
        <p>登录成功</p>
        <div class="stat-number">{success_count}</div>
    </div>
    <div class="stat-card failed-card">
        <p>登录失败</p>
        <div class="stat-number">{failed_count}</div>
    </div>
    <div class="stat-card ip-card">
        <p>可疑 IP</p>
        <div class="stat-number">{len(suspicious_ips)}</div>
    </div>
</div>

            
            <div class="risk-panel {risk_level}">
                <h2>安全风险评估</h2>
                <p class="risk-level">{risk_level}</p>
                <p>{risk_message}</p>
            </div>
            
<div class="chart-card">
    <h2>登录情况可视化</h2>

    <p>登录成功</p>
    <div class="bar-bg">
        <div class="bar-success"
             style="width: {success_count / max(success_count + failed_count, 1) * 100:.1f}%;">
        </div>
    </div>

    <p>登录失败</p>
    <div class="bar-bg">
        <div class="bar-failed"
             style="width: {failed_count / max(success_count + failed_count, 1) * 100:.1f}%;">
        </div>
    </div>

    <p class="chart-note">
        成功 {success_count} 次，失败 {failed_count} 次
    </p>
</div>

            <h2>各 IP 登录失败次数</h2>
            <ul>
                
                {''.join(f'<li>{ip}：{count} 次 — <span class="ip-risk" style="color: {"#b91c1c" if count >= 10 else "#b45309" if count >= 3 else "#15803d"}; font-weight: bold;">{"高风险" if count >= 10 else "中风险" if count >= 3 else "低风险"}</span></li>' for ip, count in sorted(failed_ips.items(), key=lambda item: item[1], reverse=True)) or "<li>没有发现登录失败记录</li>"}

            </ul>
            <h2>风险提示</h2>
            <ul>
                {''.join(f"<li>需要关注：{ip}，失败 {count} 次</li>" for ip, count in suspicious_ips.items()) or "<li>暂未发现达到阈值的 IP（单个 IP 失败至少 3 次）</li>"}
            </ul>
            <a href="/analyze">继续分析</a> |
            <a href="/">返回首页</a>
        </div>
    </body>
    </html>
    """
    return result_html
@app.errorhandler(413)
def file_too_large(error):
    return """
    <h1>文件太大了</h1>
    <p>请上传小于 5 MB 的日志文件。</p>
    <p><a href="/analyze">返回日志分析</a></p>
    """, 413


def test_time_detection():
    with open("test_time.log", "r", encoding="utf-8") as f:
        logs = f.read()

    alerts = detect_repeated_failures(logs)

    print("\n===== 时间窗口检测测试 =====")
    if alerts:
        for alert in alerts:
            print(
                f"异常 IP：{alert['ip']}，"
                f"失败次数：{alert['count']}，"
                f"检测时间：{alert['time']}"
            )
    else:
        print("没有检测到异常登录")



if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

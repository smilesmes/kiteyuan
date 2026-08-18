#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
纸鸢网盘 (mybt.kiteyuan.info) 每日积分任务自动领取

流程:
  1. 通过站点 /api/auth/casdoor/login 取得带 state 的 Casdoor 授权地址
  2. Casdoor 密码登录 (/api/login?service=<授权query>)
  3. 跟随授权回调, 从最终 URL 的 ?token= 取出站点 JWT
  4. GET /api/auth/me 获取 sign_secret (HMAC 签名密钥)
  5. 依次 POST 三个积分任务 (新用户礼包 / 每日签到 / 使用纸鸢磁力)
  6. 汇总结果推送 Telegram

签名算法 (逆向自前端 index-*.js):
  msg  = METHOD + "\n" + "/api" + path + "\n" + canonical_query + "\n" +
         sha256_hex(body) + "\n" + timestamp
  X-Sign      = hmac_sha256_hex(msg, sign_secret)
  X-Timestamp = unix 秒
canonical_query: 按 key 排序后用 & 连接的原始 key=value(不重新编码)

环境变量:
  KITEYUAN_EMAIL     必填, Casdoor 邮箱
  KITEYUAN_PASSWORD  必填, Casdoor 密码
  TG_BOT_TOKEN       选填, Telegram Bot Token
  TG_CHAT_ID         选填, Telegram Chat ID
  KITEYUAN_ACCOUNTS  选填, 多账号 JSON: [{"email":"..","password":"..","name":".."}]
  START_DELAY_MAX    选填, 启动随机延时上限(秒), 默认 1800, 设 0 关闭
  SKIP_START_DELAY   选填, 置 1/true 跳过启动延时(手动触发时用)
"""

import hashlib
import hmac
import json
import os
import random
import re
import sys
import time
from urllib.parse import quote, urlsplit

import requests

# curl_cffi 模拟浏览器 TLS/HTTP2 指纹，主要用于规避 GitHub Actions 机房 IP 的 CF 403。
# 保留 requests 回退，以便依赖安装异常时脚本仍能给出可读错误或在无 CF 拦截环境运行。
try:
    from curl_cffi import requests as curl_requests
except ImportError:
    curl_requests = None

SITE = "https://mybt.kiteyuan.info"
API = SITE + "/api"
CASDOOR = "https://auth.kiteyuan.info"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)
TIMEOUT = 30
RETRY = 3

# 随机延时区间(秒)。cron 触发时刻全网一致, 打散请求时间避免集中访问特征。
START_DELAY_RANGE = (0, 1800)   # 脚本启动前, 可用 START_DELAY_MAX 覆盖上限
TASK_DELAY_RANGE = (3, 12)      # 相邻任务之间
ACCOUNT_DELAY_RANGE = (10, 40)  # 多账号之间
STEP_DELAY_RANGE = (1.0, 3.0)   # 登录链路各步骤之间

# 积分任务: (显示名, 接口路径)
TASKS = [
    ("新用户礼包", "/auth/points/tasks/newbie"),
    ("每日签到", "/auth/points/tasks/signin"),
    ("使用纸鸢磁力", "/auth/points/tasks/visit"),
]


# ---------------------------------------------------------------- 延时


def rand_sleep(rng, label=""):
    """按区间随机休眠, 返回实际秒数。"""
    secs = random.uniform(*rng)
    if label:
        print(f"[延时] {label} {secs:.1f}s")
    time.sleep(secs)
    return secs


def initial_delay():
    """启动随机延时。

    GitHub Actions 的 cron 本身有排队抖动, 但同一时刻仍会有大量任务并发,
    这里再叠加一次随机等待, 把请求摊到时间窗内。
    手动触发(workflow_dispatch)或显式设置 START_DELAY_MAX=0 时跳过。
    """
    if os.environ.get("SKIP_START_DELAY", "").strip().lower() in ("1", "true", "yes"):
        print("[延时] 已设置 SKIP_START_DELAY, 跳过启动延时")
        return
    try:
        upper = int(os.environ.get("START_DELAY_MAX", START_DELAY_RANGE[1]))
    except ValueError:
        upper = START_DELAY_RANGE[1]
    if upper <= 0:
        print("[延时] START_DELAY_MAX=0, 跳过启动延时")
        return
    secs = random.randint(START_DELAY_RANGE[0], upper)
    print(f"[延时] 启动随机等待 {secs}s ({secs // 60}分{secs % 60}秒)")
    time.sleep(secs)


# ---------------------------------------------------------------- 签名


def canonical_query(query: str) -> str:
    """复刻前端 Oo(): 按 key 排序, 保留原始编码, 重复 key 取最后一个值。"""
    if not query:
        return ""
    values = {}
    keys = []
    for part in query.split("&"):
        idx = part.find("=")
        if idx != -1:
            key, val = part[:idx], part[idx + 1:]
            if key not in values:
                keys.append(key)
            values[key] = val
        else:
            if part not in values:
                keys.append(part)
                values[part] = None
    keys.sort()
    out = []
    for k in keys:
        v = values.get(k)
        out.append(k if v is None else f"{k}={v}")
    return "&".join(out)


def make_sign(method: str, path: str, query: str, body: str, secret: str):
    """返回 (X-Sign, X-Timestamp)。path 需为含 /api 前缀的完整路径。"""
    ts = str(int(time.time()))
    body_hash = hashlib.sha256((body or "").encode("utf-8")).hexdigest()
    msg = "\n".join([method.upper(), path, canonical_query(query), body_hash, ts])
    sign = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
    return sign, ts


# ---------------------------------------------------------------- 客户端


class KiteYuanClient:
    def __init__(self, email: str, password: str, label: str = ""):
        self.email = email
        self.password = password
        self.label = label or email
        # curl_cffi 会模拟 Chrome 的 TLS / HTTP2 指纹。
        # GitHub Actions 的机房 IP 用普通 python-requests 容易被 Cloudflare 返回 403。
        if curl_requests is not None:
            self.session = curl_requests.Session(impersonate="chrome")
            self.http_backend = "curl_cffi/Chrome"
        else:
            self.session = requests.Session()
            self.http_backend = "requests（未安装 curl_cffi，CF 403 风险较高）"
        self.session.headers.update({
            "User-Agent": UA,
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Origin": SITE,
            "Referer": SITE + "/",
        })
        self.token = ""
        self.secret = ""
        self.user = {}

    # -- 登录 --------------------------------------------------------

    def login(self):
        # 1. 取授权地址(内含服务端签发的 state)
        r = self.session.get(
            API + "/auth/casdoor/login", allow_redirects=False, timeout=TIMEOUT
        )
        authorize_url = r.headers.get("location", "")
        if not authorize_url:
            raise RuntimeError(f"未取得 Casdoor 授权地址 (HTTP {r.status_code})")
        service_qs = urlsplit(authorize_url).query

        rand_sleep(STEP_DELAY_RANGE)

        # 2. Casdoor 密码登录, service 必须是完整的授权 query
        payload = {
            "owner": "admin",
            "application": "KiteYuan KiteMagnet",
            "username": self.email,
            "password": self.password,
            "autoSignin": True,
            "type": "login",
            "signinMethod": "Password",
        }
        r = self.session.post(
            CASDOOR + "/api/login?service=" + quote(service_qs, safe=""),
            json=payload,
            headers={"User-Agent": UA},
            timeout=TIMEOUT,
        )
        data = r.json()
        if data.get("status") != "ok":
            raise RuntimeError(f"Casdoor 登录失败: {data.get('msg') or r.text[:200]}")

        rand_sleep(STEP_DELAY_RANGE)

        # 3. 跟随授权回调, 从最终 URL 取出站点 token
        r = self.session.get(authorize_url, allow_redirects=True, timeout=TIMEOUT)
        m = re.search(r"[?&]token=([^&#]+)", r.url)
        if not m:
            err = re.search(r"[?&]error=([^&#]+)", r.url)
            raise RuntimeError(
                "回调未返回 token: " + (err.group(1) if err else r.url[:200])
            )
        self.token = m.group(1)

        # 4. /auth/me 拿签名密钥(此接口本身不需要签名)
        r = self.session.get(
            API + "/auth/me",
            headers={"Authorization": "Bearer " + self.token},
            timeout=TIMEOUT,
        )
        me = r.json()
        self.secret = me.get("sign_secret") or ""
        self.user = me.get("user") or {}
        if not self.secret:
            raise RuntimeError("未取得 sign_secret")

    # -- 带签名请求 ---------------------------------------------------

    def request(self, method: str, path: str, body=None):
        query = ""
        if "?" in path:
            path, query = path.split("?", 1)
        full_path = path if path.startswith("/api") else "/api" + path
        body_str = "" if body is None else json.dumps(body, separators=(",", ":"))
        last_err = None
        for attempt in range(RETRY):
            sign, ts = make_sign(method, full_path, query, body_str, self.secret)
            try:
                r = self.session.request(
                    method,
                    SITE + full_path + (("?" + query) if query else ""),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + self.token,
                        "X-Sign": sign,
                        "X-Timestamp": ts,
                    },
                    data=body_str or None,
                    timeout=TIMEOUT,
                )
            except Exception as exc:
                # curl_cffi 与 requests 的异常类不同；这里统一纳入重试。
                last_err = exc
                # 指数退避 + 随机抖动
                time.sleep(2 ** attempt * 2 + random.uniform(0, 2))
                continue
            # 签名带时间戳, 偶发时钟/风控问题重试一次
            if r.status_code == 401 and "签名" in r.text and attempt < RETRY - 1:
                last_err = RuntimeError(r.text[:120])
                time.sleep(random.uniform(2, 5))
                continue
            return r
        raise RuntimeError(f"请求 {full_path} 失败: {last_err}")

    def refresh_me(self):
        r = self.session.get(
            API + "/auth/me",
            headers={"Authorization": "Bearer " + self.token},
            timeout=TIMEOUT,
        )
        self.user = (r.json() or {}).get("user") or {}
        return self.user

    # -- 任务 --------------------------------------------------------

    def run_tasks(self):
        results = []
        # 任务顺序随机化, 避免每天固定的请求序列特征
        tasks = TASKS[:]
        random.shuffle(tasks)
        for i, (name, path) in enumerate(tasks):
            try:
                r = self.request("POST", path, {})
                try:
                    data = r.json()
                except ValueError:
                    data = {}
                if r.status_code == 200 and data.get("ok"):
                    added = data.get("added", 0)
                    results.append((name, "ok", f"+{added} 积分"))
                else:
                    msg = data.get("error") or f"HTTP {r.status_code}"
                    # "今日已签到" / "今日已领取" / "已领取过" 属于正常状态, 不算失败
                    done_words = ("已签到", "已领取", "已领", "已完成", "重复")
                    state = "skip" if any(w in msg for w in done_words) else "fail"
                    results.append((name, state, msg))
            except Exception as exc:
                results.append((name, "fail", str(exc)[:120]))
            if i < len(tasks) - 1:
                rand_sleep(TASK_DELAY_RANGE, "任务间隔")
        # 结果按 TASKS 原顺序输出, 保持通知可读
        order = {n: idx for idx, (n, _) in enumerate(TASKS)}
        results.sort(key=lambda x: order.get(x[0], 99))
        return results


# ---------------------------------------------------------------- 通知


def notify_telegram(text: str):
    token = os.environ.get("TG_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TG_CHAT_ID", "").strip()
    if not token or not chat_id:
        print("[TG] 未配置 TG_BOT_TOKEN / TG_CHAT_ID, 跳过推送")
        return
    # GitHub Secret 未配置时会作为空字符串注入，不能只依赖 get() 的默认值。
    api = (os.environ.get("TG_API_HOST", "").strip() or "https://api.telegram.org").rstrip("/")
    for attempt in range(3):
        try:
            r = requests.post(
                f"{api}/bot{token}/sendMessage",
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                print("[TG] 推送成功")
                return
            print(f"[TG] 推送失败 HTTP {r.status_code}: {r.text[:200]}")
            # 401/403 = Token 或 Chat ID 配置错误, 重试无意义
            if r.status_code in (400, 401, 403, 404):
                return
        except requests.RequestException as exc:
            print(f"[TG] 推送异常: {exc}")
        time.sleep(3)


# ---------------------------------------------------------------- 主流程


def load_accounts():
    raw = os.environ.get("KITEYUAN_ACCOUNTS", "").strip()
    if raw:
        try:
            items = json.loads(raw)
            accounts = [
                (a["email"], a["password"], a.get("name", ""))
                for a in items
                if a.get("email") and a.get("password")
            ]
            if accounts:
                return accounts
        except Exception as exc:
            print(f"KITEYUAN_ACCOUNTS 解析失败, 回退单账号: {exc}")
    email = os.environ.get("KITEYUAN_EMAIL", "").strip()
    password = os.environ.get("KITEYUAN_PASSWORD", "").strip()
    if not email or not password:
        return []
    return [(email, password, "")]


ICON = {"ok": "✅", "skip": "➖", "fail": "❌"}


def mask(email: str) -> str:
    name, _, domain = email.partition("@")
    if len(name) <= 2:
        shown = name[:1] + "*"
    else:
        shown = name[:2] + "*" * (len(name) - 2)
    return f"{shown}@{domain}" if domain else shown


def main():
    accounts = load_accounts()
    if not accounts:
        print("缺少凭据: 请设置 KITEYUAN_EMAIL / KITEYUAN_PASSWORD")
        notify_telegram("🪁 <b>纸鸢网盘签到</b>\n\n❌ 未配置账号凭据, 任务未执行")
        return 1

    initial_delay()

    lines = ["🪁 <b>纸鸢网盘 · 积分任务</b>", ""]
    beijing = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() + 8 * 3600))
    lines.append(f"🕐 {beijing} (UTC+8)")
    lines.append("")

    exit_code = 0
    for idx, (email, password, name) in enumerate(accounts, 1):
        if idx > 1:
            rand_sleep(ACCOUNT_DELAY_RANGE, "账号间隔")
        label = name or mask(email)
        header = f"👤 <b>{label}</b>" if len(accounts) == 1 else f"👤 <b>[{idx}] {label}</b>"
        lines.append(header)
        print(f"\n=== 账号 {idx}: {label} ===")
        client = KiteYuanClient(email, password, label)
        print(f"HTTP 后端: {client.http_backend}")
        try:
            client.login()
            print(f"登录成功, 当前积分 {client.user.get('points')}")
        except Exception as exc:
            print(f"登录失败: {exc}")
            lines.append(f"  ❌ 登录失败: {exc}")
            lines.append("")
            exit_code = 1
            continue

        results = client.run_tasks()
        for tname, state, msg in results:
            print(f"  {ICON[state]} {tname}: {msg}")
            lines.append(f"  {ICON[state]} {tname} — {msg}")
            if state == "fail":
                exit_code = 1

        try:
            user = client.refresh_me()
            points = user.get("points", "?")
            lines.append(f"  💰 当前积分: <b>{points}</b>")
            print(f"  当前积分: {points}")
        except Exception as exc:
            print(f"  积分查询失败: {exc}")
        lines.append("")

    text = "\n".join(lines).strip()
    print("\n" + "-" * 40)
    print(re.sub(r"</?b>", "", text))
    notify_telegram(text)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

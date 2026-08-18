# 纸鸢网盘自动签到

自动完成 [纸鸢网盘](https://mybt.kiteyuan.info/) 的每日积分任务，运行在 GitHub Actions，结果推送 Telegram。

## 领取的任务

| 任务 | 接口 | 说明 |
| --- | --- | --- |
| 新用户礼包 | `POST /api/auth/points/tasks/newbie` | 仅一次，+1 积分 |
| 每日签到 | `POST /api/auth/points/tasks/signin` | 每日 +4 积分 |
| 使用纸鸢磁力 | `POST /api/auth/points/tasks/visit` | 每日 +1 积分 |

「邀请好友」需要填别人的邀请码，属于一次性手动操作，脚本不做处理。

## 部署

1. Fork 或新建仓库，放入 `kiteyuan_checkin.py`、`requirements.txt`、`.github/workflows/checkin.yml`。
2. 到 `Settings → Secrets and variables → Actions` 添加 Secrets：

   | Secret | 必填 | 说明 |
   | --- | --- | --- |
   | `KITEYUAN_EMAIL` | 是 | Casdoor 登录邮箱 |
   | `KITEYUAN_PASSWORD` | 是 | Casdoor 登录密码 |
   | `TG_BOT_TOKEN` | 否 | Telegram Bot Token（[@BotFather](https://t.me/BotFather) 获取） |
   | `TG_CHAT_ID` | 否 | 接收通知的 Chat ID（[@userinfobot](https://t.me/userinfobot) 获取） |
   | `KITEYUAN_ACCOUNTS` | 否 | 多账号，JSON 数组，优先级高于上面两个 |
   | `TG_API_HOST` | 否 | 自建 Telegram API 反代地址 |

   多账号格式：

   ```json
   [
     {"email": "a@example.com", "password": "pwd1", "name": "主号"},
     {"email": "b@example.com", "password": "pwd2"}
   ]
   ```

3. `Settings → Actions → General → Workflow permissions` 选 **Read and write permissions**（keepalive 需要）。
4. 到 Actions 页手动 `Run workflow` 验证一次。

默认每天北京时间 08:05 触发（`cron: "5 0 * * *"`，UTC），实际执行时间叠加随机延时。

## 随机延时

避免所有人卡在同一时刻请求，也让请求序列不那么规整：

| 位置 | 区间 | 说明 |
| --- | --- | --- |
| 脚本启动 | 0~30 分钟 | 仅 `schedule` 触发时生效，手动触发为 0 |
| 登录各步骤之间 | 1~3 秒 | 取授权地址 → 密码登录 → 回调 |
| 任务之间 | 3~12 秒 | 同时对三个任务的**执行顺序随机洗牌** |
| 多账号之间 | 10~40 秒 | |
| 失败重试 | 指数退避 + 抖动 | 网络异常 2/4/8 秒起，叠加 0~2 秒随机 |

通知里的任务顺序始终按固定顺序排列，不受洗牌影响。

可调环境变量：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `START_DELAY_MAX` | `1800` | 启动延时上限（秒），设 `0` 关闭 |
| `SKIP_START_DELAY` | 空 | 置 `1`/`true` 直接跳过启动延时 |

因为启动延时最长 30 分钟，job 的 `timeout-minutes` 设为 50。若不想等，可把 workflow 里的 `START_DELAY_MAX` 改小。

## 防 60 天自动停用

GitHub 会在仓库 60 天无提交活动后停用 `schedule` 触发。workflow 里做了两层处理：

- 每次运行调用 `PUT /repos/{owner}/{repo}/actions/workflows/checkin.yml/enable`，即便被停用也会重新启用。
- 距上次提交满 20 天时，自动向 `.github/last-keepalive` 写入时间戳并提交，刷新仓库活动时间。

## 本地运行

```bash
pip install -r requirements.txt
export KITEYUAN_EMAIL="your@email.com"
export KITEYUAN_PASSWORD="your-password"
export TG_BOT_TOKEN="..."   # 可选
export TG_CHAT_ID="..."     # 可选
python kiteyuan_checkin.py
```

退出码：`0` 全部成功或已领取，`1` 存在登录/任务失败。

## 实现说明

站点接口除鉴权 `Authorization: Bearer <token>` 外，还需要 HMAC 签名头，算法逆向自前端：

```
msg  = METHOD + "\n" + "/api" + path + "\n" + canonical_query + "\n"
     + sha256_hex(body) + "\n" + timestamp
X-Sign      = hmac_sha256_hex(msg, sign_secret)
X-Timestamp = unix 秒
```

`sign_secret` 由 `GET /api/auth/me` 返回（该接口不需要签名）。`canonical_query` 为 query 参数按 key 排序后以 `&` 拼接，不重新编码。

登录链路：`GET /api/auth/casdoor/login`（拿带 state 的授权地址）→ `POST https://auth.kiteyuan.info/api/login?service=<授权query>`（密码登录）→ 跟随授权回调，从最终 URL 的 `?token=` 取站点 JWT。

## 注意

签到失败常见原因是密码变更或 Casdoor 应用配置调整，届时需要更新 Secrets。脚本对签名失败会自动重试 3 次。
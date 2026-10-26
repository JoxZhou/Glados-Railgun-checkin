import base64
import json
import logging
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union

import requests
from pypushdeer import PushDeer

from logging_config import init_logger


class CheckinStatus(Enum):
    """签到状态"""

    SUCCESS = 0
    REPEAT = 1
    FAILURE = -2


class APIEndpoint(Enum):
    """API端点"""

    CHECKIN = "/api/user/checkin"
    STATUS = "/api/user/status"
    POINTS = "/api/user/points"


class LogEmoji:
    """日志 Emoji 常量"""

    SUCCESS = "✅"
    FAIL = "❌"
    REPEAT = "🔄"
    PENDING = "⏳"
    CHECKIN = "🎫"
    STATUS = "📊"
    POINTS = "💰"
    START = "🚀"
    END = "🏁"
    COOKIE = "🍪"
    DOMAIN = "🌐"
    WARNING = "⚠️ "
    ERROR = "🔴"
    INFO = "ℹ️ "


# 默认仓库标识（用于本地运行时回退生成直达链接）
DEFAULT_GITHUB_REPO = "JoxZhou/Glados-Railgun-checkin"
BEIJING_TZ = timezone(timedelta(hours=8))

# 各平台合法 User-Agent（版本号无关，仅平台 token 关键）
# GLaDOS 自 2026-09 起对签到请求做设备/UA 校验：UA 与登录设备不一致会返回
# code:4 reason:device-mismatch（"Automated check-in detected"），需伪装成登录设备的 UA 才能签到成功。
PLATFORM_UA = {
    "Windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "macOS": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "iPhone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Android": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
}


def resolve_platform_ua(login_device: Optional[str]) -> Optional[str]:
    """根据服务端返回的 loginDevice 匹配对应平台的合法 User-Agent（忽略大小写及常见别名）"""
    if not login_device:
        return None
    if login_device in PLATFORM_UA:
        return PLATFORM_UA[login_device]
    dev_lower = str(login_device).strip().lower()
    alias_map = {
        "windows": "Windows",
        "win": "Windows",
        "pc": "Windows",
        "macos": "macOS",
        "mac": "macOS",
        "darwin": "macOS",
        "osx": "macOS",
        "linux": "Linux",
        "ubuntu": "Linux",
        "iphone": "iPhone",
        "ios": "iPhone",
        "ipad": "iPhone",
        "android": "Android",
    }
    for key, target in alias_map.items():
        if key in dev_lower:
            return PLATFORM_UA[target]
    return None


def get_beijing_now_str() -> str:
    """获取当前北京时间字符串"""
    return datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S")


def get_direct_links() -> Dict[str, str]:
    """构建签到页、GitHub Secrets 配置页、Actions 运行记录的直达链接"""
    server_url = (os.environ.get("GITHUB_SERVER_URL") or "https://github.com").rstrip("/")
    repo = (os.environ.get("GITHUB_REPOSITORY") or DEFAULT_GITHUB_REPO).strip("/")
    run_id = (os.environ.get("GITHUB_RUN_ID") or "").strip()

    repo_url = f"{server_url}/{repo}"
    secrets_url = f"{repo_url}/settings/secrets/actions"
    if run_id:
        actions_url = f"{repo_url}/actions/runs/{run_id}"
    else:
        actions_url = f"{repo_url}/actions/workflows/gladosCheck.yml"

    return {
        "glados_checkin": "https://glados.cloud/console/checkin",
        "railgun_checkin": "https://railgun.info/console/checkin",
        "github_secrets": secrets_url,
        "github_actions": actions_url,
    }


def mask_account_identifier(email: Optional[str] = None, user_id: Optional[Union[str, int]] = None) -> str:
    """对账号邮箱/ID 做简洁脱敏展示（优先展示脱敏邮箱，无邮箱时回退展示 ID）"""
    if email and isinstance(email, str) and "@" in email:
        local, domain = email.split("@", 1)
        if len(local) <= 2:
            masked_local = local[0] + "***"
        elif len(local) <= 4:
            masked_local = local[:1] + "***" + local[-1:]
        else:
            masked_local = local[:2] + "***" + local[-2:]
        return f"{masked_local}@{domain}"
    if user_id is not None and str(user_id).strip():
        return f"ID:{user_id}"
    return ""


def normalize_cookie(raw_cookie: str) -> str:
    """
    标准化单账号 Cookie 字符串，自动兼容以下常见粘贴格式：
    1. 标准格式: 'gld:sess=gld_xxx; gld:sess.sig=yyy'
    2. 浏览器 Application 表格复制（空格/Tab 分隔）:
       'gld:sess gld_xxx gld:sess.sig yyy'
    3. 冒号/斜杠分隔: 'gld:sess: gld_xxx / gld:sess.sig: yyy'
    4. 带 'Cookie:' 前缀或首尾引号
    """
    if not raw_cookie:
        return ""

    s = raw_cookie.strip().strip("\"'")
    if s.lower().startswith("cookie:"):
        s = s[7:].strip()

    # 若包含无 '=' 的会话键（如 'gld:sess gld_xxx gld:sess.sig yyy'），用正则提取键值对
    token_pattern = re.compile(
        r"(gld:sess\.sig|koa:sess\.sig|gld:sess|koa:sess)\s*(?:=|:|\s)\s*([^\s;/,]+)"
    )

    # 先检查是否已经是标准 ';' 分隔的 k=v 列表
    semi_parts = [p.strip() for p in s.split(";") if p.strip()]
    has_non_kv = any("=" not in p or re.search(r"\s+(gld:sess|koa:sess)", p) for p in semi_parts)

    if has_non_kv or ("=" not in s):
        matches = token_pattern.findall(s)
        if matches:
            seen = {}
            ordered_keys = []
            for k, v in matches:
                v_clean = v.strip().strip(";,\"'")
                if k not in seen:
                    ordered_keys.append(k)
                seen[k] = v_clean
            return "; ".join(f"{k}={seen[k]}" for k in ordered_keys)

    # 标准格式清理空白
    cleaned_parts = []
    for p in semi_parts:
        if "=" in p:
            k, v = p.split("=", 1)
            cleaned_parts.append(f"{k.strip()}={v.strip()}")
        else:
            cleaned_parts.append(p.strip())
    return "; ".join(cleaned_parts)


def log_method(func):
    """日志装饰器"""

    def wrapper(self, *args, **kwargs):
        method_name = func.__name__
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            logger.error(f"{LogEmoji.COOKIE}[{self.cookie_index}] {LogEmoji.DOMAIN}[{self.domain}] {LogEmoji.ERROR} {method_name} 执行失败: {e}")

            DEFAULT_ERRORS = {
                "checkin": {
                    "status": "签到失败",
                    "points": "0",
                    "message": f"执行异常: {e}",
                    "code": CheckinStatus.FAILURE,
                    "auth_invalid": False,
                },
                "get_status": ("None 天", -2, ""),
                "get_points": ("None 积分", 0),
            }

            if method_name in DEFAULT_ERRORS:
                error_template = DEFAULT_ERRORS[method_name]
                if isinstance(error_template, dict):
                    return error_template.copy()
                return error_template
            raise

    return wrapper


def is_auth_invalid(code: int, message: str) -> bool:
    """判断是否为 Cookie 失效/未登录导致的鉴权失败（区别于网络错误/其他错误）"""
    if code != CheckinStatus.FAILURE.value:
        return False
    msg = (message or "").lower()
    keywords = [
        "没有权限",
        "nopermission",
        "no permission",
        "请先登录",
        "未登录",
        "not logged",
        "login required",
        "unauthorized",
        "鉴权",
        "登录",
        "expired",
        "过期",
        "invalid",
    ]
    return any(k in msg for k in keywords)


def analyze_cookie(cookie_str: str) -> Dict[str, object]:
    """
    本地预检 Cookie，无需请求接口即可发现明显问题：
    - 分别检测 gld:sess + gld:sess.sig（GLaDOS 新版）与 koa:sess + koa:sess.sig（Railgun/旧版）
    - gld:sess 通常为 'gld_<hex>' 不透明令牌；koa:sess 为 base64 JSON（含 userId 与 _expire）
    - 若同时存在有效 gld:sess 与旧 koa:sess，只要任一会话对完整且未过期即放行
    返回字段：
      valid_format / expired / sig_suspicious / missing_session /
      has_gld / has_koa / user_id / expire_dt / note
    """
    info: Dict[str, object] = {
        "valid_format": False,
        "expired": False,
        "sig_suspicious": False,
        "missing_session": False,
        "has_gld": False,
        "has_koa": False,
        "user_id": None,
        "expire_dt": None,
        "note": "",
    }
    normalized = normalize_cookie(cookie_str)
    if not normalized:
        info["missing_session"] = True
        info["note"] = "Cookie 为空"
        return info

    kv_map: Dict[str, str] = {}
    for p in normalized.split(";"):
        p = p.strip()
        if "=" in p:
            k, v = p.split("=", 1)
            kv_map[k.strip()] = v.strip()

    gld_sess = kv_map.get("gld:sess")
    gld_sig = kv_map.get("gld:sess.sig")
    koa_sess = kv_map.get("koa:sess")
    koa_sig = kv_map.get("koa:sess.sig")

    info["has_gld"] = bool(gld_sess)
    info["has_koa"] = bool(koa_sess)

    if not gld_sess and not koa_sess:
        info["missing_session"] = True
        info["note"] = "Cookie 缺少 gld:sess 或 koa:sess 会话字段"
        return info

    notes: List[str] = []
    gld_pair_ok = False
    koa_pair_ok = False
    koa_expired = False

    # 1) 校验 gld:sess + gld:sess.sig（GLaDOS 当前主流格式）
    if gld_sess is not None:
        if not gld_sig:
            notes.append("缺少 gld:sess.sig，GLaDOS Cookie 不完整")
        elif len(gld_sig) < 16:
            notes.append(f"gld:sess.sig 疑似被截断（长度 {len(gld_sig)}，正常约 26~28）")
        elif len(gld_sess) < 16:
            notes.append(f"gld:sess 长度异常（长度 {len(gld_sess)}）")
        else:
            gld_pair_ok = True

    # 2) 校验 koa:sess + koa:sess.sig（Railgun 或旧版 GLaDOS 格式）
    if koa_sess is not None:
        sig_ok = True
        if not koa_sig:
            sig_ok = False
            notes.append("缺少 koa:sess.sig，koa Cookie 不完整")
        elif len(koa_sig) < 16:
            sig_ok = False
            notes.append(f"koa:sess.sig 疑似被截断（长度 {len(koa_sig)}，正常约 26~28）")

        try:
            pad = koa_sess + "=" * (-len(koa_sess) % 4)
            data = json.loads(base64.b64decode(pad))
            info["user_id"] = data.get("userId") or data.get("userID")
            exp = data.get("_expire") or data.get("expire") or data.get("_expires")
            if exp is not None:
                exp_s = exp / 1000.0 if exp > 1e12 else float(exp)
                exp_dt = datetime.fromtimestamp(exp_s, tz=timezone.utc)
                info["expire_dt"] = exp_dt
                if exp_dt.timestamp() < time.time():
                    koa_expired = True
                    notes.append(f"koa:sess 已于 {exp_dt.strftime('%Y-%m-%d %H:%M UTC')} 过期")
            if sig_ok and not koa_expired:
                koa_pair_ok = True
        except Exception as e:
            notes.append(f"koa:sess 解码失败: {e}")

    # 综合判定：只要 gld 或 koa 任一会话对完整且未过期，即视为有效
    if gld_pair_ok or koa_pair_ok:
        info["valid_format"] = True
        info["expired"] = False
        info["sig_suspicious"] = False
        info["note"] = "; ".join(notes) if notes else "预检通过"
    else:
        info["valid_format"] = False
        if koa_expired and not gld_sess:
            info["expired"] = True
        else:
            info["sig_suspicious"] = True
        info["note"] = "; ".join(notes) if notes else "Cookie 预检未通过"

    return info


def diagnose_failure_reason(
    domain: str,
    code: int,
    raw_message: str,
    cookie_info: Optional[Dict[str, object]] = None,
) -> str:
    """将接口原始报错转换为简洁明了的失败原因"""
    msg = (raw_message or "").strip() or "未知错误"
    msg_lower = msg.lower()

    if code == 4 or "device-mismatch" in msg_lower or "automated check-in" in msg_lower:
        return "设备 UA 校验未通过，请重新登录更新 Cookie"

    if is_auth_invalid(code, msg):
        if cookie_info:
            if domain == "glados.cloud" and not cookie_info.get("has_gld") and cookie_info.get("has_koa"):
                return "Cookie 已失效（仅含旧版 koa:sess，需更新为 gld:sess）"
            if domain == "railgun.info" and not cookie_info.get("has_koa") and cookie_info.get("has_gld"):
                return "非 Railgun 账号（仅含 gld:sess）"
        return "Cookie 已失效/无权限，请重新登录更新"

    if "http " in msg_lower or "网络" in msg_lower or "timeout" in msg_lower or "ssl" in msg_lower:
        return f"网络或接口异常 ({msg})"

    return f"{msg} (code={code})"


class Config:
    """应用配置"""

    ENV_PUSH_KEY = "PUSHDEER_SENDKEY"
    ENV_COOKIES = "GLADOS_COOKIES"
    ENV_VERBOSE = "GLADOS_VERBOSE"
    ENV_NOTIFY_ON_SUCCESS = "GLADOS_NOTIFY_ON_SUCCESS"

    DEFAULT_VERBOSE = False
    DEFAULT_NOTIFY_ON_SUCCESS = False
    DOMAINS = ["glados.cloud", "railgun.info"]

    def __init__(self):
        self.push_key: str = ""
        self.cookies_list: List[str] = []
        self.verbose: bool = self.DEFAULT_VERBOSE
        self.notify_on_success: bool = self.DEFAULT_NOTIFY_ON_SUCCESS
        self._load_config()

    @staticmethod
    def _parse_bool_env(env_name: str, raw_val: Optional[str], default: bool) -> bool:
        if raw_val is None or raw_val.strip() == "":
            return default
        val_lower = raw_val.strip().lower()
        if val_lower in ("true", "1", "yes", "y"):
            return True
        if val_lower in ("false", "0", "no", "n"):
            return False
        logger.warning(f"{LogEmoji.WARNING} 环境变量 '{env_name}' 的值 '{raw_val}' 无效，将使用默认值 {default}。")
        return default

    def _load_config(self) -> None:
        """加载并标准化配置"""
        push_key_env = os.environ.get(self.ENV_PUSH_KEY)
        raw_cookies_env = os.environ.get(self.ENV_COOKIES)
        verbose_env = os.environ.get(self.ENV_VERBOSE)
        notify_env = os.environ.get(self.ENV_NOTIFY_ON_SUCCESS)

        if not push_key_env or not push_key_env.strip():
            logger.warning(f"{LogEmoji.WARNING} 环境变量 '{self.ENV_PUSH_KEY}' 未设置。")
            self.push_key = ""
        else:
            self.push_key = push_key_env.strip()

        if not raw_cookies_env or not raw_cookies_env.strip():
            logger.warning(f"{LogEmoji.WARNING} 环境变量 '{self.ENV_COOKIES}' 未设置。")
            self.cookies_list = []
        else:
            # 支持使用 '&' 或换行符分隔多个账号的 Cookie，并自动标准化每个 Cookie 格式
            raw_parts = re.split(r"[&\r\n]+", raw_cookies_env)
            self.cookies_list = [normalize_cookie(c) for c in raw_parts if normalize_cookie(c)]
            if not self.cookies_list:
                raise ValueError(f"环境变量 '{self.ENV_COOKIES}' 已设置，但未包含任何有效的 Cookie。")

        self.verbose = self._parse_bool_env(self.ENV_VERBOSE, verbose_env, self.DEFAULT_VERBOSE)
        self.notify_on_success = self._parse_bool_env(
            self.ENV_NOTIFY_ON_SUCCESS, notify_env, self.DEFAULT_NOTIFY_ON_SUCCESS
        )

        logger.info(f"{LogEmoji.INFO} 共加载了 {len(self.cookies_list)} 个账号 Cookie 用于签到。")
        logger.info(f"{LogEmoji.INFO} 当前 {self.ENV_PUSH_KEY}: {'已设置' if self.push_key else '未设置'}。")
        logger.info(f"{LogEmoji.INFO} 当前 {self.ENV_VERBOSE}: {self.verbose}。")
        if self.notify_on_success:
            logger.info(f"{LogEmoji.INFO} 当前 {self.ENV_NOTIFY_ON_SUCCESS}: True（已开启成功时也推送通知）。")


class API:
    """API 调用"""

    CHECKIN_URL = APIEndpoint.CHECKIN.value
    STATUS_URL = APIEndpoint.STATUS.value
    POINTS_URL = APIEndpoint.POINTS.value

    def __init__(self, domain: str, cookie_index: int = 0, verbose: bool = False):
        self.domain: str = domain
        self.cookie_index: int = cookie_index
        self.verbose: bool = verbose
        self.headers: Dict[str, str] = self._get_headers()
        self._device_ua_cache: Dict[str, str] = {}
        self.last_error: str = ""
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def __del__(self):
        self.close()

    def close(self) -> None:
        if hasattr(self, "session"):
            try:
                self.session.close()
            except Exception as e:
                logger.error(f"{LogEmoji.ERROR} 关闭 session 时发生错误: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def _get_headers(self) -> Dict[str, str]:
        return {
            "origin": f"https://{self.domain}",
            "referer": f"https://{self.domain}/console/checkin",
            "content-type": "application/json;charset=UTF-8",
            "user-agent": PLATFORM_UA["macOS"],
        }

    def _log(self, level: str, emoji: str, message: str, force: bool = False) -> None:
        log_message = f"{LogEmoji.COOKIE}[{self.cookie_index}] {LogEmoji.DOMAIN}[{self.domain}] {emoji} {message}"
        if force or self.verbose:
            if level == "info":
                logger.info(log_message)
            elif level == "warning":
                logger.warning(log_message)
            elif level == "error":
                logger.error(log_message)

    def _get_full_url(self, path: str) -> str:
        return f"https://{self.domain}{path}"

    def _make_request(
        self,
        url: str,
        method: str,
        data: Optional[Dict] = None,
        cookies: str = "",
        retries: int = 2,
        user_agent: Optional[str] = None,
    ) -> Optional[requests.Response]:
        """发送 HTTP 请求（带退避重试与详细错误记录）"""
        session_headers = self.headers.copy()
        effective_ua = user_agent or self._device_ua_cache.get("_last")
        if effective_ua:
            session_headers["user-agent"] = effective_ua
        session_headers["cookie"] = cookies
        retryable = (500, 502, 503, 504, 429)
        self.last_error = ""

        for attempt in range(retries + 1):
            try:
                if method.upper() == "POST":
                    response = self.session.post(
                        url, headers=session_headers, data=json.dumps(data), timeout=(30, 60)
                    )
                elif method.upper() == "GET":
                    response = self.session.get(url, headers=session_headers, timeout=(30, 60))
                else:
                    self.last_error = f"不支持的 HTTP 方法: {method}"
                    self._log("error", LogEmoji.ERROR, self.last_error, force=True)
                    return None

                if not response.ok:
                    snippet = (response.text or "").strip().replace("\n", " ")[:120]
                    self.last_error = f"HTTP {response.status_code}" + (f" ({snippet})" if snippet else "")
                    if response.status_code in retryable and attempt < retries:
                        self._log(
                            "warning",
                            LogEmoji.WARNING,
                            f"请求 {url} 返回 {response.status_code}，{attempt + 1}/{retries} 后重试",
                            force=True,
                        )
                        time.sleep((attempt + 1) * 2)
                        continue
                    self._log(
                        "warning",
                        LogEmoji.WARNING,
                        f"向 {url} 发起的请求失败，状态码 {response.status_code}。响应片段: {snippet}",
                        force=True,
                    )
                    return None
                return response
            except requests.exceptions.RequestException as e:
                self.last_error = f"网络请求异常: {type(e).__name__}: {e}"
                if attempt < retries:
                    self._log(
                        "warning",
                        LogEmoji.WARNING,
                        f"向 {url} 请求发生网络错误: {e}，{attempt + 1}/{retries} 后重试",
                        force=True,
                    )
                    time.sleep((attempt + 1) * 2)
                    continue
                self._log("error", LogEmoji.ERROR, f"向 {url} 发起请求时发生网络错误: {e}", force=True)
                return None
        return None

    def _get_checkin_data(self) -> Dict[str, str]:
        return {"token": self.domain}

    @log_method
    def checkin(self, cookies: str) -> Dict[str, Union[str, CheckinStatus]]:
        """执行签到，含设备平台自适应重试（应对 GLaDOS 反爬：code 4 device-mismatch）"""
        url = self._get_full_url(self.CHECKIN_URL)
        checkin_data = self._get_checkin_data()

        start_ua = self._device_ua_cache.get("_last") or self.headers.get("user-agent")
        raw = self._checkin_attempt(url, checkin_data, cookies, start_ua)

        # 设备不匹配(code 4 / reason:device-mismatch)时，按服务端 loginDevice 切换 UA 重试
        if raw is not None and raw.get("code") == 4 and raw.get("reason") == "device-mismatch":
            login_device = raw.get("loginDevice")
            recover_ua = self._device_ua_cache.get(str(login_device)) or resolve_platform_ua(login_device)
            if recover_ua and recover_ua != start_ua:
                self._log(
                    "warning",
                    LogEmoji.WARNING,
                    f"设备平台不匹配 (loginDevice={login_device})，切换对应平台 UA 重试",
                    force=True,
                )
                raw = self._checkin_attempt(url, checkin_data, cookies, recover_ua)
            elif not recover_ua:
                # 若服务端未明确返回可识别的 loginDevice，轮询常见平台 UA 重试
                for plat_name, candidate_ua in PLATFORM_UA.items():
                    if candidate_ua == start_ua:
                        continue
                    self._log(
                        "warning",
                        LogEmoji.WARNING,
                        f"设备平台不匹配 (loginDevice={login_device})，尝试 {plat_name} UA 重试",
                        force=True,
                    )
                    raw = self._checkin_attempt(url, checkin_data, cookies, candidate_ua)
                    if raw is not None and raw.get("code") in (
                        CheckinStatus.SUCCESS.value,
                        CheckinStatus.REPEAT.value,
                    ):
                        break

        return self._parse_checkin(raw)

    def _checkin_attempt(self, url: str, data: Dict, cookies: str, user_agent: str) -> Optional[Dict]:
        response = self._make_request(url, "POST", data, cookies, user_agent=user_agent)
        if not response:
            return None
        try:
            raw = response.json()
        except ValueError:
            self.last_error = "响应非合法 JSON 格式"
            self._log("error", LogEmoji.ERROR, "签到响应解析失败", force=True)
            return None

        if raw.get("code") == 4 and raw.get("reason") == "device-mismatch":
            login_device = raw.get("loginDevice")
            matched_ua = resolve_platform_ua(login_device)
            if login_device and matched_ua:
                self._device_ua_cache[str(login_device)] = matched_ua
        elif raw.get("code") in (CheckinStatus.SUCCESS.value, CheckinStatus.REPEAT.value):
            self._device_ua_cache["_last"] = user_agent

        return raw

    def _parse_checkin(self, raw: Optional[Dict]) -> Dict[str, Union[str, CheckinStatus]]:
        result = {
            "status": "签到失败",
            "points": "0",
            "message": "",
            "code": CheckinStatus.FAILURE,
            "auth_invalid": False,
        }

        if not raw:
            result["message"] = self.last_error or "网络请求失败"
            return result

        code = raw.get("code", -2)
        message = raw.get("message", "无消息字段")
        if raw.get("reason") and raw.get("reason") not in str(message):
            login_dev = raw.get("loginDevice")
            extra = f"reason={raw.get('reason')}" + (f", loginDevice={login_dev}" if login_dev else "")
            message = f"{message} ({extra})"
        points = str(raw.get("points", 0))

        if code == CheckinStatus.SUCCESS.value:
            self._log("info", LogEmoji.SUCCESS, f"{{ code : {code}, points : {points}, message : {message} }}")
            result["code"] = CheckinStatus.SUCCESS
            result["status"] = "签到成功"
            result["points"] = points
            result["message"] = message
        elif code == CheckinStatus.REPEAT.value:
            self._log("info", LogEmoji.REPEAT, f"{{ code : {code}, message : {message} }}", force=True)
            result["code"] = CheckinStatus.REPEAT
            result["status"] = "重复签到"
            result["points"] = "0"
            result["message"] = message
        else:
            self._log("info", LogEmoji.FAIL, f"{{ code : {code}, message : {message} }}", force=True)
            result["code"] = CheckinStatus.FAILURE
            result["status"] = "签到失败"
            result["points"] = "0"
            result["message"] = message
            result["auth_invalid"] = is_auth_invalid(code, message)

        return result

    @log_method
    def get_status(self, cookies: str) -> Tuple[str, int, str]:
        """获取账号状态（返回: 剩余天数, 状态码, 脱敏账号标识）"""
        url = self._get_full_url(self.STATUS_URL)
        response = self._make_request(url, "GET", cookies=cookies)

        if response:
            data = response.json()
            code = data.get("code", -2)
            user_data = data.get("data", {}) if isinstance(data.get("data"), dict) else {}
            left_days = user_data.get("leftDays", None)
            account_label = mask_account_identifier(
                email=user_data.get("email"),
                user_id=user_data.get("userId"),
            )

            if left_days is not None:
                left_days_int = int(float(left_days))
                self._log("info", LogEmoji.SUCCESS, f"{{ code : {code}, leftDays : {left_days_int} 天}}")
                return f"{left_days_int} 天", code, account_label
            else:
                self._log("info", LogEmoji.FAIL, f"{{ code : {code}, leftDays : {left_days} 天}}", force=True)
                return "None 天", code, account_label
        else:
            self._log("warning", LogEmoji.WARNING, "获取状态失败", force=True)
            return "None 天", -2, ""

    @log_method
    def get_points(self, cookies: str) -> Tuple[str, int]:
        """获取总积分"""
        url = self._get_full_url(self.POINTS_URL)
        response = self._make_request(url, "GET", cookies=cookies)

        if response:
            data = response.json()
            code = data.get("code", -2)
            points = data.get("points", None)

            if points is not None:
                points_int = int(float(points))
                self._log("info", LogEmoji.SUCCESS, f"{{ code : {code}, points : {points_int} 积分}}")
                return f"{points_int} 积分", points_int
            else:
                self._log("info", LogEmoji.FAIL, f"{{ code : {code}, points : {points} 积分}}", force=True)
                return "None 积分", 0
        else:
            self._log("warning", LogEmoji.WARNING, "获取积分失败", force=True)
            return "None 积分", 0


@dataclass()
class CheckinResult:
    """单账号签到汇总结果"""

    cookie_index: int
    domain: str
    status: str = "签到失败"
    points: str = "0"
    days: str = "None"
    points_total: str = "None"
    code: int = CheckinStatus.FAILURE.value  # 0: 成功, 1: 重复, -2: 失败
    auth_invalid: bool = False  # True 表示因 Cookie 失效/未登录导致失败
    detail: str = ""  # 失败原因或接口返回详情
    account_label: str = ""  # 脱敏邮箱/UserID 标识
    attempted_domains: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        result_dict = asdict(self)
        if isinstance(result_dict.get("code"), CheckinStatus):
            result_dict["code"] = result_dict["code"].value
        return result_dict


class PushService:
    """推送服务"""

    def __init__(self, config: Optional[Config]):
        self.config = config

    def send(self, title: str, content: str) -> bool:
        """发送 PushDeer 通知（优先使用 Markdown 格式，使直达链接可点击）"""
        if not self.config or not getattr(self.config, "push_key", ""):
            logger.info(f"{LogEmoji.WARNING} 未设置推送密钥 ({Config.ENV_PUSH_KEY})，跳过推送通知。")
            return False

        try:
            pushdeer = PushDeer(pushkey=self.config.push_key)
            ok = pushdeer.send_markdown(title, desp=content)
            if ok:
                logger.info(f"{LogEmoji.SUCCESS} 推送通知发送成功。")
                return True
            logger.warning(f"{LogEmoji.WARNING} Markdown 推送返回 False，尝试降级为纯文本推送...")
            ok_text = pushdeer.send_text(title, desp=content)
            if ok_text:
                logger.info(f"{LogEmoji.SUCCESS} 纯文本推送通知发送成功。")
                return True
            logger.error(f"{LogEmoji.ERROR} 推送通知发送失败：服务端返回未成功状态。")
            return False
        except Exception as e:
            logger.error(f"{LogEmoji.ERROR} 发送推送通知发生异常: {e}")
            return False


class Checker:
    """签到执行与汇总器"""

    def __init__(self, config: Config):
        self.config = config
        self.results: List[CheckinResult] = []
        self.cookie_covered: Dict[int, bool] = {}
        self.auth_invalid_cookies: List[int] = []

    def _log(self, cookie_idx: int, domain: str, emoji: str, message: str, force: bool = False) -> None:
        if self.config.verbose or force:
            logger.info(f"{LogEmoji.COOKIE}[{cookie_idx}] {LogEmoji.DOMAIN}[{domain}] {emoji} {message}")

    @staticmethod
    def _normalize_code(code) -> int:
        return code.value if isinstance(code, CheckinStatus) else int(code)

    def checkin_all(self) -> None:
        """按账号依次执行签到（单账号跨域名成功/重复即短路，每个账号生成 1 条汇总结果）"""
        cookie_count = len(self.config.cookies_list)
        domain_count = len(self.config.DOMAINS)
        total_tasks = cookie_count * domain_count
        task_idx = 0

        self.cookie_covered = {i: False for i in range(1, cookie_count + 1)}
        self.auth_invalid_cookies = []
        self.results = []

        logger.info(f"{LogEmoji.INFO} 共 {cookie_count} 个账号, {domain_count} 个候选域名, 最多 {total_tasks} 个签到尝试")

        for cookie_idx, cookie in enumerate(self.config.cookies_list, 1):
            logger.info(f"{LogEmoji.START} ========== 开始处理 账号 #{cookie_idx} ==========")

            # 1. 本地预检：缺失会话段 / 过期 / 签名被截断 直接拦截并记录清晰原因
            pre = analyze_cookie(cookie)
            pre_label = mask_account_identifier(user_id=pre.get("user_id"))
            if pre.get("missing_session") or pre.get("expired") or pre.get("sig_suspicious"):
                detail = str(pre.get("note") or "Cookie 本地预检未通过")
                logger.error(f"{LogEmoji.ERROR} 账号 #{cookie_idx} 本地预检未通过: {detail}")
                self.results.append(
                    CheckinResult(
                        cookie_index=cookie_idx,
                        domain="本地预检",
                        status="Cookie无效",
                        code=CheckinStatus.FAILURE.value,
                        auth_invalid=True,
                        detail=detail,
                        account_label=pre_label,
                        attempted_domains=["本地预检"],
                    )
                )
                self.cookie_covered[cookie_idx] = False
                self.auth_invalid_cookies.append(cookie_idx)
                continue

            # 2. 依次尝试候选域名，成功或重复即短路
            domain_errors: List[Tuple[str, str, bool]] = []
            attempted_domains: List[str] = []
            winning_result: Optional[CheckinResult] = None

            for domain in self.config.DOMAINS:
                task_idx += 1
                attempted_domains.append(domain)
                logger.info(
                    f"{LogEmoji.INFO} ----- 尝试 {task_idx}/{total_tasks}: "
                    f"{LogEmoji.COOKIE}[#{cookie_idx}] on {LogEmoji.DOMAIN}[{domain}] -----"
                )

                domain_res = self._checkin_on_domain(cookie, cookie_idx, domain, pre)
                if not domain_res.account_label and pre_label:
                    domain_res.account_label = pre_label
                domain_res.attempted_domains = list(attempted_domains)

                if domain_res.code == CheckinStatus.SUCCESS.value:
                    msg = (
                        f"结果: {domain_res.status}, 获得 +{domain_res.points} 积分, "
                        f"剩余 {domain_res.days}, 总积分 {domain_res.points_total}"
                    )
                    self._log(cookie_idx, domain, LogEmoji.SUCCESS, msg, force=True)
                    self.cookie_covered[cookie_idx] = True
                    winning_result = domain_res
                    logger.info(f"{LogEmoji.SUCCESS} 账号 #{cookie_idx} 于 {domain} 签到成功，跳过后续备用域名。")
                    break

                if domain_res.code == CheckinStatus.REPEAT.value:
                    msg = (
                        f"结果: {domain_res.status} (今日已签), "
                        f"剩余 {domain_res.days}, 总积分 {domain_res.points_total}"
                    )
                    self._log(cookie_idx, domain, LogEmoji.REPEAT, msg, force=True)
                    self.cookie_covered[cookie_idx] = True
                    winning_result = domain_res
                    logger.info(f"{LogEmoji.REPEAT} 账号 #{cookie_idx} 于 {domain} 今日已签（重复签到），跳过后续备用域名。")
                    break

                # 当前域名失败，记录详细原因并继续尝试下一域名
                domain_errors.append((domain, domain_res.detail, domain_res.auth_invalid))
                self._log(
                    cookie_idx,
                    domain,
                    LogEmoji.WARNING,
                    f"结果: {domain_res.status} | 原因: {domain_res.detail}",
                    force=True,
                )

            if winning_result is not None:
                self.results.append(winning_result)
            else:
                # 所有域名均失败：去重并优先展示主域名根因
                any_auth_invalid = any(is_auth for _, _, is_auth in domain_errors)
                if any_auth_invalid:
                    self.auth_invalid_cookies.append(cookie_idx)

                unique_reasons: List[str] = []
                for dom, reason, _ in domain_errors:
                    if pre.get("has_gld") and dom == "railgun.info" and len(domain_errors) > 1:
                        continue
                    if reason not in unique_reasons:
                        unique_reasons.append(reason)
                combined_reason = "；".join(unique_reasons) if unique_reasons else "所有域名均签到失败"

                self.results.append(
                    CheckinResult(
                        cookie_index=cookie_idx,
                        domain=" / ".join(attempted_domains),
                        status="签到失败",
                        code=CheckinStatus.FAILURE.value,
                        auth_invalid=any_auth_invalid,
                        detail=combined_reason,
                        account_label=pre_label,
                        attempted_domains=attempted_domains,
                    )
                )

    def has_failure(self) -> bool:
        """是否存在整体失败的账号（所有域名均失败）"""
        return any(not covered for covered in self.cookie_covered.values())

    def _checkin_on_domain(
        self,
        cookie: str,
        cookie_idx: int,
        domain: str,
        cookie_info: Optional[Dict[str, object]] = None,
    ) -> CheckinResult:
        result = CheckinResult(cookie_index=cookie_idx, domain=domain)

        with API(domain, cookie_idx, verbose=self.config.verbose) as api:
            # 1. 执行签到
            self._log(cookie_idx, domain, LogEmoji.CHECKIN, "执行签到")
            checkin_result = api.checkin(cookie)
            result.status = str(checkin_result.get("status", "签到失败"))
            result.code = self._normalize_code(checkin_result.get("code", CheckinStatus.FAILURE))
            result.points = str(checkin_result.get("points", "0"))
            result.auth_invalid = bool(checkin_result.get("auth_invalid", False))
            raw_msg = str(checkin_result.get("message", ""))

            # 2. 成功或重复时查询剩余天数、账号标识与总积分；失败时诊断详细原因
            if result.code in (CheckinStatus.SUCCESS.value, CheckinStatus.REPEAT.value):
                result.detail = raw_msg
                self._log(cookie_idx, domain, LogEmoji.STATUS, "查询剩余天数与账号状态")
                status_res = api.get_status(cookie)
                days_str = status_res[0]
                account_label = status_res[2] if len(status_res) > 2 else ""
                result.days = days_str
                if account_label:
                    result.account_label = account_label

                self._log(cookie_idx, domain, LogEmoji.POINTS, "查询总积分")
                points_str, _ = api.get_points(cookie)
                result.points_total = points_str
            else:
                result.detail = diagnose_failure_reason(domain, result.code, raw_msg, cookie_info)

        return result

    def get_results(self) -> List[Dict[str, object]]:
        """获取所有账号的签到汇总结果"""
        return [result.to_dict() for result in self.results]

    def format_results(self) -> Tuple[str, str, str]:
        """格式化推送标题、推送正文（简洁易读，含失败原因与直达链接）与控制台日志"""
        results = self.get_results()
        links = get_direct_links()

        success_count = sum(1 for r in results if r["code"] == CheckinStatus.SUCCESS.value)
        repeat_count = sum(1 for r in results if r["code"] == CheckinStatus.REPEAT.value)
        fail_count = sum(1 for r in results if r["code"] == CheckinStatus.FAILURE.value)

        base_summary = f"GLaDOS 签到：成功{success_count} 失败{fail_count} 重复{repeat_count}"
        if self.auth_invalid_cookies:
            idx_list = ",".join(f"#{i}" for i in self.auth_invalid_cookies)
            title = f"⚠️ [Cookie失效 {idx_list}] {base_summary}"
        elif fail_count > 0:
            title = f"❌ {base_summary}"
        else:
            title = f"✅ {base_summary}"

        account_lines: List[str] = []
        log_lines: List[str] = []

        for res in results:
            idx = res["cookie_index"]
            label = f" ({res['account_label']})" if res.get("account_label") else ""
            code = res["code"]
            domain = res["domain"]
            status = res["status"]
            days_clean = str(res["days"]).replace(" ", "")
            pts_total_clean = str(res["points_total"]).replace(" 积分", "分").replace("积分", "分")

            if code == CheckinStatus.SUCCESS.value:
                account_lines.append(
                    f"#{idx}{label} ✅ 签到成功 (+{res['points']}分 | 剩余{days_clean} | 总{pts_total_clean})"
                )
                log_lines.append(
                    f"#{idx}{label} [{domain}] ✅ {status} | +{res['points']}分 | 剩余:{days_clean} | 总:{pts_total_clean}"
                )
            elif code == CheckinStatus.REPEAT.value:
                account_lines.append(f"#{idx}{label} 🔄 今日已签 (剩余{days_clean} | 总{pts_total_clean})")
                log_lines.append(
                    f"#{idx}{label} [{domain}] 🔄 {status} | 剩余:{days_clean} | 总:{pts_total_clean}"
                )
            else:
                reason = res.get("detail") or "未知原因"
                account_lines.append(f"#{idx}{label} ❌ {status}\n└ 原因：{reason}")
                log_lines.append(f"#{idx}{label} [{domain}] ❌ {status} | 原因:{reason}")

        link_lines = [
            f"🔗 签到页：{links['glados_checkin']}",
            f"🔑 更新Cookie：{links['github_secrets']}",
            f"📋 运行日志：{links['github_actions']}",
        ]

        content = "\n\n".join(["\n".join(account_lines), "\n".join(link_lines)])
        log_content = "\n".join(log_lines)
        return title, content, log_content


def format_fatal_error_notification(title: str, error_reason: str) -> Tuple[str, str]:
    """构建配置缺失或未捕获异常时的简洁通知内容"""
    links = get_direct_links()
    lines = [
        f"❌ 原因：{error_reason}",
        "",
        f"🔗 签到页：{links['glados_checkin']}",
        f"🔑 更新Cookie：{links['github_secrets']}",
        f"📋 运行日志：{links['github_actions']}",
    ]
    return title, "\n".join(lines)


def write_github_step_summary(title: str, content: str) -> None:
    """在 GitHub Actions 环境中写入 Step Summary，方便打开运行页直接查看结果与直达链接"""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    try:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(f"## {title}\n\n```text\n{content}\n```\n")
    except Exception as e:
        logger.warning(f"{LogEmoji.WARNING} 写入 GITHUB_STEP_SUMMARY 失败: {e}")


# 初始化日志
logger = init_logger()


def main():
    """主函数"""
    config: Optional[Config] = None
    need_push = True
    exit_code = 0

    try:
        # 1. 加载配置
        logger.info(f"{LogEmoji.START} 步骤 1: 加载配置")
        config = Config()

        if not config.cookies_list:
            reason = "未配置环境变量 GLADOS_COOKIES 或其中不包含任何有效 Cookie"
            logger.error(f"{LogEmoji.ERROR} {reason}，退出程序。")
            title, content = format_fatal_error_notification("[配置缺失] GLaDOS 签到未找到有效 Cookie", reason)
            need_push = True
            exit_code = 1
        else:
            # 2. 执行签到
            logger.info(f"{LogEmoji.START} 步骤 2: 执行签到")
            checker = Checker(config)
            checker.checkin_all()

            # 3. 格式化结果
            logger.info(f"{LogEmoji.START} 步骤 3: 格式化结果")
            title, content, log_content = checker.format_results()
            logger.info(f"\n{LogEmoji.END}========== 签到总结 ==========\n{title}\n{log_content}\n{content}")

            # 存在任一账号在所有域名均签到失败 -> 以非零退出码结束，并触发推送通知
            if checker.has_failure():
                exit_code = 1
                need_push = True
                logger.error(f"{LogEmoji.ERROR} 存在签到失败的账号，将以非零退出码结束并发送告警通知。")
            else:
                need_push = bool(config.notify_on_success)

    except Exception as e:
        logger.error(f"{LogEmoji.ERROR} 主程序执行过程中发生未预期的错误: {e}")
        title, content = format_fatal_error_notification("[运行出错] GLaDOS 签到脚本异常中断", str(e))
        need_push = True
        exit_code = 1

    # 写入 GitHub Actions Step Summary（若在 Actions 环境中）
    write_github_step_summary(title, content)

    # 4. 发送推送（按需）
    logger.info(f"{LogEmoji.START} 步骤 4: 发送推送")
    push_service = PushService(config)
    if need_push:
        push_service.send(title, content)
    else:
        logger.info(f"{LogEmoji.SUCCESS} 所有账号均签到成功（或今日已签），无失败，按默认策略静默跳过推送通知。")

    logger.info(f"{LogEmoji.END} 签到流程结束 (exit_code={exit_code})")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

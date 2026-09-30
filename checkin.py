import requests
import json
import os
import sys
import time
import base64
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, asdict
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


def log_method(func):
    """日志装饰器"""

    def wrapper(self, *args, **kwargs):
        method_name = func.__name__
        emoji_map = {
            "checkin": LogEmoji.CHECKIN,
            "get_status": LogEmoji.STATUS,
            "get_points": LogEmoji.POINTS,
        }
        emoji = emoji_map.get(method_name, LogEmoji.INFO)
        try:
            result = func(self, *args, **kwargs)
            return result
        except Exception as e:
            logger.error(f"{LogEmoji.COOKIE}[{self.cookie_index}] {LogEmoji.DOMAIN}[{self.domain}] {LogEmoji.ERROR} {method_name} 执行失败: {e}")

            DEFAULT_ERRORS = {
                "checkin": {"status": "签到失败", "points": "0", "message": ""},
                "get_status": ("None 天", -2),
                "get_points": ("None 积分", 0),
            }

            if method_name in DEFAULT_ERRORS:
                error_template = DEFAULT_ERRORS[method_name]
                if isinstance(error_template, dict):
                    error_result = error_template.copy()
                    error_result["message"] = f"执行失败: {e}"
                    return error_result
                return error_template
            raise

    return wrapper


def is_auth_invalid(code: int, message: str) -> bool:
    """判断是否为 Cookie 失效/未登录导致的鉴权失败（区别于网络错误/其他错误）"""
    if code != CheckinStatus.FAILURE.value:
        return False
    msg = (message or "").lower()
    keywords = [
        "没有权限", "nopermission", "no permission",
        "请先登录", "未登录", "not logged", "login required",
        "unauthorized", "鉴权", "登录", "expired", "过期", "invalid",
    ]
    return any(k in msg for k in keywords)


def analyze_cookie(cookie_str: str) -> Dict[str, object]:
    """
    本地预检 Cookie，无需请求接口即可发现明显问题（根本解决“签到静默失败”难排查）：
    - koa:sess 是否可解码、是否含过期时间
    - 是否已过期
    - koa:sess.sig 是否疑似被截断（标准 HMAC-SHA256 签名 base64url 约 43 字符）
    返回字段：valid_format / expired / sig_suspicious / user_id / expire_dt / note
    """
    info = {
        "valid_format": False,
        "expired": False,
        "sig_suspicious": False,
        "user_id": None,
        "expire_dt": None,
        "note": "",
    }
    if not cookie_str or "koa:sess=" not in cookie_str:
        info["note"] = "Cookie 缺少 koa:sess 字段"
        return info

    parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
    sess = sig = None
    for p in parts:
        if p.startswith("koa:sess=") and sess is None:
            sess = p[len("koa:sess="):]
        elif p.startswith("koa:sess.sig=") and sig is None:
            sig = p[len("koa:sess.sig="):]

    if not sess:
        info["note"] = "未能解析出 koa:sess 值"
        return info

    # 1) 检测签名是否疑似被截断（最常见的“复制不全”导致签到失败的原因）
    if sig is None:
        info["sig_suspicious"] = True
        info["note"] = "缺少 koa:sess.sig，Cookie 不完整"
    elif len(sig) < 30:
        info["sig_suspicious"] = True
        info["note"] = f"koa:sess.sig 疑似被截断（长度 {len(sig)}，正常约 43），请复制完整 Cookie"

    # 2) 解码 payload 并检查过期时间
    try:
        pad = sess + "=" * (-len(sess) % 4)
        data = json.loads(base64.b64decode(pad))
        info["valid_format"] = True
        info["user_id"] = data.get("userId") or data.get("userID")
        exp = data.get("_expire") or data.get("expire") or data.get("_expires")
        if exp is not None:
            exp_s = exp / 1000.0 if exp > 1e12 else float(exp)
            info["expire_dt"] = datetime.fromtimestamp(exp_s, tz=timezone.utc)
            if info["expire_dt"].timestamp() < time.time():
                info["expired"] = True
                info["note"] = (
                    f"Cookie 已于 {info['expire_dt'].strftime('%Y-%m-%d %H:%M UTC')} 过期，"
                    "请重新登录 GLaDOS / Railgun 并更新"
                )
    except Exception as e:
        info["note"] = f"koa:sess 解码失败（可能不是有效的 GLaDOS Cookie）: {e}"

    return info



class Config:
    """应用配置"""

    ENV_PUSH_KEY = "PUSHDEER_SENDKEY"
    ENV_COOKIES = "GLADOS_COOKIES"
    ENV_VERBOSE = "GLADOS_VERBOSE"

    """默认是否输出详细响应"""
    DEFAULT_VERBOSE = False

    """默认域名"""
    DOMAINS = ["glados.cloud", "railgun.info"]

    def __init__(self):
        self.push_key: str = ""
        self.cookies_list: List[str] = []
        self.verbose: bool = self.DEFAULT_VERBOSE
        self._load_config()

    def _load_config(self) -> None:
        """加载配置"""
        push_key_env: Optional[str] = os.environ.get(self.ENV_PUSH_KEY)
        raw_cookies_env: Optional[str] = os.environ.get(self.ENV_COOKIES)
        verbose_env: Optional[str] = os.environ.get(self.ENV_VERBOSE)

        if not push_key_env:
            logger.warning(f"{LogEmoji.WARNING} 环境变量 '{self.ENV_PUSH_KEY}' 未设置。")
            self.push_key = ""
        else:
            self.push_key = push_key_env

        if not raw_cookies_env:
            logger.warning(f"{LogEmoji.WARNING} 环境变量 '{self.ENV_COOKIES}' 未设置。")
            self.cookies_list = []
        else:
            self.cookies_list = [cookie.strip() for cookie in raw_cookies_env.split("&") if cookie.strip()]
            if not self.cookies_list:
                raise ValueError(f"环境变量 '{self.ENV_COOKIES}' 已设置，但未包含任何有效的 Cookie。")

        logger.info(f"{LogEmoji.INFO} 共加载了 {len(self.cookies_list)} 个 Cookie 用于签到。")
        logger.info(f"{LogEmoji.INFO} 当前 {self.ENV_PUSH_KEY} {'已设置' if push_key_env else '未设置'}。")

        if verbose_env is not None:
            verbose_env_lower = verbose_env.lower()
            if verbose_env_lower in ["true", "1", "yes", "y"]:
                self.verbose = True
            elif verbose_env_lower in ["false", "0", "no", "n"]:
                self.verbose = False
            else:
                logger.warning(f"{LogEmoji.WARNING} 环境变量 '{self.ENV_VERBOSE}' 的值 '{verbose_env}' 无效，将使用默认值 {self.DEFAULT_VERBOSE}。")

        logger.info(f"{LogEmoji.INFO} 当前 {self.ENV_VERBOSE}: {self.verbose}。")


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
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def __del__(self):
        """关闭 session"""
        self.close()

    def close(self) -> None:
        """关闭 session"""
        if hasattr(self, "session"):
            try:
                self.session.close()
            except Exception as e:
                logger.error(f"{LogEmoji.ERROR} 关闭 session 时发生错误: {e}")

    def __enter__(self):
        """进入上下文管理器"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出上下文管理器"""
        self.close()
        return False

    def _get_headers(self) -> Dict[str, str]:
        """获取请求头"""
        return {
            "origin": f"https://{self.domain}",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
        }

    def _log(self, level: str, emoji: str, message: str, force: bool = False) -> None:
        """统一日志输出方法"""

        log_message = f"{LogEmoji.COOKIE}[{self.cookie_index}] {LogEmoji.DOMAIN}[{self.domain}] {emoji} {message}"

        if force or self.verbose:
            if level == "info":
                logger.info(log_message)
            elif level == "warning":
                logger.warning(log_message)
            elif level == "error":
                logger.error(log_message)

    def _get_full_url(self, path: str) -> str:
        """获取完整 URL"""
        return f"https://{self.domain}{path}"

    def _make_request(self, url: str, method: str, data: Optional[Dict] = None, cookies: str = "", retries: int = 2) -> Optional[requests.Response]:
        """发送 HTTP 请求（带简单退避重试，提升对偶发网络抖动/5xx/限流的鲁棒性）"""
        session_headers = self.headers.copy()
        session_headers["cookie"] = cookies
        retryable = (500, 502, 503, 504, 429)

        for attempt in range(retries + 1):
            try:
                if method.upper() == "POST":
                    response = self.session.post(url, headers=session_headers, data=json.dumps(data), timeout=(60, 120))
                elif method.upper() == "GET":
                    response = self.session.get(url, headers=session_headers, timeout=(60, 120))
                else:
                    self._log("error", LogEmoji.ERROR, f"不支持的 HTTP 方法: {method}", force=True)
                    return None

                if not response.ok:
                    if response.status_code in retryable and attempt < retries:
                        self._log("warning", LogEmoji.WARNING,
                                  f"请求 {url} 返回 {response.status_code}，{attempt + 1}/{retries} 后重试", force=True)
                        time.sleep((attempt + 1) * 2)
                        continue
                    self._log("warning", LogEmoji.WARNING, f"向 {url} 发起的请求失败，状态码 {response.status_code}。响应内容: {response.text}", force=True)
                    return None
                return response
            except requests.exceptions.RequestException as e:
                if attempt < retries:
                    self._log("warning", LogEmoji.WARNING,
                              f"向 {url} 请求发生网络错误: {e}，{attempt + 1}/{retries} 后重试", force=True)
                    time.sleep((attempt + 1) * 2)
                    continue
                self._log("error", LogEmoji.ERROR, f"向 {url} 发起请求时发生网络错误: {e}", force=True)
                return None
        return None

    def _get_checkin_data(self) -> Dict[str, str]:
        """获取签到数据"""
        return {"token": self.domain}

    @log_method
    def checkin(self, cookies: str) -> Dict[str, Union[str, CheckinStatus]]:
        """执行签到"""
        url = self._get_full_url(self.CHECKIN_URL)
        checkin_data = self._get_checkin_data()
        response = self._make_request(url, "POST", checkin_data, cookies)

        result = {
            "status": "签到失败",
            "points": "0",
            "message": "",
            "code": CheckinStatus.FAILURE,
            "auth_invalid": False,
        }

        if response:
            data = response.json()
            code = data.get("code", -2)
            message = data.get("message", "无消息字段")
            points = str(data.get("points", 0))

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
                # 鉴权失败（Cookie 失效/未登录）单独标记，便于后续给出明确修复指引
                result["auth_invalid"] = is_auth_invalid(code, message)
        else:
            self._log("warning", LogEmoji.WARNING, "签到失败", force=True)
            result["code"] = CheckinStatus.FAILURE
            result["status"] = "签到失败"
            result["message"] = "网络请求失败"

        return result

    @log_method
    def get_status(self, cookies: str) -> Tuple[str, int]:
        """获取状态"""

        url = self._get_full_url(self.STATUS_URL)
        response = self._make_request(url, "GET", cookies=cookies)

        if response:
            data = response.json()
            code = data.get("code", -2)
            left_days = data.get("data", {}).get("leftDays", None)

            if left_days is not None:
                left_days_int = int(float(left_days))
                self._log("info", LogEmoji.SUCCESS, f"{{ code : {code}, leftDays : {left_days_int} 天}}")
                return f"{left_days_int} 天", code
            else:
                self._log("info", LogEmoji.FAIL, f"{{ code : {code}, leftDays : {left_days} 天}}", force=True)
                return "None 天", code
        else:
            self._log("warning", LogEmoji.WARNING, "获取状态失败", force=True)
            return "None 天", -2

    @log_method
    def get_points(self, cookies: str) -> Tuple[str, int]:
        """获取积分"""
        url = self._get_full_url(self.POINTS_URL)
        response = self._make_request(url, "GET", cookies=cookies)

        if response:
            data = response.json()
            code = data.get("code", -2)
            points = data.get("points", None)

            if points is not None:
                points_int = int(float(points))
                self._log("info", LogEmoji.SUCCESS, f"{{ code : {code}, points : {points_int} 积分}}")
                points_str = f"{points_int} 积分"
                points_num = points_int
                return points_str, points_num
            else:
                self._log("info", LogEmoji.FAIL, f"{{ code : {code}, points : {points} 积分}}", force=True)
                return "None 积分", 0
        else:
            self._log("warning", LogEmoji.WARNING, "获取积分失败", force=True)
            return "None 积分", 0


@dataclass()
class CheckinResult:
    """签到结果"""

    cookie_index: int
    domain: str
    status: str = "签到失败"
    points: str = "0"
    days: str = "None"
    points_total: str = "None"
    code: CheckinStatus = CheckinStatus.FAILURE  # 0: 成功, 1: 重复, -2: 失败
    auth_invalid: bool = False  # True 表示因 Cookie 失效/未登录导致失败
    detail: str = ""

    def to_dict(self) -> Dict[str, Union[str, CheckinStatus]]:
        result_dict = asdict(self)
        return result_dict


class PushService:
    """推送服务"""

    def __init__(self, config: Config):
        self.config = config

    def send(self, title: str, content: str) -> bool:
        """发送推送"""
        if not self.config or not hasattr(self.config, "push_key") or not self.config.push_key:
            logger.info(f"{LogEmoji.WARNING} 未设置推送密钥，跳过推送通知。")
            return False

        try:
            pushdeer = PushDeer(pushkey=self.config.push_key)
            pushdeer.send_text(title, desp=content)
            logger.info(f"{LogEmoji.SUCCESS} 推送通知发送成功。")
            return True
        except Exception as e:
            logger.error(f"{LogEmoji.ERROR} 发送推送通知失败: {e}")
            return False


class Checker:
    """签到"""

    def __init__(self, config: Config):
        self.config = config
        self.results = []

    def _log(self, cookie_idx: int, domain: str, emoji: str, message: str, force: bool = False) -> None:
        """统一日志输出方法"""

        if self.config.verbose or force:
            logger.info(f"{LogEmoji.COOKIE}[{cookie_idx}] {LogEmoji.DOMAIN}[{domain}] {emoji} {message}")

    @staticmethod
    def _normalize_code(code) -> int:
        """将签到返回的 code 统一为 int（兼容 API 直接返回 int 与异常分支返回枚举两种情况）"""
        return code.value if isinstance(code, CheckinStatus) else int(code)

    def checkin_all(self):
        """执行所有签到任务"""
        cookie_count = len(self.config.cookies_list)
        domain_count = len(self.config.DOMAINS)
        total_tasks = cookie_count * domain_count
        task_idx = 0

        # 记录每个 Cookie 是否被任一域名成功/重复签到覆盖；未被覆盖即视为该 Cookie 整体失败
        self.cookie_covered = {i: False for i in range(1, cookie_count + 1)}
        # 记录因 Cookie 失效（鉴权失败）而整体失败的 Cookie 序号
        self.auth_invalid_cookies = []

        logger.info(f"{LogEmoji.INFO} 共 {cookie_count} 个 Cookie, {domain_count} 个域名, 共 {total_tasks} 个任务")

        for cookie_idx, cookie in enumerate(self.config.cookies_list, 1):
            logger.info(f"{LogEmoji.START} ========== 开始处理 Cookie {cookie_idx} ==========")
            cookie_auth_invalid = False

            # 本地预检：过期 / 签名被截断 直接判定失效，避免无效网络请求并给出精准提示
            pre = analyze_cookie(cookie)
            if pre["expired"] or pre["sig_suspicious"]:
                detail = pre["note"] or "Cookie 预检未通过"
                logger.error(f"{LogEmoji.ERROR} Cookie {cookie_idx} 预检失败: {detail}")
                self.results.append(CheckinResult(
                    cookie_index=cookie_idx,
                    domain="预检",
                    status="Cookie无效",
                    code=CheckinStatus.FAILURE.value,
                    auth_invalid=True,
                    detail=detail,
                ))
                self.cookie_covered[cookie_idx] = False
                self.auth_invalid_cookies.append(cookie_idx)
                continue

            for domain in self.config.DOMAINS:
                task_idx += 1
                logger.info(f"{LogEmoji.INFO} ----- 任务 {task_idx}/{total_tasks}: {LogEmoji.COOKIE}[{cookie_idx}] on {LogEmoji.DOMAIN}[{domain}] -----")

                result = self._checkin_on_domain(cookie, cookie_idx, domain)
                self.results.append(result)

                result_message = f"结果: {result.status}"
                if result.code == CheckinStatus.SUCCESS.value:
                    if self.config.verbose:
                        result_message = f"结果: {result.status}, 获得 {result.points} 积分, 剩余 {result.days}, 总 {result.points_total}"
                    self._log(cookie_idx, domain, LogEmoji.SUCCESS, result_message, force=True)
                    # 成功即短路：该 Cookie 已签到完成，跳过其剩余域名
                    self.cookie_covered[cookie_idx] = True
                    logger.info(f"{LogEmoji.SUCCESS} Cookie {cookie_idx} 于 {domain} 签到成功，跳过该 Cookie 的后续域名。")
                    break
                elif result.code == CheckinStatus.REPEAT.value:
                    if self.config.verbose:
                        result_message = f"结果: {result.status}, 获得 {result.points} 积分, 剩余 {result.days}, 总 {result.points_total}"
                    self._log(cookie_idx, domain, LogEmoji.REPEAT, result_message, force=True)
                    # 重复签到（当日已签）视为完成，同样短路
                    self.cookie_covered[cookie_idx] = True
                    logger.info(f"{LogEmoji.REPEAT} Cookie {cookie_idx} 于 {domain} 重复签到，跳过该 Cookie 的后续域名。")
                    break
                else:
                    if result.auth_invalid:
                        cookie_auth_invalid = True
                    if self.config.verbose:
                        result_message = f"结果: {result.status}, 获得 {result.points} 积分, 剩余 {result.days}, 总 {result.points_total}"
                    self._log(cookie_idx, domain, LogEmoji.WARNING, result_message, force=True)
                    # 失败：继续执行后面的签到（下一个域名）

            if not self.cookie_covered[cookie_idx] and cookie_auth_invalid:
                self.auth_invalid_cookies.append(cookie_idx)

    def has_failure(self) -> bool:
        """是否存在整体失败的 Cookie（所有域名均失败）。存在则返回 True，供主流程决定是否以非零退出码结束。"""
        return any(not covered for covered in self.cookie_covered.values())

    def _checkin_on_domain(self, cookie: str, cookie_idx: int, domain: str) -> CheckinResult:
        result = CheckinResult(cookie_idx, domain)

        with API(domain, cookie_idx, verbose=self.config.verbose) as api:
            # 1. 优先执行签到（核心动作）
            self._log(cookie_idx, domain, LogEmoji.CHECKIN, "执行签到")
            checkin_result = api.checkin(cookie)
            result.status = checkin_result["status"]
            result.code = self._normalize_code(checkin_result.get("code", CheckinStatus.FAILURE))
            result.points = checkin_result.get("points", "0")
            result.auth_invalid = checkin_result.get("auth_invalid", False)
            result.detail = checkin_result.get("message", "")

            # 2. 仅当签到成功/重复时，才补充查询剩余天数与总积分（失败时不再浪费请求）
            if result.code in (CheckinStatus.SUCCESS.value, CheckinStatus.REPEAT.value):
                self._log(cookie_idx, domain, LogEmoji.STATUS, "查询剩余天数")
                days_str, _ = api.get_status(cookie)
                result.days = days_str

                self._log(cookie_idx, domain, LogEmoji.POINTS, "查询总积分")
                points_str, _ = api.get_points(cookie)
                result.points_total = points_str

        return result

    def get_results(self) -> List[Dict[str, str]]:
        """获取所有结果"""
        return [result.to_dict() for result in self.results]

    def format_results(self) -> Tuple[str, str, str]:
        """格式化结果"""
        results = self.get_results()

        success_count = sum(1 for r in results if r["code"] == CheckinStatus.SUCCESS.value)
        repeat_count = sum(1 for r in results if r["code"] == CheckinStatus.REPEAT.value)
        fail_count = sum(1 for r in results if r["code"] == CheckinStatus.FAILURE.value)

        title = f"GLaDOS 签到, 成功{success_count}, 失败{fail_count}, 重复{repeat_count}"

        send_content_lines = []
        log_content_lines = []
        for i, res in enumerate(results, 1):
            line = f"#{i} P:{res['points']} 剩余:{res['days']} 总积分:{res['points_total']} | {res['status']}"
            send_content_lines.append(line)

            if self.config.verbose:
                log_line = line
            else:
                log_line = f"#{i} {res['status']}"
            log_content_lines.append(log_line)

        content = "\n".join(send_content_lines)
        log_content = "\n".join(log_content_lines)

        # 若存在 Cookie 失效（鉴权失败），在推送内容中追加明确的修复指引
        if getattr(self, "auth_invalid_cookies", []):
            idx_list = ", ".join(f"#{i}" for i in self.auth_invalid_cookies)
            guidance = (
                "\n\n⚠️ 存在 Cookie 失效/无效（接口鉴权失败或本地预检未通过），请重新登录 GLaDOS / Railgun，"
                "复制【完整】Cookie（尤其是 koa:sess.sig 需完整、约 43 字符，切勿截断）后，"
                "在仓库 Settings -> Secrets -> GLADOS_COOKIES 更新。"
            )
            content += guidance
            title = f"[Cookie失效] {title} (失效: {idx_list})"

        return title, content, log_content


# 初始化日志
logger = init_logger()


def main():
    """主函数"""
    config = None
    need_push = True  # 默认异常/配置错误时推送，便于及时发现问题
    exit_code = 0
    try:
        # 1. 加载配置
        logger.info(f"{LogEmoji.START} 步骤 1: 加载配置")
        config = Config()

        if not config.cookies_list:
            logger.error(f"{LogEmoji.ERROR} 未找到有效的 Cookie, 退出程序。")
            title, content = "# 未找到 cookies!", ""
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
            logger.info(f"\n{LogEmoji.END}========== 签到总结 ==========\n{title}\n{log_content}")

            # 存在任一 Cookie 在所有域名均签到失败 -> 视为运行失败，job 以非零码退出（GitHub 会标红并邮件通知）
            if checker.has_failure():
                exit_code = 1
                logger.error(f"{LogEmoji.ERROR} 存在签到失败的账号，将以非零退出码结束，便于在 Actions 中标记失败。")
            # 仅当本次运行出现过签到失败(并因此继续执行了后续签到)才推送汇总结果；
            # 全部首次成功/重复则不通知
            need_push = any(r["code"] == CheckinStatus.FAILURE.value for r in checker.get_results())

    except Exception as e:
        logger.error(f"{LogEmoji.ERROR} 主程序执行过程中发生未预期的错误: {e}")
        title, content, log_content = "# 脚本执行出错", str(e), str(e)
        need_push = True
        exit_code = 1

    # 4. 发送推送（按需）
    logger.info(f"{LogEmoji.START} 步骤 4: 发送推送")
    push_service = PushService(config if config is not None else "")
    if need_push:
        push_service.send(title, content)
    else:
        logger.info(f"{LogEmoji.SUCCESS} 所有签到均成功（或重复），无失败，按配置跳过推送通知。")
    logger.info(f"{LogEmoji.END} 签到完成")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

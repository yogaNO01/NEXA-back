from __future__ import annotations

import json
import os
import base64
import hashlib
import hmac
import secrets
import time
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime
from typing import Annotated, Any, Literal

import pymysql
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
UPLOAD_DIR = ROOT / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
ADMIN_USERNAME = os.getenv("NEXA_ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("NEXA_ADMIN_PASSWORD", "")
ADMIN_TOKEN_SECRET = os.getenv("NEXA_ADMIN_TOKEN_SECRET", "")
ADMIN_TOKEN_TTL_SECONDS = int(os.getenv("NEXA_ADMIN_TOKEN_TTL_SECONDS", "28800"))
MYSQL = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", ""),
    "database": os.getenv("MYSQL_DATABASE", "nexa_portal"),
    "charset": "utf8mb4",
}
DEFAULT_CORS_ORIGINS = (
    "http://localhost:5175,"
    "http://127.0.0.1:5175,"
    "http://192.168.5.56:5175"
)
CORS_ORIGINS = [origin.strip() for origin in os.getenv("NEXA_CORS_ORIGINS", DEFAULT_CORS_ORIGINS).split(",") if origin.strip()]
# Development machines may be reached through different private-network adapters.
# Keep the explicit allow-list above, and allow only localhost/private LAN origins
# (with any dev-server port) through this regex.
CORS_ORIGIN_REGEX = os.getenv(
    "NEXA_CORS_ORIGIN_REGEX",
    r"^https?://(localhost|127\.0\.0\.1|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|198\.18(?:\.\d{1,3}){2})(?::\d+)?$",
)

app = FastAPI(title="NEXA Content API", version="0.1.0")
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_methods=["*"], allow_headers=["*"],
)
bearer = HTTPBearer(auto_error=False)


class Connection:
    """Small DB-API adapter preserving a concise repository layer while using MySQL."""
    def __init__(self, connection: pymysql.Connection):
        self.connection = connection

    @staticmethod
    def sql(statement: str) -> str:
        return statement.replace("?", "%s")

    def execute(self, statement: str, params: Any = ()):
        cursor = self.connection.cursor()
        cursor.execute(self.sql(statement), params)
        return cursor

    def executemany(self, statement: str, params: Any):
        cursor = self.connection.cursor()
        cursor.executemany(self.sql(statement), params)
        return cursor


@contextmanager
def db():
    connection = pymysql.connect(**MYSQL, cursorclass=pymysql.cursors.DictCursor, autocommit=False)
    try:
        yield Connection(connection)
        connection.commit()
    finally:
        connection.close()


def json_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def configured_admin_secret() -> str:
    """Return the signing secret only when token signing has been configured."""
    if not ADMIN_TOKEN_SECRET:
        raise HTTPException(503, "管理端尚未配置。请设置 NEXA_ADMIN_TOKEN_SECRET。")
    return ADMIN_TOKEN_SECRET


def issue_admin_token(username: str) -> str:
    secret = configured_admin_secret()
    payload = json_value({"sub": username, "exp": int(time.time()) + ADMIN_TOKEN_TTL_SECONDS}).encode()
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=")
    signature = hmac.new(secret.encode(), encoded, hashlib.sha256).hexdigest()
    return f"{encoded.decode()}.{signature}"


def require_admin(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> str:
    secret = configured_admin_secret()
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="请先登录管理后台", headers={"WWW-Authenticate": "Bearer"})
    try:
        encoded, signature = credentials.credentials.rsplit(".", 1)
        expected = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).hexdigest()
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        payload = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(401, "无效的管理令牌")
    username = payload.get("sub")
    if not hmac.compare_digest(signature, expected) or not isinstance(username, str) or payload.get("exp", 0) <= time.time():
        raise HTTPException(401, "管理登录已失效", headers={"WWW-Authenticate": "Bearer"})
    with db() as conn:
        exists = conn.execute("SELECT 1 FROM admin_users WHERE username=?", (username,)).fetchone()
    if not exists:
        raise HTTPException(401, "管理登录已失效", headers={"WWW-Authenticate": "Bearer"})
    return username


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"{salt.hex()}${digest.hex()}"


def password_matches(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=16384, r=8, p=1).hex()
        return hmac.compare_digest(actual, digest_hex)
    except (ValueError, TypeError):
        return False


def ensure_column(conn: Connection, table: str, column: str, definition: str) -> None:
    existing = conn.execute(
        "SELECT COUNT(*) AS total FROM information_schema.columns WHERE table_schema=? AND table_name=? AND column_name=?",
        (MYSQL["database"], table, column),
    ).fetchone()["total"]
    if not existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db() -> None:
    with db() as conn:
        statements = [
          """CREATE TABLE IF NOT EXISTS solution_groups (id BIGINT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(80) NOT NULL, sort_order INT NOT NULL DEFAULT 0, published BOOLEAN NOT NULL DEFAULT TRUE) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
          """CREATE TABLE IF NOT EXISTS solutions (id BIGINT PRIMARY KEY AUTO_INCREMENT, group_id BIGINT NOT NULL, name VARCHAR(100) NOT NULL, slug VARCHAR(100) NOT NULL UNIQUE, icon VARCHAR(100) NOT NULL DEFAULT '', cover_image VARCHAR(2048) NOT NULL DEFAULT '', summary TEXT NOT NULL, sort_order INT NOT NULL DEFAULT 0, published BOOLEAN NOT NULL DEFAULT FALSE, detail_json JSON NOT NULL, CONSTRAINT fk_solutions_group FOREIGN KEY(group_id) REFERENCES solution_groups(id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
          """CREATE TABLE IF NOT EXISTS content_items (id BIGINT PRIMARY KEY AUTO_INCREMENT, kind VARCHAR(20) NOT NULL, category VARCHAR(100), title VARCHAR(200) NOT NULL, slug VARCHAR(120) NOT NULL, summary TEXT NOT NULL, body LONGTEXT NOT NULL, image_url VARCHAR(2048) NOT NULL DEFAULT '', published_at DATETIME NULL, featured BOOLEAN NOT NULL DEFAULT FALSE, published BOOLEAN NOT NULL DEFAULT FALSE, sort_order INT NOT NULL DEFAULT 0, UNIQUE KEY uq_content_kind_slug(kind,slug)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
          """CREATE TABLE IF NOT EXISTS content_categories (id BIGINT PRIMARY KEY AUTO_INCREMENT, kind VARCHAR(20) NOT NULL, name VARCHAR(80) NOT NULL, slug VARCHAR(100) NOT NULL, sort_order INT NOT NULL DEFAULT 0, published BOOLEAN NOT NULL DEFAULT TRUE, UNIQUE KEY uq_category_kind_slug(kind,slug)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
          """CREATE TABLE IF NOT EXISTS leads (id BIGINT PRIMARY KEY AUTO_INCREMENT, company VARCHAR(200) NOT NULL, name VARCHAR(100) NOT NULL, contact VARCHAR(200) NOT NULL, type VARCHAR(100) NOT NULL, description TEXT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
          """CREATE TABLE IF NOT EXISTS tickets (id BIGINT PRIMARY KEY AUTO_INCREMENT, company VARCHAR(200) NOT NULL, name VARCHAR(100) NOT NULL, contact VARCHAR(200) NOT NULL, type VARCHAR(100) NOT NULL, level VARCHAR(50) NOT NULL DEFAULT 'P3 一般问题', description TEXT NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
          """CREATE TABLE IF NOT EXISTS admin_users (id BIGINT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(80) NOT NULL UNIQUE, password_hash VARCHAR(256) NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
          """CREATE TABLE IF NOT EXISTS content_imports (name VARCHAR(100) PRIMARY KEY, applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
        ]
        for statement in statements: conn.execute(statement)
        if conn.execute("SELECT COUNT(*) AS total FROM admin_users").fetchone()["total"] == 0 and ADMIN_USERNAME and ADMIN_PASSWORD:
            conn.execute("INSERT INTO admin_users(username,password_hash) VALUES(?,?)", (ADMIN_USERNAME, password_hash(ADMIN_PASSWORD)))
        # Keep existing installations compatible while adding workflow metadata.
        for table in ("leads", "tickets"):
            ensure_column(conn, table, "workflow_status", "VARCHAR(30) NOT NULL DEFAULT '待处理'")
            ensure_column(conn, table, "assignee", "VARCHAR(100) NOT NULL DEFAULT ''")
            ensure_column(conn, table, "notes", "TEXT NOT NULL")
            ensure_column(conn, table, "updated_at", "TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP")
        ensure_column(conn, "content_items", "published_at", "DATETIME NULL")
        ensure_column(conn, "content_items", "image_url", "VARCHAR(2048) NOT NULL DEFAULT ''")
        conn.execute("UPDATE content_items SET published_at=CURRENT_TIMESTAMP WHERE kind='news' AND published_at IS NULL")
        if conn.execute("SELECT COUNT(*) AS total FROM solution_groups").fetchone()["total"] == 0:
            conn.executemany("INSERT INTO solution_groups(name, sort_order, published) VALUES (?, ?, 1)", [("空间行业", 1), ("能源与工业", 2)])
            group_ids = {row["name"]: row["id"] for row in conn.execute("SELECT id,name FROM solution_groups")}
            seed_solutions(conn, group_ids)
        migrate_solution_architectures(conn)
        if conn.execute("SELECT COUNT(*) AS total FROM content_items").fetchone()["total"] == 0:
            seed_content(conn)
        import_reference_cases(conn)
        import_reference_news(conn)
        import_reference_news_supplement(conn)
        migrate_news_categories(conn)


def seed_solutions(conn: Connection, group_ids: dict[str, int]) -> None:
    records = [
        ("空间行业", "智慧楼宇", "building", "楼", "1486406146926-c627a92ad1ab", "设备管理、区域守护、能源监测和辅助运维的一体化楼宇方案。"),
        ("空间行业", "智慧酒店", "hotel", "酒", "1566073771259-6a8506099945", "围绕客房控制、住客体验、能耗策略与酒店运营构建一体化智慧客房方案。"),
        ("空间行业", "智慧办公", "office", "办", "1497366811353-6870744d04b2", "围绕门禁、会议、公区、用电与空间环境构建数字办公空间。"),
        ("空间行业", "智慧零售", "retail", "店", "1441986300917-64674bd600d8", "远程巡店、门店安防、数字化运营、环境与配送管理。"),
        ("空间行业", "智慧校园", "campus", "校", "1562774053-701939374585", "覆盖校园、教室、宿舍、安全和能源的多系统协同方案。"),
        ("能源与工业", "智慧节能", "energy", "能", "1473341304170-971dccb5ac1e", "用能采集、能效分析、异常预警和节能策略闭环。"),
        ("能源与工业", "智慧工业", "industry", "工", "1581091226825-a6a2a5aee158", "工业 SaaS、PaaS、设备联网、生产、质量与仓储管理。"),
        ("能源与工业", "私有云", "private-cloud", "云", "1558494949-ef010cbdcc31", "面向数据隔离和本地部署场景构建私有化智能平台。"),
        ("能源与工业", "AI 大模型", "ai", "AI", "1677442136019-21780ecad995", "面向智能硬件和行业应用提供大模型与 Copilot 能力。"),
    ]
    for order, (group, name, slug, icon, photo, summary) in enumerate(records, 1):
        cover = f"https://images.unsplash.com/{photo}?auto=format&fit=crop&w=1600&q=86"
        detail = default_detail(name, summary, cover)
        conn.execute("""INSERT INTO solutions(group_id,name,slug,icon,cover_image,summary,sort_order,published,detail_json)
        VALUES(?,?,?,?,?,?,?,1,?)""", (group_ids[group], name, slug, icon, cover, summary, order, json_value(detail)))


def default_detail(name: str, summary: str, image: str) -> dict[str, Any]:
    return {
        "hero": {"title": name, "description": summary, "image": image},
        "capabilities": [{"title": x, "text": f"围绕{name}的真实业务现场，提供可组合、可持续运营的标准能力。", "icon": f"0{i}"} for i, x in enumerate(["设备连接", "运营管理", "数据洞察", "开放集成"], 1)],
        "architecture": default_architecture(name, image),
        "advantages": ["统一数据底座", "可复制交付", "开放集成", "持续运营"],
        "scenarios": [{"name": x, "description": f"通过{x}将设备、人员与运营流程连接起来，实现可量化的业务改善。", "image": image, "features": ["实时数据", "规则联动", "告警闭环"]} for x in ["设备运营", "业务协同", "能效优化"]],
        "flow": ["需求诊断", "方案设计", "部署集成", "持续运营"],
        "faq": [{"q": "方案是否支持现有系统集成？", "a": "支持通过标准 API、协议与实施服务对接现有设备及业务系统。"}],
        "cta": {"title": f"构建可持续运营的{name}", "text": "与解决方案专家沟通项目背景、业务目标和实施节奏。", "action": "联系方案专家"},
    }


def default_architecture(name: str, image: str) -> dict[str, Any]:
    return {"title": f"{name}系统架构", "background": image, "layers": [
        {"name": "业务应用", "items": ["运营中心", "移动应用", "管理驾驶舱"]},
        {"name": "平台服务", "items": ["设备管理", "规则引擎", "数据服务", "工单"]},
        {"name": "边缘连接", "items": ["协议接入", "本地联动", "边缘计算"]},
        {"name": "现场设备", "items": ["传感器", "控制器", "网关", "业务设备"]},
    ]}


def migrate_solution_architectures(conn: Connection) -> None:
    """Persist the legacy architecture shown by the front end into solution JSON.

    Do not touch the user-created 测试222 record, nor an intentionally empty
    architecture: an empty layer list means the public page should hide it.
    """
    for row in conn.execute("SELECT id,name,cover_image,detail_json FROM solutions WHERE name<>?", ("测试222",)):
        detail = json.loads(row["detail_json"]) if isinstance(row["detail_json"], str) else row["detail_json"]
        if "architecture" not in detail:
            detail["architecture"] = default_architecture(row["name"], row["cover_image"])
            conn.execute("UPDATE solutions SET detail_json=? WHERE id=?", (json_value(detail), row["id"]))


def seed_content(conn: Connection) -> None:
    items = [
        ("news", "产品动态", "边缘协同能力升级", "edge-upgrade", "面向多现场设备连接、离线联动与远程运维，进一步提升项目交付效率。", "聚焦边缘连接、现场规则和远程运维的能力升级。", 1, 1, 1),
        ("news", "行业实践", "从设备联网到业务运营的实践路径", "operations-practice", "围绕数据、告警和工单建立持续运营的智能化基础。", "将设备数据转化为可执行的运营流程。", 1, 1, 2),
        ("cases", "智能制造", "生产设备联网与车间可视化", "factory-visibility", "统一采集设备状态、告警和能耗数据，支撑设备运维与生产分析。", "接入 PLC、传感器与产线设备，构建统一数据链路。", 1, 1, 1),
        ("cases", "商业园区", "多楼栋设备统一运营", "building-operations", "照明、空调、门禁、能耗和工单统一纳管。", "通过楼宇运营平台实现跨空间设备协同。", 1, 1, 2),
        ("help", "设备接入", "设备首次接入", "first-device", "完成产品创建、设备配网与状态上报。", "按产品创建、功能定义、配网和状态上报完成首次接入。", 1, 1, 1),
        ("help", "故障排查", "排查设备离线", "device-offline", "按网络、鉴权、日志与设备状态逐步定位问题。", "检查网络、设备证书、消息链路和日志错误码。", 1, 1, 2),
    ]
    conn.executemany("""INSERT INTO content_items(kind,category,title,slug,summary,body,featured,published,sort_order)
    VALUES(?,?,?,?,?,?,?,?,?)""", items)


def import_reference_cases(conn: Connection) -> None:
    """Import the supplied HTML project's home-page cases exactly once."""
    import_name = "project2-full-optimized-v14-cases"
    if conn.execute("SELECT 1 FROM content_imports WHERE name=?", (import_name,)).fetchone():
        return
    cases = [
        ("华东 · 智能制造", "生产设备联网与车间可视化", "factory-visibility", "接入 PLC、传感器与产线设备，统一采集状态、告警和能耗数据，支撑设备运维与生产分析。", "https://images.unsplash.com/photo-1565043666747-69f6646db940?auto=format&fit=crop&w=1600&q=86", 1),
        ("商业园区 · 楼宇", "多楼栋设备统一运营", "building-operations", "照明、空调、门禁、能耗和工单统一纳管。", "https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?auto=format&fit=crop&w=1400&q=86", 2),
        ("酒店 · 客房", "客房场景与节能联动", "hotel-guestroom", "入住、离房、睡眠等场景自动联动灯光、空调与服务。", "https://images.unsplash.com/photo-1611892440504-42a792e24d32?auto=format&fit=crop&w=1400&q=86", 3),
    ]
    for category, title, slug, summary, image_url, sort_order in cases:
        conn.execute("""INSERT INTO content_items(kind,category,title,slug,summary,body,image_url,featured,published,sort_order)
        VALUES('cases',?,?,?,?,?,?,1,1,?)
        ON DUPLICATE KEY UPDATE category=VALUES(category),title=VALUES(title),summary=VALUES(summary),body=VALUES(body),image_url=VALUES(image_url),featured=1,published=1,sort_order=VALUES(sort_order)""", (category, title, slug, summary, summary, image_url, sort_order))
    conn.execute("INSERT INTO content_imports(name) VALUES(?)", (import_name,))


def import_reference_news(conn: Connection) -> None:
    """Import the three news stories and matching visuals from the HTML reference once."""
    import_name = "project2-full-optimized-v14-news-v2"
    if conn.execute("SELECT 1 FROM content_imports WHERE name=?", (import_name,)).fetchone():
        return
    # Replace only the original placeholder news seeded by this project; do not
    # touch news created by an editor.
    conn.execute("DELETE FROM content_items WHERE kind='news' AND slug IN ('edge-upgrade','operations-practice')")
    news = [
        ("产品", "边缘网关 3.2 正式上线，新增断网续传与批量配置", "edge-gateway-3-2", "面向楼宇和工业现场优化弱网环境下的数据采集与远程运维。", "2026-09-05 09:00:00", "https://images.unsplash.com/photo-1558494949-ef010cbdcc31?auto=format&fit=crop&w=1400&q=86", 1),
        ("项目", "某连锁酒店客房智能化项目完成首批门店交付", "hotel-rollout", "覆盖客控、空调、门锁状态与能耗策略，统一接入运营平台。", "2026-08-21 09:00:00", "https://images.unsplash.com/photo-1611892440504-42a792e24d32?auto=format&fit=crop&w=1400&q=86", 2),
        ("技术", "设备日志与告警中心完成版本升级", "device-log-upgrade", "新增错误聚合、设备链路追踪和批量诊断能力。", "2026-08-03 09:00:00", "https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=1400&q=86", 3),
    ]
    for category, title, slug, summary, published_at, image_url, sort_order in news:
        conn.execute("""INSERT INTO content_items(kind,category,title,slug,summary,body,image_url,published_at,featured,published,sort_order)
        VALUES('news',?,?,?,?,?,?,?,1,1,?)
        ON DUPLICATE KEY UPDATE category=VALUES(category),title=VALUES(title),summary=VALUES(summary),body=VALUES(body),image_url=VALUES(image_url),published_at=VALUES(published_at),featured=1,published=1,sort_order=VALUES(sort_order)""", (category, title, slug, summary, summary, image_url, published_at, sort_order))
    conn.execute("INSERT INTO content_imports(name) VALUES(?)", (import_name,))


def import_reference_news_supplement(conn: Connection) -> None:
    """Add the fourth latest-news item shown in the HTML reference's sidebar."""
    import_name = "project2-full-optimized-v14-news-supplement"
    if conn.execute("SELECT 1 FROM content_imports WHERE name=?", (import_name,)).fetchone():
        return
    conn.execute("""INSERT INTO content_items(kind,category,title,slug,summary,body,image_url,published_at,featured,published,sort_order)
    VALUES('news',?,?,?,?,?,?,?,1,1,4)
    ON DUPLICATE KEY UPDATE category=VALUES(category),title=VALUES(title),summary=VALUES(summary),body=VALUES(body),image_url=VALUES(image_url),published_at=VALUES(published_at),featured=1,published=1,sort_order=4""", (
        "行业实践", "从设备联网到生产分析：制造现场如何构建可持续运营的数据链路", "manufacturing-data-link",
        "围绕设备接入、边缘计算、告警与运维建立统一技术底座。", "围绕设备接入、边缘计算、告警与运维建立统一技术底座。",
        "https://images.unsplash.com/photo-1565043666747-69f6646db940?auto=format&fit=crop&w=1400&q=86", "2026-07-18 09:00:00",
    ))
    conn.execute("INSERT INTO content_imports(name) VALUES(?)", (import_name,))


def migrate_news_categories(conn: Connection) -> None:
    """Create category records for every existing named news category once."""
    known_names = {row["name"] for row in conn.execute("SELECT name FROM content_categories WHERE kind='news'")}
    known_slugs = {row["slug"] for row in conn.execute("SELECT slug FROM content_categories WHERE kind='news'")}
    names = [row["category"].strip() for row in conn.execute("SELECT DISTINCT category FROM content_items WHERE kind='news' AND category IS NOT NULL AND TRIM(category)<>'' ORDER BY category")]
    next_number = 1
    for name in names:
        if name in known_names:
            continue
        slug = f"news-category-{next_number}"
        while slug in known_slugs:
            next_number += 1
            slug = f"news-category-{next_number}"
        conn.execute("INSERT INTO content_categories(kind,name,slug,sort_order,published) VALUES(?,?,?,?,1)", ("news", name, slug, next_number))
        known_names.add(name)
        known_slugs.add(slug)
        next_number += 1


class GroupInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    sort_order: int = 0
    published: bool = True


class SolutionInput(BaseModel):
    group_id: int
    name: str = Field(min_length=1, max_length=100)
    slug: str = Field(pattern=r"^[a-z0-9-]+$")
    icon: str = ""
    cover_image: str = ""
    summary: str = ""
    sort_order: int = 0
    published: bool = False
    detail: dict[str, Any] = Field(default_factory=dict)


class ContentInput(BaseModel):
    category: str | None = None
    title: str = Field(min_length=1)
    slug: str = Field(pattern=r"^[a-z0-9-]+$")
    summary: str = ""
    body: str = ""
    image_url: str = Field(default="", max_length=2048)
    published_at: datetime | None = None
    featured: bool = False
    published: bool = False
    sort_order: int = 0


class CategoryInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    slug: str = Field(pattern=r"^[a-z0-9-]+$")
    sort_order: int = 0
    published: bool = True


class LeadInput(BaseModel):
    company: str = Field(min_length=1)
    name: str = Field(min_length=1)
    contact: str = Field(min_length=1)
    type: str = Field(min_length=1)
    description: str = Field(min_length=1)


class TicketInput(LeadInput):
    level: str = "P3 一般问题"


class LoginInput(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class AdminUserInput(LoginInput):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)


class PasswordChangeInput(BaseModel):
    current_password: str | None = Field(default=None, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class WorkflowInput(BaseModel):
    workflow_status: Literal["待处理", "处理中", "已完成"]
    assignee: str = Field(default="", max_length=100)
    notes: str = ""


def solution_from_row(row: dict[str, Any], full: bool = False) -> dict[str, Any]:
    data = dict(row)
    data["published"] = bool(data["published"])
    data["group_id"] = data.pop("group_id")
    if full:
        detail = data.pop("detail_json")
        data.update(json.loads(detail) if isinstance(detail, str) else detail)
    else:
        data.pop("detail_json", None)
    return data


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/api/public/solutions/navigation")
def public_solution_navigation() -> list[dict[str, Any]]:
    with db() as conn:
        groups = conn.execute("SELECT * FROM solution_groups WHERE published=1 ORDER BY sort_order,id").fetchall()
        return [{"id": group["id"], "name": group["name"], "order": group["sort_order"], "solutions": [solution_from_row(row) for row in conn.execute("SELECT * FROM solutions WHERE group_id=? AND published=1 ORDER BY sort_order,id", (group["id"],))]} for group in groups]


@app.get("/api/public/solutions")
def public_solutions(limit: Annotated[int | None, Query(ge=1, le=100)] = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM solutions WHERE published=1 ORDER BY sort_order,id"
    params: tuple[Any, ...] = () if limit is None else (limit,)
    if limit is not None: query += " LIMIT ?"
    with db() as conn:
        return [solution_from_row(row) for row in conn.execute(query, params)]


@app.get("/api/public/solutions/{slug}")
def public_solution_detail(slug: str) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM solutions WHERE slug=? AND published=1", (slug,)).fetchone()
    if not row: raise HTTPException(status_code=404, detail="方案不存在或未发布")
    return solution_from_row(row, full=True)


@app.post("/api/leads", status_code=status.HTTP_201_CREATED)
def create_lead(payload: LeadInput) -> dict[str, int]:
    with db() as conn:
        cursor = conn.execute(
            "INSERT INTO leads(company,name,contact,type,description,workflow_status,assignee,notes) VALUES(?,?,?,?,?,?,?,?)",
            (payload.company, payload.name, payload.contact, payload.type, payload.description, "待处理", "", ""),
        )
        return {"id": cursor.lastrowid}


@app.post("/api/tickets", status_code=status.HTTP_201_CREATED)
def create_ticket(payload: TicketInput) -> dict[str, int]:
    with db() as conn:
        cursor = conn.execute(
            "INSERT INTO tickets(company,name,contact,type,level,description,workflow_status,assignee,notes) VALUES(?,?,?,?,?,?,?,?,?)",
            (payload.company, payload.name, payload.contact, payload.type, payload.level, payload.description, "待处理", "", ""),
        )
        return {"id": cursor.lastrowid}


@app.post("/api/admin/auth/login")
def admin_login(payload: LoginInput) -> dict[str, Any]:
    configured_admin_secret()
    with db() as conn:
        user = conn.execute("SELECT username,password_hash FROM admin_users WHERE username=?", (payload.username,)).fetchone()
    if not user or not password_matches(payload.password, user["password_hash"]):
        raise HTTPException(401, "用户名或密码不正确")
    return {"access_token": issue_admin_token(user["username"]), "token_type": "bearer", "expires_in": ADMIN_TOKEN_TTL_SECONDS}


@app.get("/api/admin/users", dependencies=[Depends(require_admin)])
def list_admin_users() -> list[dict[str, Any]]:
    with db() as conn:
        return [dict(row) for row in conn.execute("SELECT id,username,created_at,updated_at FROM admin_users ORDER BY id")]


@app.post("/api/admin/users", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
def create_admin_user(payload: AdminUserInput) -> dict[str, int]:
    with db() as conn:
        try:
            cursor = conn.execute("INSERT INTO admin_users(username,password_hash) VALUES(?,?)", (payload.username, password_hash(payload.password)))
        except pymysql.err.IntegrityError:
            raise HTTPException(409, "该用户名已存在")
        return {"id": cursor.lastrowid}


@app.put("/api/admin/users/{username}/password")
def change_admin_password(username: str, payload: PasswordChangeInput, current_user: str = Depends(require_admin)) -> dict[str, bool]:
    with db() as conn:
        target = conn.execute("SELECT password_hash FROM admin_users WHERE username=?", (username,)).fetchone()
        if not target:
            raise HTTPException(404, "管理员账号不存在")
        if username == current_user and not payload.current_password:
            raise HTTPException(400, "请填写当前密码")
        if payload.current_password and username == current_user and not password_matches(payload.current_password, target["password_hash"]):
            raise HTTPException(400, "当前密码不正确")
        conn.execute("UPDATE admin_users SET password_hash=? WHERE username=?", (password_hash(payload.new_password), username))
    return {"ok": True}


@app.delete("/api/admin/users/{username}", status_code=status.HTTP_204_NO_CONTENT)
def delete_admin_user(username: str, current_user: str = Depends(require_admin)) -> None:
    if username == current_user:
        raise HTTPException(400, "不能删除当前登录账号")
    with db() as conn:
        count = conn.execute("SELECT COUNT(*) AS total FROM admin_users").fetchone()["total"]
        if count <= 1:
            raise HTTPException(400, "至少需要保留一个管理员账号")
        changed = conn.execute("DELETE FROM admin_users WHERE username=?", (username,)).rowcount
    if not changed:
        raise HTTPException(404, "管理员账号不存在")


@app.post("/api/admin/uploads", dependencies=[Depends(require_admin)])
async def upload_image(file: UploadFile = File(...)) -> dict[str, str]:
    if file.content_type not in {"image/jpeg", "image/png", "image/webp", "image/gif"}:
        raise HTTPException(415, "仅支持 JPG、PNG、WebP 或 GIF 图片")
    content = await file.read()
    if not content or len(content) > 10 * 1024 * 1024:
        raise HTTPException(413, "图片不能为空且不能超过 10MB")
    suffix = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/gif": ".gif"}[file.content_type]
    name = f"{int(time.time())}-{secrets.token_hex(8)}{suffix}"
    (UPLOAD_DIR / name).write_bytes(content)
    return {"url": f"/uploads/{name}"}


@app.get("/api/admin/solution-groups", dependencies=[Depends(require_admin)])
def admin_groups() -> list[dict[str, Any]]:
    with db() as conn: return [{**dict(row), "published": bool(row["published"])} for row in conn.execute("SELECT * FROM solution_groups ORDER BY sort_order,id")]


@app.post("/api/admin/solution-groups", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
def create_group(payload: GroupInput) -> dict[str, int]:
    with db() as conn:
        cursor = conn.execute("INSERT INTO solution_groups(name,sort_order,published) VALUES(?,?,?)", (payload.name, payload.sort_order, payload.published))
        return {"id": cursor.lastrowid}


@app.put("/api/admin/solution-groups/{group_id}", dependencies=[Depends(require_admin)])
def update_group(group_id: int, payload: GroupInput) -> dict[str, bool]:
    with db() as conn:
        changed = conn.execute("UPDATE solution_groups SET name=?,sort_order=?,published=? WHERE id=?", (payload.name, payload.sort_order, payload.published, group_id)).rowcount
    if not changed: raise HTTPException(404, "二级标题不存在")
    return {"ok": True}


@app.delete("/api/admin/solution-groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin)])
def delete_group(group_id: int) -> None:
    with db() as conn:
        count = conn.execute("SELECT COUNT(*) AS total FROM solutions WHERE group_id=?", (group_id,)).fetchone()["total"]
        if count:
            raise HTTPException(409, "该二级标题仍包含方案，无法删除")
        changed = conn.execute("DELETE FROM solution_groups WHERE id=?", (group_id,)).rowcount
    if not changed:
        raise HTTPException(404, "二级标题不存在")


@app.get("/api/admin/solutions", dependencies=[Depends(require_admin)])
def admin_solutions() -> list[dict[str, Any]]:
    with db() as conn: return [solution_from_row(row, full=True) for row in conn.execute("SELECT * FROM solutions ORDER BY sort_order,id")]


def save_solution(payload: SolutionInput, solution_id: int | None = None) -> dict[str, Any]:
    # The admin may submit only the blocks it exposes as structured fields.
    # Keep all other detail-page blocks available by filling them from defaults.
    detail = {**default_detail(payload.name, payload.summary, payload.cover_image), **(payload.detail or {})}
    faq = detail.get("faq") if isinstance(detail, dict) else None
    if faq is not None and (
        not isinstance(faq, list)
        or any(not isinstance(item, dict) or not str(item.get("q", "")).strip() or not str(item.get("a", "")).strip() for item in faq)
    ):
        raise HTTPException(422, "每条常见问题的问题和答案都不能为空")
    with db() as conn:
        if solution_id is None:
            cursor = conn.execute("""INSERT INTO solutions(group_id,name,slug,icon,cover_image,summary,sort_order,published,detail_json)
            VALUES(?,?,?,?,?,?,?,?,?)""", (payload.group_id,payload.name,payload.slug,payload.icon,payload.cover_image,payload.summary,payload.sort_order,payload.published,json_value(detail)))
            return {"id": cursor.lastrowid}
        changed = conn.execute("""UPDATE solutions SET group_id=?,name=?,slug=?,icon=?,cover_image=?,summary=?,sort_order=?,published=?,detail_json=? WHERE id=?""", (payload.group_id,payload.name,payload.slug,payload.icon,payload.cover_image,payload.summary,payload.sort_order,payload.published,json_value(detail),solution_id)).rowcount
        # MySQL reports 0 affected rows when an existing record is saved without
        # changing any values. Check existence separately before treating it as 404.
        exists = changed or conn.execute("SELECT 1 FROM solutions WHERE id=?", (solution_id,)).fetchone()
    if not exists: raise HTTPException(404, "行业方案不存在")
    return {"ok": True}


@app.post("/api/admin/solutions", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
def create_solution(payload: SolutionInput) -> dict[str, Any]: return save_solution(payload)


@app.put("/api/admin/solutions/{solution_id}", dependencies=[Depends(require_admin)])
def update_solution(solution_id: int, payload: SolutionInput) -> dict[str, Any]: return save_solution(payload, solution_id)


@app.delete("/api/admin/solutions/{solution_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin)])
def delete_solution(solution_id: int) -> None:
    with db() as conn: changed = conn.execute("DELETE FROM solutions WHERE id=?", (solution_id,)).rowcount
    if not changed: raise HTTPException(404, "行业方案不存在")


@app.get("/api/admin/leads", dependencies=[Depends(require_admin)])
def admin_leads() -> list[dict[str, Any]]:
    with db() as conn: return [dict(row) for row in conn.execute("SELECT * FROM leads ORDER BY id DESC")]


@app.get("/api/admin/tickets", dependencies=[Depends(require_admin)])
def admin_tickets() -> list[dict[str, Any]]:
    with db() as conn: return [dict(row) for row in conn.execute("SELECT * FROM tickets ORDER BY id DESC")]


def content_from_row(row: dict[str, Any]) -> dict[str, Any]:
    data = dict(row); data["featured"] = bool(data["featured"]); data["published"] = bool(data["published"]); return data


@app.get("/api/admin/{kind}", dependencies=[Depends(require_admin)])
def admin_content(kind: Literal["news", "cases", "help"]) -> list[dict[str, Any]]:
    with db() as conn: return [content_from_row(row) for row in conn.execute("SELECT * FROM content_items WHERE kind=? ORDER BY sort_order,id", (kind,))]


@app.post("/api/admin/{kind}", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
def create_content(kind: Literal["news", "cases", "help"], payload: ContentInput) -> dict[str, int]:
    with db() as conn:
        cursor = conn.execute("INSERT INTO content_items(kind,category,title,slug,summary,body,image_url,published_at,featured,published,sort_order) VALUES(?,?,?,?,?,?,?,?,?,?,?)", (kind,payload.category,payload.title,payload.slug,payload.summary,payload.body,payload.image_url,payload.published_at if kind == "news" else None,payload.featured,payload.published,payload.sort_order))
        return {"id": cursor.lastrowid}


@app.put("/api/admin/{kind}/{item_id}", dependencies=[Depends(require_admin)])
def update_content(kind: Literal["news", "cases", "help"], item_id: int, payload: ContentInput) -> dict[str, bool]:
    with db() as conn:
        changed = conn.execute("""UPDATE content_items SET category=?,title=?,slug=?,summary=?,body=?,image_url=?,published_at=?,featured=?,published=?,sort_order=?
        WHERE id=? AND kind=?""", (payload.category,payload.title,payload.slug,payload.summary,payload.body,payload.image_url,payload.published_at if kind == "news" else None,payload.featured,payload.published,payload.sort_order,item_id,kind)).rowcount
    if not changed: raise HTTPException(404, "内容不存在")
    return {"ok": True}


@app.delete("/api/admin/{kind}/{item_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin)])
def delete_record(kind: Literal["news", "cases", "help", "leads", "tickets"], item_id: int) -> None:
    with db() as conn:
        if kind in {"leads", "tickets"}:
            changed = conn.execute(f"DELETE FROM {kind} WHERE id=?", (item_id,)).rowcount
        else:
            changed = conn.execute("DELETE FROM content_items WHERE id=? AND kind=?", (item_id, kind)).rowcount
    if not changed:
        raise HTTPException(404, "记录不存在")


@app.get("/api/admin/categories/{kind}/items", dependencies=[Depends(require_admin)])
def admin_categories(kind: Literal["news", "help"]) -> list[dict[str, Any]]:
    with db() as conn:
        return [{**dict(row), "published": bool(row["published"])} for row in conn.execute("SELECT * FROM content_categories WHERE kind=? ORDER BY sort_order,id", (kind,))]


@app.post("/api/admin/categories/{kind}/items", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
def create_category(kind: Literal["news", "help"], payload: CategoryInput) -> dict[str, int]:
    with db() as conn:
        cursor = conn.execute("INSERT INTO content_categories(kind,name,slug,sort_order,published) VALUES(?,?,?,?,?)", (kind,payload.name,payload.slug,payload.sort_order,payload.published))
        return {"id": cursor.lastrowid}


@app.put("/api/admin/categories/{kind}/items/{category_id}", dependencies=[Depends(require_admin)])
def update_category(kind: Literal["news", "help"], category_id: int, payload: CategoryInput) -> dict[str, bool]:
    with db() as conn:
        changed = conn.execute("UPDATE content_categories SET name=?,slug=?,sort_order=?,published=? WHERE id=? AND kind=?", (payload.name,payload.slug,payload.sort_order,payload.published,category_id,kind)).rowcount
    if not changed: raise HTTPException(404, "分类不存在")
    return {"ok": True}


@app.delete("/api/admin/categories/{kind}/items/{category_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin)])
def delete_category(kind: Literal["news", "help"], category_id: int) -> None:
    with db() as conn: changed = conn.execute("DELETE FROM content_categories WHERE id=? AND kind=?", (category_id, kind)).rowcount
    if not changed: raise HTTPException(404, "分类不存在")


@app.get("/api/public/{kind}")
def public_content(kind: Literal["news", "cases", "help"], featured: bool = False, q: str | None = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM content_items WHERE kind=? AND published=1"
    params: list[Any] = [kind]
    if featured:
        query += " AND featured=1"
    if q:
        query += " AND (title LIKE ? OR summary LIKE ? OR body LIKE ?)"
        params.extend([f"%{q}%"] * 3)
    query += " ORDER BY sort_order,id"
    with db() as conn: return [content_from_row(row) for row in conn.execute(query, params)]


@app.get("/api/public/{kind}/{slug}")
def public_content_detail(kind: Literal["news", "cases", "help"], slug: str) -> dict[str, Any]:
    with db() as conn: row = conn.execute("SELECT * FROM content_items WHERE kind=? AND slug=? AND published=1", (kind,slug)).fetchone()
    if not row: raise HTTPException(404, "内容不存在或未发布")
    return content_from_row(row)


@app.put("/api/admin/{kind}/{item_id}/workflow", dependencies=[Depends(require_admin)])
def update_submission_workflow(kind: Literal["leads", "tickets"], item_id: int, payload: WorkflowInput) -> dict[str, bool]:
    with db() as conn:
        changed = conn.execute(
            f"UPDATE {kind} SET workflow_status=?,assignee=?,notes=? WHERE id=?",
            (payload.workflow_status, payload.assignee, payload.notes, item_id),
        ).rowcount
    if not changed:
        raise HTTPException(404, "提交记录不存在")
    return {"ok": True}

# NEXA Python API

轻量的 FastAPI + MySQL 后端，仅管理运营内容和提交数据，不包含通用页面搭建器。

```bash
cd /Users/zhangmingchun/Documents/web/backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

创建 `.env`（或在运行环境中提供同名变量）：

```bash
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=nexa
MYSQL_PASSWORD=change-me
MYSQL_DATABASE=nexa_portal
NEXA_ADMIN_TOKEN_SECRET=replace-with-a-random-32-byte-or-longer-secret
NEXA_ADMIN_TOKEN_TTL_SECONDS=28800
# 首次启动时可选：用于创建第一个数据库管理员账号。
NEXA_ADMIN_USERNAME=admin
NEXA_ADMIN_PASSWORD=replace-with-a-long-unique-password
```

应用启动时会连接已存在的 MySQL 数据库并初始化表结构。生产环境由运维预先建库，并仅向应用账号授予该目标库权限。

本地没有 MySQL 时，先使用随项目提供的配置启动：

```bash
cp .env.example .env
docker compose up -d mysql
```

前端设置 `VITE_API_BASE_URL=http://localhost:8000` 后即可调用。

公开接口：

- `GET /api/public/solutions/navigation`
- `GET /api/public/solutions?limit=8`
- `GET /api/public/solutions/{slug}`
- `POST /api/leads`
- `POST /api/tickets`
- `GET /api/public/news?featured=true`
- `GET /api/public/cases?featured=true`
- `GET /api/public/help?q=关键词`

运营端接口统一位于 `/api/admin`，包含解决方案分组、方案、新闻、案例、帮助文章以及线索/工单处理。所有运营接口（含图片上传）均要求 Bearer 管理员令牌。管理员账号保存在 MySQL 的 `admin_users` 表中，密码采用 scrypt 哈希存储；首次启动时，若表中没有账号且配置了 `NEXA_ADMIN_USERNAME`、`NEXA_ADMIN_PASSWORD`，系统会创建首个管理员。之后可在运营后台的“账号管理”中创建账号、修改或重置密码。

图片上传接口为 `POST /api/admin/uploads`，仅接受不超过 10MB 的 JPG、PNG、WebP、GIF 文件，文件保存在 `backend/uploads/` 并由 `/uploads/` 提供访问。生产环境请将此目录挂载到持久化卷或对象存储。

## 生产部署检查

- 使用独立 MySQL 应用账号，仅授予 `nexa_portal` 所需权限；不要使用 root。
- 通过反向代理将前端静态文件和 API 分域或分路径暴露，设置生产环境 `VITE_API_BASE_URL`。
- 设置强随机的 `NEXA_ADMIN_TOKEN_SECRET` 与管理员密码，HTTPS 下访问后台。
- 定期备份 MySQL 与 `uploads/`，并收集 Uvicorn/反向代理错误日志。

可从 `deploy/nginx.conf.example` 复制反向代理配置；它同时覆盖 `/api/`、上传文件和 React Hash 路由的静态站点回退。

分类接口使用 `/api/admin/categories/{news|help}/items`，避免和内容按 ID 编辑路由发生匹配冲突。

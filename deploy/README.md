# NEXA Docker 部署

此配置假定三个 Git 仓库在服务器上是同级目录：

```text
/srv/nexa/
├── front/
├── admin/
└── backend/
    └── deploy/
```

## 首次部署

1. 在服务器的 `/srv/nexa` 克隆 `front`、`admin`、`backend` 三个仓库。
2. 进入 `backend/deploy`，复制环境变量模板并填写强密码：

   ```bash
   cd /srv/nexa/backend/deploy
   cp .env.example .env
   chmod 600 .env
   nano .env
   ```

   `NEXA_ADMIN_USERNAME` 与 `NEXA_ADMIN_PASSWORD` 仅用于首次创建管理员。
   不要提交 `.env`，也不要把它发送给任何人。

3. 先验证配置，再构建并启动：

   ```bash
   docker compose --env-file .env -f compose.production.yml config
   docker compose --env-file .env -f compose.production.yml build --pull
   docker compose --env-file .env -f compose.production.yml up -d
   docker compose --env-file .env -f compose.production.yml ps
   ```

4. 在局域网浏览器访问：

   ```text
   http://<服务器IP>/       公开前台
   http://<服务器IP>:8080/  管理后台
   ```

## 服务边界

- `public` 仅发布宿主机 `80` 端口。
- `admin` 仅发布宿主机 `8080` 端口。
- `api` 和 `mysql` 没有 `ports`，只能由 Docker 网络中的前后台容器访问。
- MySQL 数据和后端上传文件存于命名卷，普通的 `up -d`、重建镜像和重启容器不会清除它们。

不要执行 `docker compose down -v`，其中的 `-v` 会删除数据库和上传文件卷。

## 日常更新

在三个仓库都推送了新提交后：

```bash
cd /srv/nexa/front && git pull
cd /srv/nexa/admin && git pull
cd /srv/nexa/backend && git pull
cd /srv/nexa/backend/deploy
docker compose --env-file .env -f compose.production.yml build
docker compose --env-file .env -f compose.production.yml up -d
```

## 排错

```bash
cd /srv/nexa/backend/deploy
docker compose --env-file .env -f compose.production.yml ps
docker compose --env-file .env -f compose.production.yml logs --tail=100 api
docker compose --env-file .env -f compose.production.yml logs --tail=100 public
docker compose --env-file .env -f compose.production.yml logs --tail=100 admin
```

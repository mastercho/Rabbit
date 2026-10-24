# Rabbit install and upgrade

## Requirements

- Docker Engine or Docker Desktop, and Docker Compose v2 (`docker compose version` works)
- Git, and a network that can reach GitHub or GHCR and the model service
- A GLM-5.3 key, or another OpenAI-compatible model key
- A working Docker daemon. The dispatcher mounts the Docker socket to start task containers, so run this only on a host you trust

The web service binds `127.0.0.1:8000` by default. For remote access, put your own reverse proxy and access control in front of it.

## First install of v0.3.1

```bash
git clone https://github.com/Rabbit0007/Rabbit.git
cd Rabbit
git checkout v0.3.1
cp .env.example .env
cp dispatch.yaml dispatch.local.yaml
chmod 600 .env dispatch.local.yaml
```

Edit `.env` and set a different random value for each of the three service tokens. `openssl rand -hex 32` is fine. Do not put the model key in `.env`.

```dotenv
CAIRN_INTERNAL_TOKEN=<random value A>
CAIRN_DISPATCHER_INTERNAL_TOKEN=<random value B>
CAIRN_WORKER_EGRESS_PROXY_TOKEN=<random value C>
```

Edit `dispatch.local.yaml` and replace `PI_API_KEY: replace-with-your-model-api-key` with your model key. The four workers share a YAML anchor, so change it once in the first worker's `env`. If you change models, also update `PI_MODEL`, `PI_BASE_URL`, and `PI_PROVIDER_API`.

Git ignores `dispatch.local.yaml` and `.env`. Do not upload them to a public repository or attach them to a ticket. If a container cannot reach the Server, check that `TSEC_SERVER_HOST` in the local config is an address the task container can actually use. Addresses between Compose services should stay as configured. Do not casually change `server: http://rabbit-pentest-server:8000`.

```bash
docker compose config -q
docker build --platform linux/amd64 -f container/Dockerfile.pi -t rabbit-pentest-worker:pi-0.84.4 .
docker compose up -d --build
docker compose ps
```

Open `http://127.0.0.1:8000/` in a browser and register the first account. Follow startup logs with `docker compose logs -f pentest-server pentest-dispatcher`. The first build downloads Node, Python dependencies, and the worker image. How long that takes depends on the network.

The image build runs `npm ci` and `npm run build`. The host does not need Node. On Docker Desktop, allow access to the project directory and make sure the daemon can start task containers.

## Upgrade an existing checkout

1. Stop running projects. Record `docker compose ps` and the local `git status`. Before upgrading, back up `datas/cairn/`, the Docker volume `rabbit-pentest-artifacts`, `.env`, and the local worker config.
2. If the model key was written directly into the tracked `dispatch.yaml`, copy it to `dispatch.local.yaml` first. Confirm Git ignores that file and the contents are right. Do not commit the key.
3. After you have saved or discarded other local uncommitted changes, run `git fetch --tags origin` and `git checkout v0.3.1`. Compare `.env.example` with your `.env` and confirm all three service tokens are set.
4. Run `docker compose up -d --build`, then check `docker compose ps`, sign in in the browser, and run a worker connectivity test.

An upgrade does not delete `datas/cairn/` or named volumes. Do not run `docker compose down -v` unless you intend to wipe persistent data.

## Day to day

```bash
docker compose ps
docker compose logs -f pentest-server pentest-dispatcher
docker compose down
```

The Server database is `./datas/cairn/`. Some runtime evidence is in the Docker volume `rabbit-pentest-artifacts`. Worker configuration is `dispatch.local.yaml`. Changes made on the Workers page are written to that local file. After frontend or backend source changes, run `docker compose up -d --build` again.

## Common problems

- **The page has no styles or scripts.** Rebuild the image with the v0.3.1 Dockerfile. This version builds the frontend static assets during the image build.
- **A worker test fails.** Check the model key, model name, and base URL. Confirm the task container can reach the Server named by `TSEC_SERVER_HOST`. A down model service does not stop the web page from starting.
- **The stack will not start.** Check `docker compose config -q`, `docker compose ps`, and the service logs. Confirm port 8000 is free.
- **A local config change has no effect.** Compose mounts `dispatch.local.yaml` by default. To use another file, set `CAIRN_DISPATCH_CONFIG` to a config file name inside the repository root.

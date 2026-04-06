# MCP Authorization Demo

This repository now uses a split deployment model:

- `server/` contains the Go backend, including the MCP client integration, OAuth-based MCP server onboarding, websocket chat, and Postgres persistence.
- `client/` contains a separate Next.js application that talks to the backend over JSON APIs and a websocket.

## What The App Does

The backend:

- authenticates browser users with bearer sessions
- stores users, sessions, conversations, messages, MCP connections, OAuth state, and tokens in Postgres
- discovers protected MCP servers through `WWW-Authenticate` + protected resource metadata
- performs OAuth authorization code flow with PKCE
- attempts OAuth dynamic client registration when the authorization server exposes a registration endpoint
- uses the MCP Go SDK to list and call tools from remote MCP servers
- uses the OpenAI Go SDK Responses API to run a chat loop that can invoke MCP tools

The frontend:

- logs into the backend
- creates and re-authorizes MCP connections
- opens the OAuth popup flow when a protected MCP server needs user approval
- sends chat prompts through a websocket and renders persisted conversation history

## Repository Layout

```text
.
├── client/   # Next.js app + client Dockerfile
├── server/   # Go module + server Dockerfile
├── .env.example
├── docker-compose.yml
└── spec.md
```

## Containerized Setup

### 1. Configure The Stack

```bash
cp .env.example .env
```

Set `OPENAI_API_KEY` in `.env`.

The default compose configuration publishes:

- Client: `http://localhost:3000`
- Server API: `http://localhost:8080`
- Postgres: `localhost:5432`

The default stack also sets `RESET_DATABASE_ON_FIRST_START=true`, which drops and recreates the target application database once per Postgres volume before migrations run. That reset marker is stored in the cluster's `postgres` database, so normal container restarts do not wipe data again.

If you need different public URLs for the browser or OAuth callback flow, update these values in `.env` before building:

- `APP_PUBLIC_BASE_URL`
- `CLIENT_APP_URL`
- `ALLOWED_ORIGINS`
- `NEXT_PUBLIC_API_BASE_URL`
- `NEXT_PUBLIC_WS_BASE_URL`

### 2. Build And Start Everything

```bash
docker compose up --build
```

The server container runs its one-time first-start reset (when enabled) and then database migrations on startup, so no separate bootstrap step is required.

### 3. Stop The Stack

```bash
docker compose down
```

To also remove the Postgres volume:

```bash
docker compose down -v
```

## Local Source Setup

### 1. Start Postgres

```bash
docker compose up -d postgres
```

### 2. Configure The Backend

```bash
cd server
cp .env.example .env
```

Set `OPENAI_API_KEY` before starting the backend.

If you want the local backend to start from a clean database once, leave `RESET_DATABASE_ON_FIRST_START=true` in `server/.env`. Set it to `false` after that if you do not want new environments to auto-reset on first boot.

### 3. Configure The Client

```bash
cd client
cp .env.local.example .env.local
```

### 4. Start The Backend

```bash
cd server
go run ./cmd/mcp-auth-server
```

### 5. Start The Client

```bash
cd client
npm install
npm run dev
```

The default URLs are:

- Client: `http://localhost:3000`
- Server API: `http://localhost:8080`

For local source runs, the example env files are:

- `server/.env.example`
- `client/.env.local.example`

## Connecting To A Remote MCP Server

The app expects a remote HTTP MCP endpoint, typically something like `https://example.com/mcp`.

When you add a connection:

1. The backend probes the MCP endpoint.
2. If the MCP server responds with `401 Unauthorized` and advertises OAuth protected resource metadata, the backend follows the MCP authorization flow.
3. If the authorization server supports dynamic client registration, the backend registers itself automatically.
4. The browser opens an authorization popup.
5. After the callback returns to the backend, the connection is verified by listing tools over the MCP Go SDK.

If a server is public, the backend skips OAuth and verifies the connection immediately.

## Google Calendar-Style Example

For a Google Calendar workflow, the easiest path is to deploy a Google Workspace-compatible MCP server behind HTTPS and then point this app at that remote endpoint.

Relevant upstream references:

- Google’s official MCP repository documents Google-managed remote servers and Google Cloud deployment guidance for Google-owned/open-source MCP servers: `https://github.com/google/mcp`
- The official MCP servers index tracks community Google Calendar servers if you want a Calendar-specific implementation to deploy: `https://github.com/modelcontextprotocol/servers`

Important constraint: many Google Calendar MCP servers in the ecosystem are local desktop or stdio-first servers. This demo backend is built around remote HTTP MCP endpoints, because the authorization flow in the MCP spec applies to HTTP transports.

## Verification Notes

This workspace does not have outbound package-manager access, so dependency installation and full build verification were not possible in-session. The codebase is scaffolded to the requested architecture, but you should expect to run:

```bash
cd server && go mod tidy && go test ./...
cd client && npm install && npm run build
```

after networked dependencies are available.

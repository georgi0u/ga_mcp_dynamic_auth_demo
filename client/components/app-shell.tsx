"use client";

import {
  startTransition,
  useDeferredValue,
  useEffect,
  useEffectEvent,
  useRef,
  useState,
} from "react";
import { API_ORIGIN, TOKEN_STORAGE_KEY, WS_BASE_URL, apiRequest } from "../lib/api";
import type {
  BeginConnectResponse,
  BootstrapResponse,
  Connection,
  LoginResponse,
  WebsocketPayload,
} from "../lib/types";

type LoginForm = {
  email: string;
  password: string;
};

type ConnectionForm = {
  name: string;
  url: string;
  scopes: string;
};

const defaultLoginForm: LoginForm = {
  email: "demo@example.com",
  password: "demo-password",
};

const defaultConnectionForm: ConnectionForm = {
  name: "",
  url: "",
  scopes: "",
};

export function AppShell() {
  const socketRef = useRef<WebSocket | null>(null);
  const chatScrollRef = useRef<HTMLDivElement | null>(null);
  const [hydrated, setHydrated] = useState(false);
  const [token, setToken] = useState("");
  const [bootstrap, setBootstrap] = useState<BootstrapResponse | null>(null);
  const [loginForm, setLoginForm] = useState<LoginForm>(defaultLoginForm);
  const [connectionForm, setConnectionForm] = useState<ConnectionForm>(defaultConnectionForm);
  const [composerValue, setComposerValue] = useState("");
  const [status, setStatus] = useState<"idle" | "working">("idle");
  const [busy, setBusy] = useState<"" | "login" | "connect" | "send" | "refresh">("");
  const [error, setError] = useState<string | null>(null);

  const deferredMessages = useDeferredValue(bootstrap?.messages ?? []);

  const refreshBootstrap = useEffectEvent(async (sessionToken: string) => {
    if (!sessionToken) {
      setBootstrap(null);
      return;
    }

    const data = await apiRequest<BootstrapResponse>("/api/bootstrap", {
      method: "GET",
      token: sessionToken,
    });
    setBootstrap(data);
  });

  const handleOAuthMessage = useEffectEvent((event: MessageEvent) => {
    if (event.origin !== API_ORIGIN) {
      return;
    }
    const data = event.data as { type?: string; status?: string; message?: string };
    if (data?.type !== "mcp-oauth") {
      return;
    }

    if (data.status === "error") {
      setError(data.message ?? "OAuth authorization failed.");
      return;
    }

    if (token) {
      setBusy("refresh");
      startTransition(() => {
        void refreshBootstrap(token)
          .catch((refreshError: unknown) => {
            setError(getErrorMessage(refreshError));
          })
          .finally(() => {
            setBusy("");
          });
      });
    }
  });

  const handleSocketPayload = useEffectEvent((payload: WebsocketPayload) => {
    if (payload.type === "chat.message") {
      setBootstrap((current) => {
        if (!current) {
          return current;
        }
        return {
          ...current,
          messages: [...(current.messages ?? []), payload.message],
        };
      });
      return;
    }

    if (payload.type === "chat.status") {
      setStatus(payload.status);
      if (payload.status === "idle") {
        setBusy("");
      }
      return;
    }

    if (payload.type === "chat.error") {
      setStatus("idle");
      setBusy("");
      setError(payload.error);
    }
  });

  useEffect(() => {
    const storedToken = window.localStorage.getItem(TOKEN_STORAGE_KEY) ?? "";
    setToken(storedToken);
    setHydrated(true);
  }, []);

  useEffect(() => {
    const listener = (event: Event) => {
      handleOAuthMessage(event as MessageEvent);
    };
    window.addEventListener("message", listener);
    return () => {
      window.removeEventListener("message", listener);
    };
  }, []);

  useEffect(() => {
    if (!hydrated) {
      return;
    }
    if (!token) {
      setBootstrap(null);
      return;
    }

    setBusy("refresh");
    void refreshBootstrap(token)
      .catch((refreshError: unknown) => {
        window.localStorage.removeItem(TOKEN_STORAGE_KEY);
        setToken("");
        setBootstrap(null);
        setError(getErrorMessage(refreshError));
      })
      .finally(() => {
        setBusy("");
      });
  }, [hydrated, token]);

  useEffect(() => {
    if (!token) {
      socketRef.current?.close();
      socketRef.current = null;
      return;
    }

    const socket = new WebSocket(`${WS_BASE_URL}/ws?token=${encodeURIComponent(token)}`);
    socket.onmessage = (event) => {
      try {
        handleSocketPayload(JSON.parse(event.data) as WebsocketPayload);
      } catch {
        setError("Received an unreadable websocket payload.");
      }
    };
    socket.onerror = () => {
      setError("Websocket connection failed.");
    };
    socketRef.current = socket;

    return () => {
      socket.close();
      if (socketRef.current === socket) {
        socketRef.current = null;
      }
    };
  }, [token]);

  useEffect(() => {
    const container = chatScrollRef.current;
    if (!container) {
      return;
    }

    container.scrollTop = container.scrollHeight;
  }, [deferredMessages.length]);

  async function handleLoginSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("login");
    setError(null);

    try {
      const data = await apiRequest<LoginResponse>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify(loginForm),
      });
      window.localStorage.setItem(TOKEN_STORAGE_KEY, data.token);
      setToken(data.token);
    } catch (loginError) {
      setError(getErrorMessage(loginError));
    } finally {
      setBusy("");
    }
  }

  async function handleLogout() {
    if (!token) {
      return;
    }
    try {
      await apiRequest<{ ok: boolean }>("/api/auth/logout", {
        method: "POST",
        token,
      });
    } catch {
      // Best-effort logout.
    }

    socketRef.current?.close();
    socketRef.current = null;
    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
    setBootstrap(null);
    setToken("");
    setStatus("idle");
    setError(null);
  }

  async function handleConnectionCreate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token) {
      return;
    }

    setBusy("connect");
    setError(null);
    try {
      const result = await apiRequest<BeginConnectResponse>("/api/connections", {
        method: "POST",
        token,
        body: JSON.stringify({
          name: connectionForm.name,
          url: connectionForm.url,
          scopes: splitScopes(connectionForm.scopes),
        }),
      });
      setConnectionForm(defaultConnectionForm);
      if (result.authorization_url) {
        openPopup(result.authorization_url);
      }
      await refreshBootstrap(token);
    } catch (connectError) {
      setError(getErrorMessage(connectError));
    } finally {
      setBusy("");
    }
  }

  async function handleConnectionAuthorize(connection: Connection) {
    if (!token) {
      return;
    }
    setBusy("connect");
    setError(null);
    try {
      const result = await apiRequest<BeginConnectResponse>(`/api/connections/${connection.id}/authorize`, {
        method: "POST",
        token,
      });
      if (result.authorization_url) {
        openPopup(result.authorization_url);
      }
      await refreshBootstrap(token);
    } catch (authorizeError) {
      setError(getErrorMessage(authorizeError));
    } finally {
      setBusy("");
    }
  }

  async function handleSendMessage(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!composerValue.trim()) {
      return;
    }
    if (!socketRef.current || socketRef.current.readyState !== WebSocket.OPEN) {
      setError("Websocket is not connected.");
      return;
    }

    setBusy("send");
    setError(null);
    socketRef.current.send(
      JSON.stringify({
        type: "chat.send",
        message: composerValue.trim(),
      }),
    );
    setComposerValue("");
  }

  if (!hydrated) {
    return <main className="page" />;
  }

  if (!bootstrap) {
    return (
      <main className="page">
        <section className="panel auth-screen">
          <div className="hero">
            <p className="eyebrow">Split Stack Demo</p>
            <h1 className="title">MCP Authorization Playground</h1>
            <p className="subtitle">
              Sign in to the Go backend, attach remote MCP servers, and chat through OpenAI-backed tool calling.
            </p>
          </div>
          <form className="section" onSubmit={handleLoginSubmit}>
            <label className="label" htmlFor="login-email">
              Email
            </label>
            <input
              id="login-email"
              name="email"
              className="field"
              autoComplete="email"
              value={loginForm.email}
              onChange={(event) => setLoginForm((current) => ({ ...current, email: event.target.value }))}
            />
            <label className="label" htmlFor="login-password" style={{ marginTop: "0.8rem" }}>
              Password
            </label>
            <input
              id="login-password"
              name="password"
              className="field"
              type="password"
              autoComplete="current-password"
              value={loginForm.password}
              onChange={(event) => setLoginForm((current) => ({ ...current, password: event.target.value }))}
            />
            <div className="actions">
              <button className="button primary" type="submit" disabled={busy === "login"}>
                {busy === "login" ? "Signing in..." : "Sign in"}
              </button>
            </div>
            {error ? <div className="error-box">{error}</div> : null}
          </form>
        </section>
      </main>
    );
  }

  return (
    <main className="page page-shell">
      <div className="shell">
        <aside className="panel sidebar">
          <section className="hero">
            <p className="eyebrow">Signed In</p>
            <h1 className="title">{bootstrap.user.email}</h1>
            <p className="subtitle">
              {(bootstrap.connections?.length ?? 0) === 1
                ? "1 MCP connection"
                : `${bootstrap.connections?.length ?? 0} MCP connections`}
            </p>
            <div className="actions">
              <button className="button ghost" type="button" onClick={handleLogout}>
                Sign out
              </button>
            </div>
          </section>

          <section className="section">
            <h2>Add MCP Server</h2>
            <form className="stack" onSubmit={handleConnectionCreate}>
              <div>
                <label className="label" htmlFor="connection-name">
                  Display name
                </label>
                <input
                  id="connection-name"
                  name="connection-name"
                  className="field"
                  placeholder="Google Maps, Calendar, Internal Tools"
                  value={connectionForm.name}
                  onChange={(event) =>
                    setConnectionForm((current) => ({ ...current, name: event.target.value }))
                  }
                />
              </div>
              <div>
                <label className="label" htmlFor="connection-url">
                  Remote MCP URL
                </label>
                <input
                  id="connection-url"
                  name="connection-url"
                  className="field"
                  placeholder="https://example.com/mcp"
                  value={connectionForm.url}
                  onChange={(event) =>
                    setConnectionForm((current) => ({ ...current, url: event.target.value }))
                  }
                />
              </div>
              <div>
                <label className="label" htmlFor="connection-scopes">
                  Requested scopes
                </label>
                <textarea
                  id="connection-scopes"
                  name="connection-scopes"
                  className="textarea"
                  placeholder="calendar.readonly, maps.read"
                  value={connectionForm.scopes}
                  onChange={(event) =>
                    setConnectionForm((current) => ({ ...current, scopes: event.target.value }))
                  }
                />
              </div>
              <div className="actions">
                <button className="button primary" type="submit" disabled={busy === "connect"}>
                  {busy === "connect" ? "Connecting..." : "Connect server"}
                </button>
              </div>
            </form>
          </section>

          <section className="section">
            <h2>Connections</h2>
            <div className="connections">
              {(bootstrap.connections?.length ?? 0) === 0 ? (
                <div className="empty">No MCP servers connected yet.</div>
              ) : (
                bootstrap.connections.map((connection) => (
                  <article className="connection-card" key={connection.id}>
                    <div className="status-row">
                      <h3>{connection.name}</h3>
                      <span className={`badge ${connection.status}`}>{connection.status}</span>
                    </div>
                    <p>{connection.endpoint}</p>
                    {connection.last_error ? <p className="tiny">{connection.last_error}</p> : null}
                    {connection.scopes.length > 0 ? (
                      <p className="tiny">Scopes: {connection.scopes.join(", ")}</p>
                    ) : null}
                    {connection.auth_required && connection.status !== "connected" ? (
                      <div className="actions">
                        <button
                          className="button ghost"
                          type="button"
                          disabled={busy === "connect"}
                          onClick={() => void handleConnectionAuthorize(connection)}
                        >
                          Re-authorize
                        </button>
                      </div>
                    ) : null}
                  </article>
                ))
              )}
            </div>
          </section>

          {error ? <div className="error-box">{error}</div> : null}
        </aside>

        <section className="panel main">
          <header className="chat-header">
            <div>
              <h2>{bootstrap.conversation.title}</h2>
              <p className="tiny">Messages are persisted in Postgres and replayed on reload.</p>
            </div>
            <div className="status-row">
              <span className={`badge ${status}`}>{status === "working" ? "Thinking" : "Ready"}</span>
            </div>
          </header>

          <div className="chat-scroll" ref={chatScrollRef}>
            <div className="messages">
              {deferredMessages.length === 0 ? (
                <div className="empty">Ask the assistant something that can use your connected MCP tools.</div>
              ) : (
                deferredMessages.map((message) => (
                  <article className={`message ${message.role}`} key={message.id}>
                    <div className="message-meta">
                      <span>{message.role}</span>
                      <span>{formatTimestamp(message.created_at)}</span>
                    </div>
                    <div>{message.content}</div>
                  </article>
                ))
              )}
            </div>
          </div>

          <form className="composer" onSubmit={handleSendMessage}>
            <div className="composer-shell">
              <textarea
                id="composer-message"
                name="message"
                className="textarea"
                placeholder="Plan tomorrow around my calendar and nearby meetings."
                value={composerValue}
                onChange={(event) => setComposerValue(event.target.value)}
              />
              <button
                className="button primary"
                type="submit"
                disabled={busy === "send" || status === "working"}
              >
                {busy === "send" || status === "working" ? "Sending..." : "Send"}
              </button>
            </div>
          </form>
        </section>
      </div>
    </main>
  );
}

function splitScopes(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function openPopup(url: string) {
  window.open(url, "mcp-oauth", "width=640,height=760,noopener=false,noreferrer=false");
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error";
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

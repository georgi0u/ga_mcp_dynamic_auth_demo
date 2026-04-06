package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/adamgeorgiou/mcp_auth/server/internal/auth"
	"github.com/adamgeorgiou/mcp_auth/server/internal/chat"
	"github.com/adamgeorgiou/mcp_auth/server/internal/config"
	"github.com/adamgeorgiou/mcp_auth/server/internal/mcpservice"
	"github.com/adamgeorgiou/mcp_auth/server/internal/store"
	"github.com/gorilla/websocket"
)

type App struct {
	cfg      config.Config
	auth     *auth.Service
	chat     *chat.Service
	mcp      *mcpservice.Service
	store    *store.Store
	upgrader websocket.Upgrader
}

func New(
	cfg config.Config,
	authService *auth.Service,
	chatService *chat.Service,
	mcpManager *mcpservice.Service,
	store *store.Store,
) *App {
	app := &App{
		cfg:   cfg,
		auth:  authService,
		chat:  chatService,
		mcp:   mcpManager,
		store: store,
	}
	app.upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			return origin == "" || app.isAllowedOrigin(origin)
		},
	}
	return app
}

func (a *App) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealthz)
	mux.HandleFunc("POST /api/auth/login", a.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", a.handleLogout)
	mux.HandleFunc("GET /api/bootstrap", a.handleBootstrap)
	mux.HandleFunc("GET /api/connections", a.handleConnectionsList)
	mux.HandleFunc("POST /api/connections", a.handleConnectionsCreate)
	mux.HandleFunc("GET /api/connections/{id}/tools", a.handleConnectionToolsList)
	mux.HandleFunc("POST /api/connections/{id}/authorize", a.handleConnectionAuthorize)
	mux.HandleFunc("GET /oauth/callback", a.handleOAuthCallback)
	mux.HandleFunc("GET /ws", a.handleWebsocket)
	return a.withCORS(a.withRequestTimeout(mux))
}

func (a *App) withRequestTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" || isWebsocketUpgrade(r) {
			next.ServeHTTP(w, r)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), a.cfg.RequestTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *App) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin != "" && a.isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Credentials", "false")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	session, user, err := a.auth.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      session.Token,
		"expires_at": session.ExpiresAt,
		"user":       user,
	})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r.Header.Get("Authorization"))
	if err := a.auth.Logout(r.Context(), token); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	user, token, ok := a.requireAPIUser(w, r)
	if !ok {
		return
	}

	conversation, messages, err := a.chat.Bootstrap(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	connections, err := a.store.ListConnections(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":         user,
		"token":        token,
		"conversation": conversation,
		"messages":     messages,
		"connections":  connections,
	})
}

func (a *App) handleConnectionsList(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.requireAPIUser(w, r)
	if !ok {
		return
	}
	connections, err := a.store.ListConnections(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": connections})
}

func (a *App) handleConnectionsCreate(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.requireAPIUser(w, r)
	if !ok {
		return
	}

	var req struct {
		Name   string   `json:"name"`
		URL    string   `json:"url"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result, err := a.mcp.BeginConnect(r.Context(), user.ID, req.Name, req.URL, req.Scopes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (a *App) handleConnectionAuthorize(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.requireAPIUser(w, r)
	if !ok {
		return
	}
	connectionID := strings.TrimSpace(r.PathValue("id"))
	if connectionID == "" {
		writeError(w, http.StatusNotFound, "connection not found")
		return
	}

	connection, err := a.store.GetConnectionByID(r.Context(), user.ID, connectionID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}

	result, err := a.mcp.BeginAuthorization(r.Context(), connection)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *App) handleConnectionToolsList(w http.ResponseWriter, r *http.Request) {
	user, _, ok := a.requireAPIUser(w, r)
	if !ok {
		return
	}
	connectionID := strings.TrimSpace(r.PathValue("id"))
	if connectionID == "" {
		writeError(w, http.StatusNotFound, "connection not found")
		return
	}

	connection, err := a.store.GetConnectionByID(r.Context(), user.ID, connectionID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	if connection.Status != "connected" {
		writeError(w, http.StatusConflict, "connection is not connected")
		return
	}

	tools, err := a.mcp.ListConnectionToolDefinitions(r.Context(), connection)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"connection": connection,
		"tools":      tools,
	})
}

func (a *App) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	slog.Info("handling OAuth callback", "query", r.URL.RawQuery)
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	oauthErr := strings.TrimSpace(r.URL.Query().Get("error"))
	oauthErrDescription := strings.TrimSpace(r.URL.Query().Get("error_description"))

	if oauthErr != "" {
		renderCallbackHTML(w, a.cfg.ClientAppURL, "error", fmt.Sprintf("%s: %s", oauthErr, oauthErrDescription))
		return
	}
	if state == "" || code == "" {
		renderCallbackHTML(w, a.cfg.ClientAppURL, "error", "missing state or code")
		return
	}

	connection, err := a.mcp.CompleteAuthorization(r.Context(), state, code)
	if err != nil {
		renderCallbackHTML(w, a.cfg.ClientAppURL, "error", err.Error())
		return
	}
	renderCallbackHTML(w, a.cfg.ClientAppURL, "success", fmt.Sprintf("Connected %s", connection.Name))
}

func (a *App) handleWebsocket(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	user, err := a.auth.Authenticate(r.Context(), token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("upgrade websocket", "error", err)
		return
	}
	defer conn.Close()
	conn.SetReadLimit(1 << 20)

	for {
		var message struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		}
		if err := conn.ReadJSON(&message); err != nil {
			return
		}

		switch message.Type {
		case "chat.send":
			turnCtx, cancel := context.WithTimeout(r.Context(), a.cfg.RequestTimeout)
			err := a.handleChatSend(turnCtx, conn, user, message.Message)
			cancel()
			if err != nil {
				_ = conn.WriteJSON(map[string]any{
					"type":  "chat.error",
					"error": err.Error(),
				})
			}
		default:
			_ = conn.WriteJSON(map[string]any{
				"type":  "chat.error",
				"error": "unsupported websocket message type",
			})
		}
	}
}

func (a *App) handleChatSend(
	ctx context.Context,
	conn *websocket.Conn,
	user *store.User,
	input string,
) error {
	input = strings.TrimSpace(input)
	if input == "" {
		return fmt.Errorf("message cannot be empty")
	}

	conversation, userMessage, err := a.chat.BeginTurn(ctx, user.ID, input)
	if err != nil {
		return err
	}
	if err := conn.WriteJSON(map[string]any{
		"type":    "chat.message",
		"message": userMessage,
	}); err != nil {
		return err
	}
	if err := conn.WriteJSON(map[string]any{
		"type":   "chat.status",
		"status": "working",
	}); err != nil {
		return err
	}

	assistantMessage, err := a.chat.CompleteTurn(ctx, user.ID, conversation, input)
	if err != nil {
		return err
	}
	if err := conn.WriteJSON(map[string]any{
		"type":    "chat.message",
		"message": assistantMessage,
	}); err != nil {
		return err
	}
	return conn.WriteJSON(map[string]any{
		"type":   "chat.status",
		"status": "idle",
	})
}

func (a *App) requireAPIUser(
	w http.ResponseWriter,
	r *http.Request,
) (*store.User, string, bool) {
	token := extractBearerToken(r.Header.Get("Authorization"))
	user, err := a.auth.Authenticate(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return nil, "", false
	}
	return user, token, true
}

func (a *App) isAllowedOrigin(origin string) bool {
	for _, candidate := range a.cfg.AllowedOrigins {
		if candidate == origin {
			return true
		}
	}
	return false
}

func extractBearerToken(header string) string {
	parts := strings.Fields(header)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return parts[1]
	}
	return ""
}

func renderCallbackHTML(
	w http.ResponseWriter,
	clientAppURL string,
	status string,
	message string,
) {
	targetOrigin := clientAppURL
	if parsed, err := url.Parse(clientAppURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		targetOrigin = parsed.Scheme + "://" + parsed.Host
	}
	visibleMessage := html.EscapeString(message)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(fmt.Sprintf(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>MCP Authorization</title>
</head>
<body>
  <script>
    if (window.opener) {
      window.opener.postMessage({ type: "mcp-oauth", status: %q, message: %q }, %q);
      window.close();
    }
  </script>
  <p>%s</p>
</body>
</html>`, status, message, targetOrigin, visibleMessage)))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func isWebsocketUpgrade(r *http.Request) bool {
	upgrade := strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket")
	if !upgrade {
		return false
	}
	for _, part := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(part), "upgrade") {
			return true
		}
	}
	return false
}

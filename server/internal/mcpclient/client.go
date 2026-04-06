package mcpclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Client struct {
	publicBaseURL string
	httpClient    *http.Client
}

type ServerDefinition struct {
	Endpoint                     string
	CanonicalResource            string
	AuthRequired                 bool
	ProtectedResourceMetadataURL string
	AuthorizationServerIssuer    string
	AuthorizationEndpoint        string
	TokenEndpoint                string
	RegistrationEndpoint         string
	ClientID                     string
	ClientSecret                 string
	TokenEndpointAuthMethod      string
}

type SessionDefinition struct {
	Name         string
	Server       ServerDefinition
	Scopes       []string
	AccessToken  string
	RefreshToken string
	TokenExpiry  *time.Time
}

type AuthorizationResult struct {
	Server           ServerDefinition
	Scopes           []string
	AuthorizationURL string
	State            string
	CodeVerifier     string
	RedirectURI      string
}

type TokenSet struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	Scope        string
	ExpiresAt    *time.Time
}

type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
	ResourceName         string   `json:"resource_name"`
}

type authorizationServerMetadata struct {
	Issuer                          string   `json:"issuer"`
	AuthorizationEndpoint           string   `json:"authorization_endpoint"`
	TokenEndpoint                   string   `json:"token_endpoint"`
	RegistrationEndpoint            string   `json:"registration_endpoint"`
	ScopesSupported                 []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupport []string `json:"token_endpoint_auth_methods_supported"`
}

type clientRegistrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope,omitempty"`
}

type clientRegistrationResponse struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

func New(
	publicBaseURL string,
	timeout time.Duration,
) *Client {
	return &Client{
		publicBaseURL: strings.TrimRight(publicBaseURL, "/"),
		httpClient:    &http.Client{Timeout: timeout},
	}
}

func (m *Client) PrepareServer(
	ctx context.Context,
	endpoint string,
) (*ServerDefinition, error) {
	normalizedEndpoint, err := normalizeEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	canonicalResource, err := canonicalizeResource(normalizedEndpoint)
	if err != nil {
		return nil, err
	}

	server := &ServerDefinition{
		Endpoint:          normalizedEndpoint,
		CanonicalResource: canonicalResource,
	}

	resourceMetadataURL, resourceMetadata, err := m.discoverProtectedResource(
		ctx,
		normalizedEndpoint,
	)
	if err != nil {
		return nil, err
	}
	if resourceMetadata == nil {
		return server, nil
	}

	server.AuthRequired = true
	server.ProtectedResourceMetadataURL = resourceMetadataURL
	if len(resourceMetadata.AuthorizationServers) > 0 {
		server.AuthorizationServerIssuer = resourceMetadata.AuthorizationServers[0]
	}
	return server, nil
}

func (m *Client) BeginAuthorization(
	ctx context.Context,
	server ServerDefinition,
	scopes []string,
) (*AuthorizationResult, error) {
	normalizedServer, err := m.normalizeServerDefinition(server)
	if err != nil {
		return nil, err
	}

	resourceMetadata := &protectedResourceMetadata{
		Resource:             normalizedServer.CanonicalResource,
		AuthorizationServers: []string{normalizedServer.AuthorizationServerIssuer},
		ScopesSupported:      sanitizeScopes(scopes),
	}
	if normalizedServer.ProtectedResourceMetadataURL == "" ||
		normalizedServer.AuthorizationServerIssuer == "" {
		metadataURL, metadata, err := m.discoverProtectedResource(
			ctx,
			normalizedServer.Endpoint,
		)
		if err != nil {
			return nil, err
		}
		if metadata == nil {
			return nil, fmt.Errorf(
				"server %q does not advertise an authorization server",
				normalizedServer.Endpoint,
			)
		}
		normalizedServer.AuthRequired = true
		normalizedServer.ProtectedResourceMetadataURL = metadataURL
		resourceMetadata = metadata
	}

	return m.beginAuthorization(ctx, normalizedServer, resourceMetadata, scopes)
}

func (m *Client) beginAuthorization(
	ctx context.Context,
	server ServerDefinition,
	resourceMetadata *protectedResourceMetadata,
	explicitScopes []string,
) (*AuthorizationResult, error) {
	issuer := server.AuthorizationServerIssuer
	if issuer == "" && len(resourceMetadata.AuthorizationServers) > 0 {
		issuer = resourceMetadata.AuthorizationServers[0]
	}
	if issuer == "" {
		return nil, fmt.Errorf("no authorization server advertised by %s", server.Endpoint)
	}

	authMetadata, err := m.fetchAuthorizationServerMetadata(ctx, issuer)
	if err != nil {
		return nil, err
	}
	server.AuthRequired = true
	server.AuthorizationServerIssuer = issuer
	server.AuthorizationEndpoint = authMetadata.AuthorizationEndpoint
	server.TokenEndpoint = authMetadata.TokenEndpoint
	server.RegistrationEndpoint = authMetadata.RegistrationEndpoint
	scopes := chooseScopes(explicitScopes, authMetadata.ScopesSupported)
	if len(scopes) == 0 {
		scopes = sanitizeScopes(resourceMetadata.ScopesSupported)
	}

	if server.ClientID == "" {
		registration, err := m.dynamicRegisterClient(ctx, server)
		if err != nil {
			return nil, err
		}
		server.ClientID = registration.ClientID
		server.ClientSecret = registration.ClientSecret
		server.TokenEndpointAuthMethod = registration.TokenEndpointAuthMethod
	}
	if server.TokenEndpointAuthMethod == "" {
		server.TokenEndpointAuthMethod = "none"
	}

	redirectURI := m.publicBaseURL + "/oauth/callback"
	verifier := randomURLSafe(48)
	state := randomURLSafe(32)

	authorizationURL, err := buildAuthorizationURL(
		server.AuthorizationEndpoint,
		server.ClientID,
		redirectURI,
		state,
		verifier,
		server.CanonicalResource,
		scopes,
	)
	if err != nil {
		return nil, err
	}

	return &AuthorizationResult{
		Server:           server,
		Scopes:           scopes,
		AuthorizationURL: authorizationURL,
		State:            state,
		CodeVerifier:     verifier,
		RedirectURI:      redirectURI,
	}, nil
}

func (m *Client) ExchangeAuthorizationCode(
	ctx context.Context,
	session SessionDefinition,
	redirectURI string,
	verifier string,
	code string,
) (*TokenSet, error) {
	normalizedSession, err := m.normalizeSessionDefinition(session)
	if err != nil {
		return nil, err
	}

	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", code)
	values.Set("client_id", normalizedSession.Server.ClientID)
	values.Set("redirect_uri", redirectURI)
	values.Set("code_verifier", verifier)
	values.Set("resource", normalizedSession.Server.CanonicalResource)
	return m.doTokenRequest(ctx, normalizedSession, values)
}

func (m *Client) withSession(
	ctx context.Context,
	session SessionDefinition,
	fn func(session *mcp.ClientSession) error,
) (*TokenSet, error) {
	normalizedSession, err := m.normalizeSessionDefinition(session)
	if err != nil {
		return nil, err
	}

	httpClient, refreshedTokens, err := m.transportHTTPClient(ctx, normalizedSession)
	if err != nil {
		return nil, err
	}

	mcpSession, err := connectMCPClientSession(
		ctx,
		normalizedSession.Server.Endpoint,
		httpClient,
	)
	if err != nil {
		return refreshedTokens, fmt.Errorf(
			"connect to %s: %w",
			sessionName(normalizedSession),
			err,
		)
	}
	defer mcpSession.Close()

	if err := fn(mcpSession); err != nil {
		return refreshedTokens, err
	}
	return refreshedTokens, nil
}

func connectMCPClientSession(
	ctx context.Context,
	endpoint string,
	httpClient *http.Client,
) (*mcp.ClientSession, error) {
	session, err := connectStreamableSession(ctx, endpoint, httpClient)
	if err == nil {
		return session, nil
	}
	if !shouldFallbackToLegacySSE(err) {
		return nil, err
	}

	session, sseErr := connectLegacySSESession(ctx, endpoint, httpClient)
	if sseErr != nil {
		return nil, fmt.Errorf("streamable HTTP failed (%v); SSE fallback failed: %w", err, sseErr)
	}
	return session, nil
}

func connectStreamableSession(
	ctx context.Context,
	endpoint string,
	httpClient *http.Client,
) (*mcp.ClientSession, error) {
	client := newMCPClient()
	transport := &mcp.StreamableClientTransport{
		Endpoint:             endpoint,
		DisableStandaloneSSE: true,
		HTTPClient:           httpClient,
	}
	return client.Connect(ctx, transport, nil)
}

func connectLegacySSESession(
	ctx context.Context,
	endpoint string,
	httpClient *http.Client,
) (*mcp.ClientSession, error) {
	client := newMCPClient()
	transport := &mcp.SSEClientTransport{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
	}
	return client.Connect(ctx, transport, nil)
}

func newMCPClient() *mcp.Client {
	return mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-auth-demo-client",
		Version: "0.1.0",
	}, nil)
}

func shouldFallbackToLegacySSE(
	err error,
) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, http.StatusText(http.StatusBadRequest)) ||
		strings.Contains(message, http.StatusText(http.StatusNotFound)) ||
		strings.Contains(message, http.StatusText(http.StatusMethodNotAllowed))
}

func (m *Client) transportHTTPClient(
	ctx context.Context,
	session SessionDefinition,
) (*http.Client, *TokenSet, error) {
	accessToken := ""
	var refreshedTokens *TokenSet
	if session.Server.AuthRequired {
		token, updatedTokens, err := m.ensureAccessToken(ctx, session)
		if err != nil {
			return nil, nil, err
		}
		accessToken = token
		refreshedTokens = updatedTokens
	}
	return &http.Client{
		Timeout: m.httpClient.Timeout,
		Transport: &bearerRoundTripper{
			base:        http.DefaultTransport,
			accessToken: accessToken,
		},
	}, refreshedTokens, nil
}

func (m *Client) ensureAccessToken(
	ctx context.Context,
	session SessionDefinition,
) (string, *TokenSet, error) {
	if session.AccessToken == "" && session.RefreshToken == "" {
		return "", nil, fmt.Errorf(
			"connection %q requires authorization again",
			sessionName(session),
		)
	}

	if session.AccessToken != "" &&
		(session.TokenExpiry == nil ||
			session.TokenExpiry.After(time.Now().UTC().Add(60*time.Second))) {
		return session.AccessToken, nil, nil
	}

	tokenSet, err := m.refreshAccessToken(ctx, session)
	if err != nil {
		return "", nil, err
	}
	return tokenSet.AccessToken, tokenSet, nil
}

func (m *Client) refreshAccessToken(
	ctx context.Context,
	session SessionDefinition,
) (*TokenSet, error) {
	values := url.Values{}
	values.Set("grant_type", "refresh_token")
	values.Set("refresh_token", session.RefreshToken)
	values.Set("client_id", session.Server.ClientID)
	values.Set("resource", session.Server.CanonicalResource)
	return m.doTokenRequest(ctx, session, values)
}

func (m *Client) doTokenRequest(
	ctx context.Context,
	session SessionDefinition,
	values url.Values,
) (*TokenSet, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		session.Server.TokenEndpoint,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if session.Server.TokenEndpointAuthMethod == "client_secret_post" {
		if session.Server.ClientSecret == "" {
			return nil, fmt.Errorf("client secret is required for token endpoint auth")
		}
		values.Set("client_secret", session.Server.ClientSecret)
		req.Body = io.NopCloser(strings.NewReader(values.Encode()))
		req.ContentLength = int64(len(values.Encode()))
	}
	if session.Server.TokenEndpointAuthMethod == "client_secret_basic" {
		if session.Server.ClientSecret == "" {
			return nil, fmt.Errorf("client secret is required for token endpoint auth")
		}
		req.SetBasicAuth(session.Server.ClientID, session.Server.ClientSecret)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token request failed: %s", strings.TrimSpace(string(body)))
	}

	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if token.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}

	refreshToken := token.RefreshToken
	if refreshToken == "" {
		refreshToken = session.RefreshToken
	}
	expiresAt := time.Now().UTC().Add(
		time.Duration(maxInt64(token.ExpiresIn, 300)) * time.Second,
	)
	return &TokenSet{
		AccessToken:  token.AccessToken,
		RefreshToken: refreshToken,
		TokenType:    token.TokenType,
		Scope:        token.Scope,
		ExpiresAt:    &expiresAt,
	}, nil
}

func (m *Client) dynamicRegisterClient(
	ctx context.Context,
	server ServerDefinition,
) (clientRegistrationResponse, error) {
	if server.RegistrationEndpoint == "" {
		return clientRegistrationResponse{}, fmt.Errorf(
			"authorization server does not support dynamic client registration",
		)
	}

	payload := clientRegistrationRequest{
		ClientName:              "MCP Auth Demo Client",
		RedirectURIs:            []string{m.publicBaseURL + "/oauth/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return clientRegistrationResponse{}, fmt.Errorf("marshal registration payload: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		server.RegistrationEndpoint,
		strings.NewReader(string(body)),
	)
	if err != nil {
		return clientRegistrationResponse{}, fmt.Errorf("create registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return clientRegistrationResponse{}, fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return clientRegistrationResponse{}, fmt.Errorf("read registration response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return clientRegistrationResponse{}, fmt.Errorf(
			"registration request failed: %s",
			strings.TrimSpace(string(respBody)),
		)
	}

	var registration clientRegistrationResponse
	if err := json.Unmarshal(respBody, &registration); err != nil {
		return clientRegistrationResponse{}, fmt.Errorf("decode registration response: %w", err)
	}
	if registration.ClientID == "" {
		return clientRegistrationResponse{}, fmt.Errorf("registration response missing client_id")
	}
	if registration.TokenEndpointAuthMethod == "" {
		registration.TokenEndpointAuthMethod = "none"
	}
	return registration, nil
}

func (m *Client) fetchAuthorizationServerMetadata(
	ctx context.Context,
	issuer string,
) (*authorizationServerMetadata, error) {
	metadataURL, err := authorizationServerMetadataURL(issuer)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create auth metadata request: %w", err)
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch auth metadata: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read auth metadata: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf(
			"authorization server metadata request failed: %s",
			strings.TrimSpace(string(body)),
		)
	}

	var metadata authorizationServerMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("decode auth metadata: %w", err)
	}
	if metadata.AuthorizationEndpoint == "" || metadata.TokenEndpoint == "" {
		return nil, fmt.Errorf("authorization server metadata is incomplete")
	}
	return &metadata, nil
}

func (m *Client) discoverProtectedResource(
	ctx context.Context,
	endpoint string,
) (string, *protectedResourceMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", nil, fmt.Errorf("create discovery request: %w", err)
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("probe mcp endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "", nil, nil
	}
	if resp.StatusCode == http.StatusMethodNotAllowed {
		return "", nil, nil
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf(
			"unexpected discovery response from %s: %s",
			endpoint,
			strings.TrimSpace(string(body)),
		)
	}

	metadataURL := extractResourceMetadataURL(resp.Header.Values("WWW-Authenticate"))
	if metadataURL == "" {
		return "", nil, fmt.Errorf(
			"server requires authorization but did not provide resource_metadata",
		)
	}

	resourceMetadata, err := m.fetchProtectedResourceMetadata(ctx, metadataURL)
	if err != nil {
		return "", nil, err
	}
	return metadataURL, resourceMetadata, nil
}

func (m *Client) fetchProtectedResourceMetadata(
	ctx context.Context,
	metadataURL string,
) (*protectedResourceMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create protected resource metadata request: %w", err)
	}
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch protected resource metadata: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read protected resource metadata: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf(
			"protected resource metadata request failed: %s",
			strings.TrimSpace(string(body)),
		)
	}

	var metadata protectedResourceMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("decode protected resource metadata: %w", err)
	}
	if len(metadata.AuthorizationServers) == 0 {
		return nil, fmt.Errorf(
			"protected resource metadata did not advertise an authorization server",
		)
	}
	return &metadata, nil
}

func buildAuthorizationURL(
	endpoint string,
	clientID string,
	redirectURI string,
	state string,
	verifier string,
	resource string,
	scopes []string,
) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse authorization endpoint: %w", err)
	}
	query := parsed.Query()
	query.Set("response_type", "code")
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("state", state)
	query.Set("code_challenge", pkceChallenge(verifier))
	query.Set("code_challenge_method", "S256")
	query.Set("resource", resource)
	if len(scopes) > 0 {
		query.Set("scope", strings.Join(scopes, " "))
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func authorizationServerMetadataURL(
	issuer string,
) (string, error) {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return "", fmt.Errorf("parse issuer: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf(
			"authorization server issuer must be absolute: %s",
			issuer,
		)
	}

	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/.well-known/oauth-authorization-server"
		return parsed.String(), nil
	}

	wellKnown := *parsed
	wellKnown.Path = path.Join("/.well-known/oauth-authorization-server", parsed.Path)
	return wellKnown.String(), nil
}

func (m *Client) normalizeServerDefinition(
	server ServerDefinition,
) (ServerDefinition, error) {
	normalizedEndpoint, err := normalizeEndpoint(server.Endpoint)
	if err != nil {
		return ServerDefinition{}, err
	}

	canonicalResource := strings.TrimSpace(server.CanonicalResource)
	if canonicalResource == "" {
		canonicalResource, err = canonicalizeResource(normalizedEndpoint)
		if err != nil {
			return ServerDefinition{}, err
		}
	}

	server.Endpoint = normalizedEndpoint
	server.CanonicalResource = canonicalResource
	server.ClientID = strings.TrimSpace(server.ClientID)
	server.ClientSecret = strings.TrimSpace(server.ClientSecret)
	server.TokenEndpointAuthMethod = strings.TrimSpace(server.TokenEndpointAuthMethod)
	return server, nil
}

func (m *Client) normalizeSessionDefinition(
	session SessionDefinition,
) (SessionDefinition, error) {
	server, err := m.normalizeServerDefinition(session.Server)
	if err != nil {
		return SessionDefinition{}, err
	}

	session.Name = strings.TrimSpace(session.Name)
	session.Server = server
	session.Scopes = sanitizeScopes(session.Scopes)
	session.AccessToken = strings.TrimSpace(session.AccessToken)
	session.RefreshToken = strings.TrimSpace(session.RefreshToken)
	return session, nil
}

func normalizeEndpoint(
	raw string,
) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("parse endpoint: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("endpoint must be an absolute URL")
	}
	parsed.Fragment = ""
	if parsed.Path == "" {
		parsed.Path = "/mcp"
	}
	return parsed.String(), nil
}

func canonicalizeResource(
	raw string,
) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse canonical resource: %w", err)
	}
	parsed.Fragment = ""
	parsed.RawQuery = ""
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Path == "/" {
		parsed.Path = ""
	}
	return parsed.String(), nil
}

func sanitizeScopes(
	scopes []string,
) []string {
	cleaned := make([]string, 0, len(scopes))
	seen := map[string]struct{}{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		cleaned = append(cleaned, scope)
	}
	return cleaned
}

func chooseScopes(
	explicit []string,
	advertised []string,
) []string {
	if len(explicit) > 0 {
		return sanitizeScopes(explicit)
	}
	return sanitizeScopes(advertised)
}

func extractResourceMetadataURL(
	headers []string,
) string {
	for _, header := range headers {
		lower := strings.ToLower(header)
		index := strings.Index(lower, "bearer")
		if index == -1 {
			continue
		}
		fragment := header[index+len("bearer"):]
		for _, part := range splitAuthParams(fragment) {
			key, value, ok := strings.Cut(part, "=")
			if !ok {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(key), "resource_metadata") {
				return strings.Trim(strings.TrimSpace(value), `"`)
			}
		}
	}
	return ""
}

func splitAuthParams(
	raw string,
) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false

	for _, r := range raw {
		switch r {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case ',':
			if inQuotes {
				current.WriteRune(r)
				continue
			}
			part := strings.TrimSpace(current.String())
			if part != "" {
				parts = append(parts, part)
			}
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}

	if part := strings.TrimSpace(current.String()); part != "" {
		parts = append(parts, part)
	}
	return parts
}

func pkceChallenge(
	verifier string,
) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomURLSafe(
	bytes int,
) string {
	random := make([]byte, bytes)
	if _, err := rand.Read(random); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(random)
}

func sessionName(
	session SessionDefinition,
) string {
	if session.Name != "" {
		return session.Name
	}
	return session.Server.Endpoint
}

func maxInt64(
	value int64,
	fallback int64,
) int64 {
	if value <= 0 {
		return fallback
	}
	return value
}

type bearerRoundTripper struct {
	base        http.RoundTripper
	accessToken string
}

func (t *bearerRoundTripper) RoundTrip(
	req *http.Request,
) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if t.accessToken != "" {
		clone.Header.Set("Authorization", "Bearer "+t.accessToken)
	}
	return t.base.RoundTrip(clone)
}

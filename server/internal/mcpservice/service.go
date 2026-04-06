package mcpservice

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/adamgeorgiou/mcp_auth/server/internal/cryptox"
	"github.com/adamgeorgiou/mcp_auth/server/internal/mcpclient"
	"github.com/adamgeorgiou/mcp_auth/server/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Service struct {
	store  *store.Store
	crypto *cryptox.Service
	client *mcpclient.Client
}

type BeginConnectResult struct {
	Connection       *store.Connection `json:"connection"`
	AuthorizationURL string            `json:"authorization_url,omitempty"`
}

type ToolDefinition struct {
	FunctionName   string         `json:"function_name"`
	ConnectionID   string         `json:"connection_id"`
	ConnectionName string         `json:"connection_name"`
	MCPName        string         `json:"mcp_name"`
	Description    string         `json:"description"`
	Parameters     map[string]any `json:"parameters"`
}

func New(
	store *store.Store,
	crypto *cryptox.Service,
	client *mcpclient.Client,
) *Service {
	return &Service{
		store:  store,
		crypto: crypto,
		client: client,
	}
}

func (s *Service) BeginConnect(
	ctx context.Context,
	userID string,
	name string,
	endpoint string,
	scopes []string,
) (*BeginConnectResult, error) {
	serverDefinition, err := s.client.PrepareServer(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(name) == "" {
		name = defaultConnectionName(serverDefinition.Endpoint)
	}

	server, err := s.store.EnsureMCPServer(
		ctx,
		serverDefinition.Endpoint,
		serverDefinition.CanonicalResource,
	)
	if err != nil {
		return nil, err
	}
	if err := s.applyServerDefinition(server, *serverDefinition); err != nil {
		return nil, err
	}
	if err := s.store.UpdateMCPServer(ctx, server); err != nil {
		return nil, err
	}

	connection, err := s.store.CreateConnection(ctx, store.CreateConnectionParams{
		UserID:            userID,
		ServerID:          server.ID,
		Name:              strings.TrimSpace(name),
		Endpoint:          server.Endpoint,
		CanonicalResource: server.CanonicalResource,
		Scopes:            sanitizeScopes(scopes),
	})
	if err != nil {
		return nil, err
	}
	applyServerToConnection(connection, server)

	if !server.AuthRequired {
		if err := s.verifyConnection(ctx, connection); err != nil {
			connection.Status = statusFromError(err)
			connection.LastError = err.Error()
			_ = s.store.UpdateConnection(ctx, connection)
			return nil, err
		}
		return &BeginConnectResult{Connection: connection}, nil
	}

	currentServerDefinition, err := s.serverDefinitionFromStore(server)
	if err != nil {
		return nil, err
	}

	authResult, err := s.client.BeginAuthorization(
		ctx,
		currentServerDefinition,
		connection.Scopes,
	)
	if err != nil {
		connection.Status = "error"
		connection.LastError = err.Error()
		_ = s.store.UpdateConnection(ctx, connection)
		return nil, err
	}
	if err := s.persistAuthorization(ctx, server, connection, authResult); err != nil {
		return nil, err
	}

	return &BeginConnectResult{
		Connection:       connection,
		AuthorizationURL: authResult.AuthorizationURL,
	}, nil
}

func (s *Service) BeginAuthorization(
	ctx context.Context,
	connection *store.Connection,
) (*BeginConnectResult, error) {
	if connection == nil {
		return nil, fmt.Errorf("connection is nil")
	}

	server, err := s.ensureServerForConnection(ctx, connection)
	if err != nil {
		return nil, err
	}

	serverDefinition, err := s.serverDefinitionFromStore(server)
	if err != nil {
		return nil, err
	}

	authResult, err := s.client.BeginAuthorization(ctx, serverDefinition, connection.Scopes)
	if err != nil {
		return nil, err
	}
	if err := s.persistAuthorization(ctx, server, connection, authResult); err != nil {
		return nil, err
	}

	return &BeginConnectResult{
		Connection:       connection,
		AuthorizationURL: authResult.AuthorizationURL,
	}, nil
}

func (s *Service) CompleteAuthorization(
	ctx context.Context,
	state string,
	code string,
) (*store.Connection, error) {
	oauthState, err := s.store.GetOAuthState(ctx, state)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = s.store.DeleteOAuthState(ctx, state)
	}()

	connection, err := s.store.GetConnectionByIDAny(ctx, oauthState.ConnectionID)
	if err != nil {
		return nil, err
	}

	server, err := s.ensureServerForConnection(ctx, connection)
	if err != nil {
		return nil, err
	}
	applyServerToConnection(connection, server)

	session, err := s.sessionDefinitionFromConnection(connection)
	if err != nil {
		return nil, err
	}

	tokenSet, err := s.client.ExchangeAuthorizationCode(
		ctx,
		session,
		oauthState.RedirectURI,
		oauthState.CodeVerifier,
		code,
	)
	if err != nil {
		connection.Status = "needs_auth"
		connection.LastError = err.Error()
		_ = s.store.UpdateConnection(ctx, connection)
		return nil, err
	}
	if err := s.persistTokenSet(ctx, connection, tokenSet); err != nil {
		return nil, err
	}
	if err := s.verifyConnection(ctx, connection); err != nil {
		connection.Status = statusFromError(err)
		connection.LastError = err.Error()
		_ = s.store.UpdateConnection(ctx, connection)
		return nil, err
	}
	return connection, nil
}

func (s *Service) BuildToolCatalog(
	ctx context.Context,
	userID string,
) ([]ToolDefinition, map[string]ToolDefinition, error) {
	connections, err := s.store.ListConnections(ctx, userID)
	if err != nil {
		return nil, nil, err
	}

	var definitions []ToolDefinition
	index := make(map[string]ToolDefinition)

	for i := range connections {
		connection := &connections[i]
		if connection.Status != "connected" {
			continue
		}

		session, err := s.sessionDefinitionFromConnection(connection)
		if err != nil {
			return nil, nil, err
		}
		tools, refreshedTokens, err := s.client.ListTools(ctx, session)
		if refreshedTokens != nil {
			if err := s.persistTokenSet(ctx, connection, refreshedTokens); err != nil {
				return nil, nil, err
			}
		}
		if err != nil {
			connection.Status = statusFromError(err)
			connection.LastError = err.Error()
			_ = s.store.UpdateConnection(ctx, connection)
			continue
		}

		connectionDefinitions := toolDefinitionsForConnection(connection, tools)
		for _, definition := range connectionDefinitions {
			definitions = append(definitions, definition)
			index[definition.FunctionName] = definition
		}
	}

	sort.Slice(definitions, func(i, j int) bool {
		if definitions[i].ConnectionName == definitions[j].ConnectionName {
			return definitions[i].MCPName < definitions[j].MCPName
		}
		return definitions[i].ConnectionName < definitions[j].ConnectionName
	})

	return definitions, index, nil
}

func (s *Service) ListConnectionToolDefinitions(
	ctx context.Context,
	connection *store.Connection,
) ([]ToolDefinition, error) {
	if connection == nil {
		return nil, fmt.Errorf("connection is nil")
	}

	session, err := s.sessionDefinitionFromConnection(connection)
	if err != nil {
		return nil, err
	}

	tools, refreshedTokens, err := s.client.ListTools(ctx, session)
	if refreshedTokens != nil {
		if err := s.persistTokenSet(ctx, connection, refreshedTokens); err != nil {
			return nil, err
		}
	}
	if err != nil {
		connection.Status = statusFromError(err)
		connection.LastError = err.Error()
		_ = s.store.UpdateConnection(ctx, connection)
		return nil, err
	}

	definitions := toolDefinitionsForConnection(connection, tools)
	sort.Slice(definitions, func(i, j int) bool {
		if definitions[i].MCPName == definitions[j].MCPName {
			return definitions[i].FunctionName < definitions[j].FunctionName
		}
		return definitions[i].MCPName < definitions[j].MCPName
	})
	return definitions, nil
}

func (s *Service) CallTool(
	ctx context.Context,
	definition ToolDefinition,
	args map[string]any,
) (string, error) {
	connection, err := s.store.GetConnectionByIDAny(ctx, definition.ConnectionID)
	if err != nil {
		return "", err
	}

	session, err := s.sessionDefinitionFromConnection(connection)
	if err != nil {
		return "", err
	}

	result, refreshedTokens, err := s.client.CallTool(
		ctx,
		session,
		definition.MCPName,
		args,
	)
	if refreshedTokens != nil {
		if err := s.persistTokenSet(ctx, connection, refreshedTokens); err != nil {
			return "", err
		}
	}
	if err != nil {
		connection.Status = statusFromError(err)
		connection.LastError = err.Error()
		_ = s.store.UpdateConnection(ctx, connection)
		return "", err
	}
	return result, nil
}

func (s *Service) persistAuthorization(
	ctx context.Context,
	server *store.MCPServer,
	connection *store.Connection,
	authResult *mcpclient.AuthorizationResult,
) error {
	if authResult == nil {
		return fmt.Errorf("authorization result is nil")
	}
	if err := s.applyServerDefinition(server, authResult.Server); err != nil {
		return err
	}
	if err := s.store.UpdateMCPServer(ctx, server); err != nil {
		return err
	}

	applyServerToConnection(connection, server)
	connection.Status = "authorizing"
	connection.LastError = ""
	connection.Scopes = sanitizeScopes(authResult.Scopes)
	if err := s.store.UpdateConnection(ctx, connection); err != nil {
		return err
	}

	return s.store.SaveOAuthState(ctx, store.OAuthState{
		State:        authResult.State,
		ConnectionID: connection.ID,
		CodeVerifier: authResult.CodeVerifier,
		RedirectURI:  authResult.RedirectURI,
		ExpiresAt:    time.Now().UTC().Add(15 * time.Minute),
	})
}

func (s *Service) verifyConnection(
	ctx context.Context,
	connection *store.Connection,
) error {
	session, err := s.sessionDefinitionFromConnection(connection)
	if err != nil {
		return err
	}

	_, refreshedTokens, err := s.client.ListTools(ctx, session)
	if refreshedTokens != nil {
		if err := s.persistTokenSet(ctx, connection, refreshedTokens); err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	connection.Status = "connected"
	connection.LastError = ""
	connection.LastVerifiedAt = &now
	return s.store.UpdateConnection(ctx, connection)
}

func (s *Service) ensureServerForConnection(
	ctx context.Context,
	connection *store.Connection,
) (*store.MCPServer, error) {
	if connection == nil {
		return nil, fmt.Errorf("connection is nil")
	}

	server, err := s.store.EnsureMCPServer(
		ctx,
		connection.Endpoint,
		connection.CanonicalResource,
	)
	if err != nil {
		return nil, err
	}
	connection.ServerID = server.ID
	applyServerToConnection(connection, server)
	return server, nil
}

func (s *Service) serverDefinitionFromStore(
	server *store.MCPServer,
) (mcpclient.ServerDefinition, error) {
	if server == nil {
		return mcpclient.ServerDefinition{}, fmt.Errorf("mcp server is nil")
	}

	clientSecret := ""
	if server.ClientSecretEnc != "" {
		secret, err := s.crypto.DecryptString(server.ClientSecretEnc)
		if err != nil {
			return mcpclient.ServerDefinition{}, fmt.Errorf(
				"decrypt client secret: %w",
				err,
			)
		}
		clientSecret = secret
	}

	return mcpclient.ServerDefinition{
		Endpoint:                     server.Endpoint,
		CanonicalResource:            server.CanonicalResource,
		AuthRequired:                 server.AuthRequired,
		ProtectedResourceMetadataURL: server.ProtectedResourceMetadataURL,
		AuthorizationServerIssuer:    server.AuthorizationServerIssuer,
		AuthorizationEndpoint:        server.AuthorizationEndpoint,
		TokenEndpoint:                server.TokenEndpoint,
		RegistrationEndpoint:         server.RegistrationEndpoint,
		ClientID:                     server.ClientID,
		ClientSecret:                 clientSecret,
		TokenEndpointAuthMethod:      server.TokenEndpointAuthMethod,
	}, nil
}

func (s *Service) sessionDefinitionFromConnection(
	connection *store.Connection,
) (mcpclient.SessionDefinition, error) {
	if connection == nil {
		return mcpclient.SessionDefinition{}, fmt.Errorf("connection is nil")
	}

	clientSecret := ""
	if connection.ClientSecretEnc != "" {
		secret, err := s.crypto.DecryptString(connection.ClientSecretEnc)
		if err != nil {
			return mcpclient.SessionDefinition{}, fmt.Errorf(
				"decrypt client secret: %w",
				err,
			)
		}
		clientSecret = secret
	}

	accessToken := ""
	if connection.AccessTokenEnc != "" {
		token, err := s.crypto.DecryptString(connection.AccessTokenEnc)
		if err != nil {
			return mcpclient.SessionDefinition{}, fmt.Errorf(
				"decrypt access token: %w",
				err,
			)
		}
		accessToken = token
	}

	refreshToken := ""
	if connection.RefreshTokenEnc != "" {
		token, err := s.crypto.DecryptString(connection.RefreshTokenEnc)
		if err != nil {
			return mcpclient.SessionDefinition{}, fmt.Errorf(
				"decrypt refresh token: %w",
				err,
			)
		}
		refreshToken = token
	}

	return mcpclient.SessionDefinition{
		Name:         connection.Name,
		Scopes:       sanitizeScopes(connection.Scopes),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenExpiry:  connection.TokenExpiry,
		Server: mcpclient.ServerDefinition{
			Endpoint:                     connection.Endpoint,
			CanonicalResource:            connection.CanonicalResource,
			AuthRequired:                 connection.AuthRequired,
			ProtectedResourceMetadataURL: connection.ProtectedResourceMetadataURL,
			AuthorizationServerIssuer:    connection.AuthorizationServerIssuer,
			AuthorizationEndpoint:        connection.AuthorizationEndpoint,
			TokenEndpoint:                connection.TokenEndpoint,
			RegistrationEndpoint:         connection.RegistrationEndpoint,
			ClientID:                     connection.ClientID,
			ClientSecret:                 clientSecret,
			TokenEndpointAuthMethod:      connection.TokenEndpointAuthMethod,
		},
	}, nil
}

func (s *Service) applyServerDefinition(
	server *store.MCPServer,
	definition mcpclient.ServerDefinition,
) error {
	if server == nil {
		return fmt.Errorf("mcp server is nil")
	}

	server.Endpoint = definition.Endpoint
	server.CanonicalResource = definition.CanonicalResource
	server.AuthRequired = definition.AuthRequired
	if definition.ProtectedResourceMetadataURL != "" || !definition.AuthRequired {
		server.ProtectedResourceMetadataURL = definition.ProtectedResourceMetadataURL
	}
	if definition.AuthorizationServerIssuer != "" {
		server.AuthorizationServerIssuer = definition.AuthorizationServerIssuer
	}
	if definition.AuthorizationEndpoint != "" {
		server.AuthorizationEndpoint = definition.AuthorizationEndpoint
	}
	if definition.TokenEndpoint != "" {
		server.TokenEndpoint = definition.TokenEndpoint
	}
	if definition.RegistrationEndpoint != "" {
		server.RegistrationEndpoint = definition.RegistrationEndpoint
	}
	if definition.ClientID != "" {
		server.ClientID = definition.ClientID
	}
	if definition.ClientSecret != "" {
		clientSecretEnc, err := s.crypto.EncryptString(definition.ClientSecret)
		if err != nil {
			return fmt.Errorf("encrypt client secret: %w", err)
		}
		server.ClientSecretEnc = clientSecretEnc
	}
	if definition.TokenEndpointAuthMethod != "" {
		server.TokenEndpointAuthMethod = definition.TokenEndpointAuthMethod
	}
	return nil
}

func (s *Service) persistTokenSet(
	ctx context.Context,
	connection *store.Connection,
	tokenSet *mcpclient.TokenSet,
) error {
	if connection == nil || tokenSet == nil {
		return nil
	}

	accessTokenEnc, err := s.crypto.EncryptString(tokenSet.AccessToken)
	if err != nil {
		return fmt.Errorf("encrypt access token: %w", err)
	}
	refreshTokenEnc, err := s.crypto.EncryptString(tokenSet.RefreshToken)
	if err != nil {
		return fmt.Errorf("encrypt refresh token: %w", err)
	}

	connection.AccessTokenEnc = accessTokenEnc
	connection.RefreshTokenEnc = refreshTokenEnc
	connection.TokenExpiry = tokenSet.ExpiresAt
	connection.LastError = ""
	return s.store.UpdateConnection(ctx, connection)
}

func parametersForTool(
	tool *mcp.Tool,
) map[string]any {
	parameters := map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
	if tool == nil || tool.InputSchema == nil {
		return parameters
	}

	if typed, ok := any(tool.InputSchema).(map[string]any); ok {
		return typed
	}

	rawSchema, err := json.Marshal(tool.InputSchema)
	if err != nil {
		return parameters
	}
	_ = json.Unmarshal(rawSchema, &parameters)
	return parameters
}

func toolDefinitionsForConnection(
	connection *store.Connection,
	tools []*mcp.Tool,
) []ToolDefinition {
	definitions := make([]ToolDefinition, 0, len(tools))
	for _, tool := range tools {
		if tool == nil {
			continue
		}

		definition := ToolDefinition{
			FunctionName:   makeFunctionName(connection.ID, tool.Name),
			ConnectionID:   connection.ID,
			ConnectionName: connection.Name,
			MCPName:        tool.Name,
			Description:    strings.TrimSpace(tool.Description),
			Parameters:     parametersForTool(tool),
		}
		if definition.Description == "" {
			definition.Description = fmt.Sprintf("%s via %s", tool.Name, connection.Name)
		}
		definitions = append(definitions, definition)
	}
	return definitions
}

func applyServerToConnection(
	connection *store.Connection,
	server *store.MCPServer,
) {
	if connection == nil || server == nil {
		return
	}
	connection.ServerID = server.ID
	connection.Endpoint = server.Endpoint
	connection.CanonicalResource = server.CanonicalResource
	connection.AuthRequired = server.AuthRequired
	connection.ProtectedResourceMetadataURL = server.ProtectedResourceMetadataURL
	connection.AuthorizationServerIssuer = server.AuthorizationServerIssuer
	connection.AuthorizationEndpoint = server.AuthorizationEndpoint
	connection.TokenEndpoint = server.TokenEndpoint
	connection.RegistrationEndpoint = server.RegistrationEndpoint
	connection.ClientID = server.ClientID
	connection.ClientSecretEnc = server.ClientSecretEnc
	connection.TokenEndpointAuthMethod = server.TokenEndpointAuthMethod
}

func defaultConnectionName(
	endpoint string,
) string {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return endpoint
	}
	name := parsed.Host
	if parsed.Path != "" && parsed.Path != "/" && parsed.Path != "/mcp" {
		name += parsed.Path
	}
	return name
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

func makeFunctionName(
	connectionID string,
	toolName string,
) string {
	hash := sha1.Sum([]byte(connectionID + ":" + toolName))
	prefix := "mcp_" + hex.EncodeToString(hash[:4]) + "_"
	safeTool := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		case r >= '0' && r <= '9':
			return r
		case r == '_':
			return r
		default:
			return '_'
		}
	}, toolName)
	safeTool = strings.Trim(safeTool, "_")
	if safeTool == "" {
		safeTool = "tool"
	}
	if len(safeTool) > 40 {
		safeTool = safeTool[:40]
	}
	return prefix + safeTool
}

func statusFromError(
	err error,
) string {
	if err == nil {
		return "connected"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "401") ||
		strings.Contains(message, "403") ||
		strings.Contains(message, "authorization") {
		return "needs_auth"
	}
	return "error"
}

package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("not found")

const resetMarkerTable = "app_first_start_resets"

type Store struct {
	pool *pgxpool.Pool
}

type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type UserAuthRecord struct {
	User
	PasswordHash string
}

type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Conversation struct {
	ID                   string    `json:"id"`
	UserID               string    `json:"user_id"`
	Title                string    `json:"title"`
	LastOpenAIResponseID string    `json:"last_openai_response_id,omitempty"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type Message struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversation_id"`
	Role           string    `json:"role"`
	Content        string    `json:"content"`
	CreatedAt      time.Time `json:"created_at"`
}

type MCPServer struct {
	ID                           string    `json:"id"`
	Endpoint                     string    `json:"endpoint"`
	CanonicalResource            string    `json:"canonical_resource"`
	AuthRequired                 bool      `json:"auth_required"`
	ProtectedResourceMetadataURL string    `json:"protected_resource_metadata_url,omitempty"`
	AuthorizationServerIssuer    string    `json:"authorization_server_issuer,omitempty"`
	AuthorizationEndpoint        string    `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                string    `json:"token_endpoint,omitempty"`
	RegistrationEndpoint         string    `json:"registration_endpoint,omitempty"`
	ClientID                     string    `json:"client_id,omitempty"`
	ClientSecretEnc              string    `json:"-"`
	TokenEndpointAuthMethod      string    `json:"token_endpoint_auth_method,omitempty"`
	CreatedAt                    time.Time `json:"created_at"`
	UpdatedAt                    time.Time `json:"updated_at"`
}

type Connection struct {
	ID                           string     `json:"id"`
	UserID                       string     `json:"user_id"`
	ServerID                     string     `json:"server_id,omitempty"`
	Name                         string     `json:"name"`
	Endpoint                     string     `json:"endpoint"`
	CanonicalResource            string     `json:"canonical_resource"`
	Status                       string     `json:"status"`
	Scopes                       []string   `json:"scopes"`
	AuthRequired                 bool       `json:"auth_required"`
	ProtectedResourceMetadataURL string     `json:"protected_resource_metadata_url,omitempty"`
	AuthorizationServerIssuer    string     `json:"authorization_server_issuer,omitempty"`
	AuthorizationEndpoint        string     `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                string     `json:"token_endpoint,omitempty"`
	RegistrationEndpoint         string     `json:"registration_endpoint,omitempty"`
	ClientID                     string     `json:"client_id,omitempty"`
	ClientSecretEnc              string     `json:"-"`
	TokenEndpointAuthMethod      string     `json:"token_endpoint_auth_method,omitempty"`
	AccessTokenEnc               string     `json:"-"`
	RefreshTokenEnc              string     `json:"-"`
	TokenExpiry                  *time.Time `json:"token_expiry,omitempty"`
	LastError                    string     `json:"last_error,omitempty"`
	CreatedAt                    time.Time  `json:"created_at"`
	UpdatedAt                    time.Time  `json:"updated_at"`
	LastVerifiedAt               *time.Time `json:"last_verified_at,omitempty"`
}

type CreateConnectionParams struct {
	UserID            string
	ServerID          string
	Name              string
	Endpoint          string
	CanonicalResource string
	Scopes            []string
}

type OAuthState struct {
	State        string
	ConnectionID string
	CodeVerifier string
	RedirectURI  string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

func New(
	ctx context.Context,
	databaseURL string,
) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	return &Store{pool: pool}, nil
}

func ResetDatabaseOnFirstStart(
	ctx context.Context,
	databaseURL string,
) error {
	targetDatabase, adminConfig, err := resetDatabaseAdminConfig(databaseURL)
	if err != nil {
		return err
	}

	conn, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		return fmt.Errorf("connect admin database: %w", err)
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(
		ctx,
		fmt.Sprintf(
			`create table if not exists %s (
			    database_name text primary key,
			    reset_at timestamptz not null default now()
			)`,
			pgx.Identifier{resetMarkerTable}.Sanitize(),
		),
	); err != nil {
		return fmt.Errorf("create reset marker table: %w", err)
	}

	var alreadyReset bool
	err = conn.QueryRow(
		ctx,
		fmt.Sprintf(
			`select exists(select 1 from %s where database_name = $1)`,
			pgx.Identifier{resetMarkerTable}.Sanitize(),
		),
		targetDatabase,
	).Scan(&alreadyReset)
	if err != nil {
		return fmt.Errorf("check reset marker: %w", err)
	}
	if alreadyReset {
		return nil
	}

	if _, err := conn.Exec(
		ctx,
		`select pg_terminate_backend(pid)
		 from pg_stat_activity
		 where datname = $1 and pid <> pg_backend_pid()`,
		targetDatabase,
	); err != nil {
		return fmt.Errorf("terminate database sessions: %w", err)
	}

	databaseIdentifier := pgx.Identifier{targetDatabase}.Sanitize()
	if _, err := conn.Exec(ctx, "drop database if exists "+databaseIdentifier); err != nil {
		return fmt.Errorf("drop database %q: %w", targetDatabase, err)
	}
	if _, err := conn.Exec(ctx, "create database "+databaseIdentifier); err != nil {
		return fmt.Errorf("create database %q: %w", targetDatabase, err)
	}

	if _, err := conn.Exec(
		ctx,
		fmt.Sprintf(
			`insert into %s (database_name) values ($1)
			 on conflict (database_name) do nothing`,
			pgx.Identifier{resetMarkerTable}.Sanitize(),
		),
		targetDatabase,
	); err != nil {
		return fmt.Errorf("record reset marker: %w", err)
	}

	return nil
}

func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

func resetDatabaseAdminConfig(
	databaseURL string,
) (string, *pgx.ConnConfig, error) {
	targetConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return "", nil, fmt.Errorf("parse database url: %w", err)
	}

	targetDatabase := strings.TrimSpace(targetConfig.Database)
	if err := validateResetDatabaseTarget(targetDatabase); err != nil {
		return "", nil, err
	}

	adminConfig := targetConfig.Copy()
	adminConfig.Database = "postgres"
	return targetDatabase, adminConfig, nil
}

func validateResetDatabaseTarget(
	databaseName string,
) error {
	switch strings.TrimSpace(databaseName) {
	case "":
		return fmt.Errorf("database name is empty")
	case "postgres", "template0", "template1":
		return fmt.Errorf("database %q cannot be reset on first start", databaseName)
	default:
		return nil
	}
}

func (s *Store) Migrate(ctx context.Context) error {
	const schema = `
create table if not exists users (
    id text primary key,
    email text not null unique,
    password_hash text not null,
    created_at timestamptz not null default now()
);

create table if not exists sessions (
    token text primary key,
    user_id text not null references users(id) on delete cascade,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);

create index if not exists sessions_expires_at_idx on sessions (expires_at);

create table if not exists conversations (
    id text primary key,
    user_id text not null unique references users(id) on delete cascade,
    title text not null,
    last_openai_response_id text not null default '',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists messages (
    id text primary key,
    conversation_id text not null references conversations(id) on delete cascade,
    role text not null,
    content text not null,
    created_at timestamptz not null default now()
);

create index if not exists messages_conversation_created_at_idx on messages (conversation_id, created_at);

create table if not exists mcp_servers (
    id text primary key,
    endpoint text not null,
    canonical_resource text not null unique,
    auth_required boolean not null default false,
    protected_resource_metadata_url text not null default '',
    authorization_server_issuer text not null default '',
    authorization_endpoint text not null default '',
    token_endpoint text not null default '',
    registration_endpoint text not null default '',
    client_id text not null default '',
    client_secret_enc text not null default '',
    token_endpoint_auth_method text not null default '',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists mcp_servers_endpoint_idx on mcp_servers (endpoint);

create table if not exists mcp_connections (
    id text primary key,
    user_id text not null references users(id) on delete cascade,
    server_id text,
    name text not null,
    endpoint text not null,
    canonical_resource text not null,
    status text not null,
    scopes text[] not null default '{}',
    auth_required boolean not null default false,
    protected_resource_metadata_url text not null default '',
    authorization_server_issuer text not null default '',
    authorization_endpoint text not null default '',
    token_endpoint text not null default '',
    registration_endpoint text not null default '',
    client_id text not null default '',
    client_secret_enc text not null default '',
    token_endpoint_auth_method text not null default '',
    access_token_enc text not null default '',
    refresh_token_enc text not null default '',
    token_expiry timestamptz,
    last_error text not null default '',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    last_verified_at timestamptz
);

create index if not exists mcp_connections_user_updated_at_idx on mcp_connections (user_id, updated_at desc);
create index if not exists mcp_connections_server_id_idx on mcp_connections (server_id);

insert into mcp_servers (
    id,
    endpoint,
    canonical_resource,
    auth_required,
    protected_resource_metadata_url,
    authorization_server_issuer,
    authorization_endpoint,
    token_endpoint,
    registration_endpoint,
    client_id,
    client_secret_enc,
    token_endpoint_auth_method
)
select
    seed.id,
    seed.endpoint,
    seed.canonical_resource,
    seed.auth_required,
    seed.protected_resource_metadata_url,
    seed.authorization_server_issuer,
    seed.authorization_endpoint,
    seed.token_endpoint,
    seed.registration_endpoint,
    seed.client_id,
    seed.client_secret_enc,
    seed.token_endpoint_auth_method
from (
    select distinct on (c.canonical_resource)
        c.id,
        c.endpoint,
        c.canonical_resource,
        c.auth_required,
        c.protected_resource_metadata_url,
        c.authorization_server_issuer,
        c.authorization_endpoint,
        c.token_endpoint,
        c.registration_endpoint,
        c.client_id,
        c.client_secret_enc,
        c.token_endpoint_auth_method
    from mcp_connections c
    where c.canonical_resource <> ''
    order by
        c.canonical_resource,
        c.client_id <> '' desc,
        c.client_secret_enc <> '' desc,
        c.authorization_server_issuer <> '' desc,
        c.authorization_endpoint <> '' desc,
        c.token_endpoint <> '' desc,
        c.registration_endpoint <> '' desc,
        c.protected_resource_metadata_url <> '' desc,
        c.auth_required desc,
        c.updated_at desc,
        c.created_at desc,
        c.id asc
) seed
on conflict (canonical_resource) do update
set endpoint = excluded.endpoint,
    auth_required = mcp_servers.auth_required or excluded.auth_required,
    protected_resource_metadata_url = coalesce(
        nullif(mcp_servers.protected_resource_metadata_url, ''),
        excluded.protected_resource_metadata_url
    ),
    authorization_server_issuer = coalesce(
        nullif(mcp_servers.authorization_server_issuer, ''),
        excluded.authorization_server_issuer
    ),
    authorization_endpoint = coalesce(nullif(mcp_servers.authorization_endpoint, ''), excluded.authorization_endpoint),
    token_endpoint = coalesce(nullif(mcp_servers.token_endpoint, ''), excluded.token_endpoint),
    registration_endpoint = coalesce(nullif(mcp_servers.registration_endpoint, ''), excluded.registration_endpoint),
    client_id = coalesce(nullif(mcp_servers.client_id, ''), excluded.client_id),
    client_secret_enc = coalesce(nullif(mcp_servers.client_secret_enc, ''), excluded.client_secret_enc),
    token_endpoint_auth_method = coalesce(
        nullif(mcp_servers.token_endpoint_auth_method, ''),
        excluded.token_endpoint_auth_method
    ),
    updated_at = now();

update mcp_connections c
set server_id = s.id
from mcp_servers s
where c.server_id is null
  and c.canonical_resource = s.canonical_resource;

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conname = 'mcp_connections_server_id_fkey'
    ) then
        alter table mcp_connections
        add constraint mcp_connections_server_id_fkey
        foreign key (server_id) references mcp_servers(id) on delete cascade;
    end if;
end
$$;

create table if not exists oauth_states (
    state text primary key,
    connection_id text not null references mcp_connections(id) on delete cascade,
    code_verifier text not null,
    redirect_uri text not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);

create index if not exists oauth_states_expires_at_idx on oauth_states (expires_at);
`
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("migrate schema: %w", err)
	}
	return nil
}

func (s *Store) EnsureBootstrapUser(
	ctx context.Context,
	email string,
	passwordHash string,
) (*User, error) {
	record, err := s.GetUserAuthRecordByEmail(ctx, email)
	if err == nil {
		return &record.User, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}

	user := &User{
		ID:    newID(),
		Email: email,
	}
	if err := s.pool.QueryRow(
		ctx,
		`insert into users (id, email, password_hash) values ($1, $2, $3) returning created_at`,
		user.ID,
		email,
		passwordHash,
	).Scan(&user.CreatedAt); err != nil {
		return nil, fmt.Errorf("insert bootstrap user: %w", err)
	}
	return user, nil
}

func (s *Store) GetUserAuthRecordByEmail(
	ctx context.Context,
	email string,
) (*UserAuthRecord, error) {
	record := &UserAuthRecord{}
	err := s.pool.QueryRow(
		ctx,
		`select id, email, password_hash, created_at from users where email = $1`,
		email,
	).Scan(&record.ID, &record.Email, &record.PasswordHash, &record.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return record, nil
}

func (s *Store) CreateSession(
	ctx context.Context,
	userID string,
	ttl time.Duration,
) (*Session, error) {
	session := &Session{
		Token:     newToken(32),
		UserID:    userID,
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	if _, err := s.pool.Exec(
		ctx,
		`insert into sessions (token, user_id, expires_at) values ($1, $2, $3)`,
		session.Token,
		session.UserID,
		session.ExpiresAt,
	); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return session, nil
}

func (s *Store) DeleteSession(
	ctx context.Context,
	token string,
) error {
	if _, err := s.pool.Exec(ctx, `delete from sessions where token = $1`, token); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *Store) GetUserBySessionToken(
	ctx context.Context,
	token string,
) (*User, error) {
	user := &User{}
	err := s.pool.QueryRow(
		ctx,
		`select u.id, u.email, u.created_at
		 from sessions s
		 join users u on u.id = s.user_id
		 where s.token = $1 and s.expires_at > now()`,
		token,
	).Scan(&user.ID, &user.Email, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get user by session token: %w", err)
	}
	return user, nil
}

func (s *Store) GetOrCreatePrimaryConversation(
	ctx context.Context,
	userID string,
) (*Conversation, error) {
	conversation := &Conversation{}
	err := s.pool.QueryRow(
		ctx,
		`select id, user_id, title, last_openai_response_id, created_at, updated_at
		 from conversations where user_id = $1`,
		userID,
	).Scan(
		&conversation.ID,
		&conversation.UserID,
		&conversation.Title,
		&conversation.LastOpenAIResponseID,
		&conversation.CreatedAt,
		&conversation.UpdatedAt,
	)
	if err == nil {
		return conversation, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get primary conversation: %w", err)
	}

	conversation.ID = newID()
	conversation.UserID = userID
	conversation.Title = "Primary conversation"
	if err := s.pool.QueryRow(
		ctx,
		`insert into conversations (id, user_id, title) values ($1, $2, $3)
		 returning last_openai_response_id, created_at, updated_at`,
		conversation.ID,
		conversation.UserID,
		conversation.Title,
	).Scan(
		&conversation.LastOpenAIResponseID,
		&conversation.CreatedAt,
		&conversation.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("create primary conversation: %w", err)
	}
	return conversation, nil
}

func (s *Store) ListMessages(
	ctx context.Context,
	conversationID string,
	limit int,
) ([]Message, error) {
	rows, err := s.pool.Query(
		ctx,
		`select id, conversation_id, role, content, created_at
		 from messages
		 where conversation_id = $1
		 order by created_at asc
		 limit $2`,
		conversationID,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list messages: %w", err)
	}
	defer rows.Close()

	messages := make([]Message, 0)
	for rows.Next() {
		var message Message
		if err := rows.Scan(
			&message.ID,
			&message.ConversationID,
			&message.Role,
			&message.Content,
			&message.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan message: %w", err)
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate messages: %w", err)
	}
	return messages, nil
}

func (s *Store) AppendMessage(
	ctx context.Context,
	conversationID string,
	role string,
	content string,
) (*Message, error) {
	message := &Message{
		ID:             newID(),
		ConversationID: conversationID,
		Role:           role,
		Content:        content,
	}
	if err := s.pool.QueryRow(
		ctx,
		`insert into messages (id, conversation_id, role, content)
		 values ($1, $2, $3, $4)
		 returning created_at`,
		message.ID,
		message.ConversationID,
		message.Role,
		message.Content,
	).Scan(&message.CreatedAt); err != nil {
		return nil, fmt.Errorf("append message: %w", err)
	}

	if _, err := s.pool.Exec(
		ctx,
		`update conversations set updated_at = now() where id = $1`,
		conversationID,
	); err != nil {
		return nil, fmt.Errorf("touch conversation: %w", err)
	}
	return message, nil
}

func (s *Store) UpdateConversationResponse(
	ctx context.Context,
	conversationID string,
	responseID string,
) error {
	if _, err := s.pool.Exec(
		ctx,
		`update conversations
		 set last_openai_response_id = $2, updated_at = now()
		 where id = $1`,
		conversationID,
		responseID,
	); err != nil {
		return fmt.Errorf("update conversation response id: %w", err)
	}
	return nil
}

func (s *Store) EnsureMCPServer(
	ctx context.Context,
	endpoint string,
	canonicalResource string,
) (*MCPServer, error) {
	server := &MCPServer{}
	err := s.pool.QueryRow(
		ctx,
		`insert into mcp_servers (id, endpoint, canonical_resource)
		 values ($1, $2, $3)
		 on conflict (canonical_resource) do update
		 set endpoint = excluded.endpoint,
		     updated_at = now()
		 returning id, endpoint, canonical_resource, auth_required,
		           protected_resource_metadata_url, authorization_server_issuer,
		           authorization_endpoint, token_endpoint, registration_endpoint,
		           client_id, client_secret_enc, token_endpoint_auth_method,
		           created_at, updated_at`,
		newID(),
		endpoint,
		canonicalResource,
	).Scan(
		&server.ID,
		&server.Endpoint,
		&server.CanonicalResource,
		&server.AuthRequired,
		&server.ProtectedResourceMetadataURL,
		&server.AuthorizationServerIssuer,
		&server.AuthorizationEndpoint,
		&server.TokenEndpoint,
		&server.RegistrationEndpoint,
		&server.ClientID,
		&server.ClientSecretEnc,
		&server.TokenEndpointAuthMethod,
		&server.CreatedAt,
		&server.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("ensure mcp server: %w", err)
	}
	return server, nil
}

func (s *Store) UpdateMCPServer(
	ctx context.Context,
	server *MCPServer,
) error {
	if server == nil {
		return fmt.Errorf("mcp server is nil")
	}
	if _, err := s.pool.Exec(
		ctx,
		`update mcp_servers
		 set endpoint = $2,
		     canonical_resource = $3,
		     auth_required = $4,
		     protected_resource_metadata_url = $5,
		     authorization_server_issuer = $6,
		     authorization_endpoint = $7,
		     token_endpoint = $8,
		     registration_endpoint = $9,
		     client_id = $10,
		     client_secret_enc = $11,
		     token_endpoint_auth_method = $12,
		     updated_at = now()
		 where id = $1`,
		server.ID,
		server.Endpoint,
		server.CanonicalResource,
		server.AuthRequired,
		server.ProtectedResourceMetadataURL,
		server.AuthorizationServerIssuer,
		server.AuthorizationEndpoint,
		server.TokenEndpoint,
		server.RegistrationEndpoint,
		server.ClientID,
		server.ClientSecretEnc,
		server.TokenEndpointAuthMethod,
	); err != nil {
		return fmt.Errorf("update mcp server: %w", err)
	}
	return nil
}

func (s *Store) CreateConnection(
	ctx context.Context,
	params CreateConnectionParams,
) (*Connection, error) {
	connection := &Connection{
		ServerID:          params.ServerID,
		ID:                newID(),
		UserID:            params.UserID,
		Name:              params.Name,
		Endpoint:          params.Endpoint,
		CanonicalResource: params.CanonicalResource,
		Status:            "discovering",
		Scopes:            params.Scopes,
	}
	err := s.pool.QueryRow(
		ctx,
		`insert into mcp_connections (
		     id, user_id, server_id, name, endpoint, canonical_resource, status, scopes
		 )
		 values ($1, $2, $3, $4, $5, $6, $7, $8)
		 returning created_at, updated_at`,
		connection.ID,
		connection.UserID,
		connection.ServerID,
		connection.Name,
		connection.Endpoint,
		connection.CanonicalResource,
		connection.Status,
		connection.Scopes,
	).Scan(&connection.CreatedAt, &connection.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create connection: %w", err)
	}
	return connection, nil
}

func (s *Store) ListConnections(
	ctx context.Context,
	userID string,
) ([]Connection, error) {
	rows, err := s.pool.Query(
		ctx,
		`select c.id, c.user_id, c.server_id, c.name,
		        coalesce(s.endpoint, c.endpoint) as endpoint,
		        coalesce(s.canonical_resource, c.canonical_resource) as canonical_resource,
		        c.status, c.scopes,
		        coalesce(s.auth_required, c.auth_required) as auth_required,
		        coalesce(
		            nullif(s.protected_resource_metadata_url, ''),
		            c.protected_resource_metadata_url
		        ) as protected_resource_metadata_url,
		        coalesce(
		            nullif(s.authorization_server_issuer, ''),
		            c.authorization_server_issuer
		        ) as authorization_server_issuer,
		        coalesce(nullif(s.authorization_endpoint, ''), c.authorization_endpoint) as authorization_endpoint,
		        coalesce(nullif(s.token_endpoint, ''), c.token_endpoint) as token_endpoint,
		        coalesce(nullif(s.registration_endpoint, ''), c.registration_endpoint) as registration_endpoint,
		        coalesce(nullif(s.client_id, ''), c.client_id) as client_id,
		        coalesce(nullif(s.client_secret_enc, ''), c.client_secret_enc) as client_secret_enc,
		        coalesce(
		            nullif(s.token_endpoint_auth_method, ''),
		            c.token_endpoint_auth_method
		        ) as token_endpoint_auth_method,
		        c.access_token_enc, c.refresh_token_enc, c.token_expiry, c.last_error,
		        c.created_at, c.updated_at, c.last_verified_at
		 from mcp_connections c
		 left join mcp_servers s on s.id = c.server_id
		 where c.user_id = $1
		 order by c.created_at desc`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list connections: %w", err)
	}
	defer rows.Close()

	connections := make([]Connection, 0)
	for rows.Next() {
		connection, err := scanConnection(rows)
		if err != nil {
			return nil, err
		}
		connections = append(connections, *connection)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate connections: %w", err)
	}
	return connections, nil
}

func (s *Store) GetConnectionByID(
	ctx context.Context,
	userID string,
	connectionID string,
) (*Connection, error) {
	row := s.pool.QueryRow(
		ctx,
		`select c.id, c.user_id, c.server_id, c.name,
		        coalesce(s.endpoint, c.endpoint) as endpoint,
		        coalesce(s.canonical_resource, c.canonical_resource) as canonical_resource,
		        c.status, c.scopes,
		        coalesce(s.auth_required, c.auth_required) as auth_required,
		        coalesce(
		            nullif(s.protected_resource_metadata_url, ''),
		            c.protected_resource_metadata_url
		        ) as protected_resource_metadata_url,
		        coalesce(
		            nullif(s.authorization_server_issuer, ''),
		            c.authorization_server_issuer
		        ) as authorization_server_issuer,
		        coalesce(nullif(s.authorization_endpoint, ''), c.authorization_endpoint) as authorization_endpoint,
		        coalesce(nullif(s.token_endpoint, ''), c.token_endpoint) as token_endpoint,
		        coalesce(nullif(s.registration_endpoint, ''), c.registration_endpoint) as registration_endpoint,
		        coalesce(nullif(s.client_id, ''), c.client_id) as client_id,
		        coalesce(nullif(s.client_secret_enc, ''), c.client_secret_enc) as client_secret_enc,
		        coalesce(
		            nullif(s.token_endpoint_auth_method, ''),
		            c.token_endpoint_auth_method
		        ) as token_endpoint_auth_method,
		        c.access_token_enc, c.refresh_token_enc, c.token_expiry, c.last_error,
		        c.created_at, c.updated_at, c.last_verified_at
		 from mcp_connections c
		 left join mcp_servers s on s.id = c.server_id
		 where c.id = $1 and c.user_id = $2`,
		connectionID,
		userID,
	)
	connection, err := scanConnection(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("get connection by id: %w", err)
	}
	return connection, nil
}

func (s *Store) GetConnectionByIDAny(
	ctx context.Context,
	connectionID string,
) (*Connection, error) {
	row := s.pool.QueryRow(
		ctx,
		`select c.id, c.user_id, c.server_id, c.name,
		        coalesce(s.endpoint, c.endpoint) as endpoint,
		        coalesce(s.canonical_resource, c.canonical_resource) as canonical_resource,
		        c.status, c.scopes,
		        coalesce(s.auth_required, c.auth_required) as auth_required,
		        coalesce(
		            nullif(s.protected_resource_metadata_url, ''),
		            c.protected_resource_metadata_url
		        ) as protected_resource_metadata_url,
		        coalesce(
		            nullif(s.authorization_server_issuer, ''),
		            c.authorization_server_issuer
		        ) as authorization_server_issuer,
		        coalesce(nullif(s.authorization_endpoint, ''), c.authorization_endpoint) as authorization_endpoint,
		        coalesce(nullif(s.token_endpoint, ''), c.token_endpoint) as token_endpoint,
		        coalesce(nullif(s.registration_endpoint, ''), c.registration_endpoint) as registration_endpoint,
		        coalesce(nullif(s.client_id, ''), c.client_id) as client_id,
		        coalesce(nullif(s.client_secret_enc, ''), c.client_secret_enc) as client_secret_enc,
		        coalesce(
		            nullif(s.token_endpoint_auth_method, ''),
		            c.token_endpoint_auth_method
		        ) as token_endpoint_auth_method,
		        c.access_token_enc, c.refresh_token_enc, c.token_expiry, c.last_error,
		        c.created_at, c.updated_at, c.last_verified_at
		 from mcp_connections c
		 left join mcp_servers s on s.id = c.server_id
		 where c.id = $1`,
		connectionID,
	)
	connection, err := scanConnection(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("get connection by id: %w", err)
	}
	return connection, nil
}

func (s *Store) UpdateConnection(
	ctx context.Context,
	connection *Connection,
) error {
	if connection == nil {
		return fmt.Errorf("connection is nil")
	}
	if _, err := s.pool.Exec(
		ctx,
		`update mcp_connections
		 set server_id = $2,
		     name = $3,
		     status = $4,
		     scopes = $5,
		     auth_required = $6,
		     access_token_enc = $7,
		     refresh_token_enc = $8,
		     token_expiry = $9,
		     last_error = $10,
		     updated_at = now(),
		     last_verified_at = $11
		 where id = $1`,
		connection.ID,
		connection.ServerID,
		connection.Name,
		connection.Status,
		connection.Scopes,
		connection.AuthRequired,
		connection.AccessTokenEnc,
		connection.RefreshTokenEnc,
		connection.TokenExpiry,
		connection.LastError,
		connection.LastVerifiedAt,
	); err != nil {
		return fmt.Errorf("update connection: %w", err)
	}
	return nil
}

func (s *Store) SaveOAuthState(
	ctx context.Context,
	oauthState OAuthState,
) error {
	if _, err := s.pool.Exec(
		ctx,
		`insert into oauth_states (state, connection_id, code_verifier, redirect_uri, expires_at)
		 values ($1, $2, $3, $4, $5)
		 on conflict (state) do update
		 set connection_id = excluded.connection_id,
		     code_verifier = excluded.code_verifier,
		     redirect_uri = excluded.redirect_uri,
		     expires_at = excluded.expires_at,
		     created_at = now()`,
		oauthState.State,
		oauthState.ConnectionID,
		oauthState.CodeVerifier,
		oauthState.RedirectURI,
		oauthState.ExpiresAt,
	); err != nil {
		return fmt.Errorf("save oauth state: %w", err)
	}
	return nil
}

func (s *Store) GetOAuthState(
	ctx context.Context,
	state string,
) (*OAuthState, error) {
	record := &OAuthState{}
	err := s.pool.QueryRow(
		ctx,
		`select state, connection_id, code_verifier, redirect_uri, created_at, expires_at
		 from oauth_states
		 where state = $1 and expires_at > now()`,
		state,
	).Scan(
		&record.State,
		&record.ConnectionID,
		&record.CodeVerifier,
		&record.RedirectURI,
		&record.CreatedAt,
		&record.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get oauth state: %w", err)
	}
	return record, nil
}

func (s *Store) DeleteOAuthState(
	ctx context.Context,
	state string,
) error {
	if _, err := s.pool.Exec(ctx, `delete from oauth_states where state = $1`, state); err != nil {
		return fmt.Errorf("delete oauth state: %w", err)
	}
	return nil
}

func scanConnection(row interface {
	Scan(dest ...any) error
}) (*Connection, error) {
	connection := &Connection{}
	var tokenExpiry sql.NullTime
	var lastVerifiedAt sql.NullTime

	err := row.Scan(
		&connection.ID,
		&connection.UserID,
		&connection.ServerID,
		&connection.Name,
		&connection.Endpoint,
		&connection.CanonicalResource,
		&connection.Status,
		&connection.Scopes,
		&connection.AuthRequired,
		&connection.ProtectedResourceMetadataURL,
		&connection.AuthorizationServerIssuer,
		&connection.AuthorizationEndpoint,
		&connection.TokenEndpoint,
		&connection.RegistrationEndpoint,
		&connection.ClientID,
		&connection.ClientSecretEnc,
		&connection.TokenEndpointAuthMethod,
		&connection.AccessTokenEnc,
		&connection.RefreshTokenEnc,
		&tokenExpiry,
		&connection.LastError,
		&connection.CreatedAt,
		&connection.UpdatedAt,
		&lastVerifiedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if tokenExpiry.Valid {
		connection.TokenExpiry = &tokenExpiry.Time
	}
	if lastVerifiedAt.Valid {
		connection.LastVerifiedAt = &lastVerifiedAt.Time
	}
	return connection, nil
}

func newID() string {
	return newToken(16)
}

func newToken(
	bytes int,
) string {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

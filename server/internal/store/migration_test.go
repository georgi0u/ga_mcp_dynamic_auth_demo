package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const defaultTestAdminDatabaseURL = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"

func TestMigrateBackfillsServerForDuplicateCanonicalResources(
	t *testing.T,
) {
	ctx := context.Background()
	databaseURL := createTestDatabase(t, ctx)

	db, err := New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t.Cleanup(db.Close)

	if _, err := db.pool.Exec(ctx, `
create table users (
    id text primary key,
    email text not null unique,
    password_hash text not null,
    created_at timestamptz not null default now()
);

create table mcp_connections (
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
`); err != nil {
		t.Fatalf("seed legacy schema: %v", err)
	}

	const canonicalResource = "https://mcp.shop/mcp"
	const preferredServerID = "conn-preferred"

	if _, err := db.pool.Exec(
		ctx,
		`insert into users (id, email, password_hash) values ($1, $2, $3)`,
		"user-1",
		"demo@example.com",
		"hash",
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	if _, err := db.pool.Exec(
		ctx,
		`insert into mcp_connections (
		     id, user_id, name, endpoint, canonical_resource, status,
		     auth_required, authorization_server_issuer, authorization_endpoint,
		     token_endpoint, client_id, created_at, updated_at
		 )
		 values
		     ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13),
		     ($14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)`,
		"conn-legacy",
		"user-1",
		"Legacy connection",
		"https://mcp.shop/mcp",
		canonicalResource,
		"ready",
		false,
		"",
		"",
		"",
		"",
		time.Date(2026, time.April, 4, 10, 0, 0, 0, time.UTC),
		time.Date(2026, time.April, 4, 10, 0, 0, 0, time.UTC),
		preferredServerID,
		"user-1",
		"Preferred connection",
		"https://mcp.shop/mcp",
		canonicalResource,
		"ready",
		true,
		"https://issuer.example.com",
		"https://issuer.example.com/authorize",
		"https://issuer.example.com/token",
		"client-123",
		time.Date(2026, time.April, 5, 10, 0, 0, 0, time.UTC),
		time.Date(2026, time.April, 5, 10, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatalf("insert legacy connections: %v", err)
	}

	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate returned error: %v", err)
	}

	var serverCount int
	if err := db.pool.QueryRow(ctx, `select count(*) from mcp_servers`).Scan(&serverCount); err != nil {
		t.Fatalf("count mcp_servers: %v", err)
	}
	if serverCount != 1 {
		t.Fatalf("expected 1 mcp_server, got %d", serverCount)
	}

	var serverID string
	var clientID string
	var authRequired bool
	if err := db.pool.QueryRow(
		ctx,
		`select id, client_id, auth_required
		 from mcp_servers
		 where canonical_resource = $1`,
		canonicalResource,
	).Scan(&serverID, &clientID, &authRequired); err != nil {
		t.Fatalf("load migrated mcp_server: %v", err)
	}
	if serverID != preferredServerID {
		t.Fatalf("expected server id %q, got %q", preferredServerID, serverID)
	}
	if clientID != "client-123" {
		t.Fatalf("expected migrated client id client-123, got %q", clientID)
	}
	if !authRequired {
		t.Fatalf("expected migrated server to require auth")
	}

	rows, err := db.pool.Query(
		ctx,
		`select server_id from mcp_connections order by id`,
	)
	if err != nil {
		t.Fatalf("query migrated connections: %v", err)
	}
	defer rows.Close()

	var linked int
	for rows.Next() {
		var connectionServerID string
		if err := rows.Scan(&connectionServerID); err != nil {
			t.Fatalf("scan migrated connection: %v", err)
		}
		if connectionServerID != preferredServerID {
			t.Fatalf("expected connection server_id %q, got %q", preferredServerID, connectionServerID)
		}
		linked++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate migrated connections: %v", err)
	}
	if linked != 2 {
		t.Fatalf("expected 2 migrated connections, got %d", linked)
	}
}

func createTestDatabase(
	t *testing.T,
	ctx context.Context,
) string {
	t.Helper()

	adminDatabaseURL := strings.TrimSpace(os.Getenv("MCP_AUTH_TEST_ADMIN_DATABASE_URL"))
	if adminDatabaseURL == "" {
		adminDatabaseURL = defaultTestAdminDatabaseURL
	}

	adminConfig, err := pgx.ParseConfig(adminDatabaseURL)
	if err != nil {
		t.Fatalf("parse admin database url: %v", err)
	}

	adminConn, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Skipf("connect admin database: %v", err)
	}
	t.Cleanup(func() {
		adminConn.Close(ctx)
	})

	databaseName := "mcp_auth_test_" + newID()
	if _, err := adminConn.Exec(ctx, "create database "+pgx.Identifier{databaseName}.Sanitize()); err != nil {
		t.Skipf("create test database: %v", err)
	}

	t.Cleanup(func() {
		if _, err := adminConn.Exec(
			ctx,
			`select pg_terminate_backend(pid)
			 from pg_stat_activity
			 where datname = $1 and pid <> pg_backend_pid()`,
			databaseName,
		); err != nil {
			t.Errorf("terminate test database sessions: %v", err)
		}
		if _, err := adminConn.Exec(ctx, "drop database if exists "+pgx.Identifier{databaseName}.Sanitize()); err != nil {
			t.Errorf("drop test database: %v", err)
		}
	})

	testConfig := adminConfig.Copy()
	testConfig.Database = databaseName
	return testConfig.ConnString()
}

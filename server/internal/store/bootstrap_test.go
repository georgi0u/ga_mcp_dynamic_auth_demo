package store

import "testing"

func TestResetDatabaseAdminConfig(
	t *testing.T,
) {
	t.Parallel()

	targetDatabase, adminConfig, err := resetDatabaseAdminConfig(
		"postgres://postgres:postgres@localhost:5432/mcp_auth?sslmode=disable",
	)
	if err != nil {
		t.Fatalf("resetDatabaseAdminConfig returned error: %v", err)
	}
	if targetDatabase != "mcp_auth" {
		t.Fatalf("expected target database mcp_auth, got %q", targetDatabase)
	}
	if adminConfig.Database != "postgres" {
		t.Fatalf("expected admin database postgres, got %q", adminConfig.Database)
	}
	if adminConfig.Host != "localhost" {
		t.Fatalf("expected host localhost, got %q", adminConfig.Host)
	}
}

func TestValidateResetDatabaseTarget(
	t *testing.T,
) {
	t.Parallel()

	cases := []struct {
		name        string
		database    string
		expectError bool
	}{
		{name: "empty", database: "", expectError: true},
		{name: "postgres", database: "postgres", expectError: true},
		{name: "template0", database: "template0", expectError: true},
		{name: "template1", database: "template1", expectError: true},
		{name: "app db", database: "mcp_auth", expectError: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateResetDatabaseTarget(tc.database)
			if tc.expectError && err == nil {
				t.Fatalf("expected error for %q", tc.database)
			}
			if !tc.expectError && err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.database, err)
			}
		})
	}
}

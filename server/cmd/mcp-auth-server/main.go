package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"

	"github.com/adamgeorgiou/mcp_auth/server/internal/app"
	"github.com/adamgeorgiou/mcp_auth/server/internal/auth"
	"github.com/adamgeorgiou/mcp_auth/server/internal/chat"
	"github.com/adamgeorgiou/mcp_auth/server/internal/config"
	"github.com/adamgeorgiou/mcp_auth/server/internal/cryptox"
	"github.com/adamgeorgiou/mcp_auth/server/internal/mcpclient"
	"github.com/adamgeorgiou/mcp_auth/server/internal/mcpservice"
	"github.com/adamgeorgiou/mcp_auth/server/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx := context.Background()
	if cfg.ResetDBOnFirstStart {
		if err := store.ResetDatabaseOnFirstStart(ctx, cfg.DatabaseURL); err != nil {
			log.Fatalf("reset database on first start: %v", err)
		}
	}

	db, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	if err := db.Migrate(ctx); err != nil {
		log.Fatalf("migrate database: %v", err)
	}

	authService := auth.New(db, cfg.SessionTTL)
	if _, err := authService.EnsureBootstrapUser(ctx, cfg.BootstrapEmail, cfg.BootstrapPassword); err != nil {
		log.Fatalf("ensure bootstrap user: %v", err)
	}

	cryptoService := cryptox.New(cfg.EncryptionKey)
	mcpClient := mcpclient.New(cfg.PublicBaseURL, cfg.RequestTimeout)
	mcpManager := mcpservice.New(db, cryptoService, mcpClient)
	chatService := chat.New(db, mcpManager, cfg.OpenAIAPIKey, cfg.OpenAIModel)
	application := app.New(cfg, authService, chatService, mcpManager, db)

	server := &http.Server{
		Addr:    cfg.Addr,
		Handler: application.Routes(),
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("starting server", "addr", cfg.Addr, "public_base_url", cfg.PublicBaseURL)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen and serve: %v", err)
	}
}

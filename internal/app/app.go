// Package app assembles dependencies and manages the application lifecycle.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/hel1th/sec-info-exchange/internal/config"
	"github.com/hel1th/sec-info-exchange/internal/repository/postgres"
	httptransport "github.com/hel1th/sec-info-exchange/internal/transport/http"
	"github.com/hel1th/sec-info-exchange/internal/usecase"
	"github.com/hel1th/sec-info-exchange/migrations"
)

// Run starts the HTTP server and gracefully shuts it down when ctx is canceled.
func Run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	pool, err := openDatabase(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	service := usecase.NewThreatService(postgres.New(pool))
	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httptransport.NewServerHandler(service, httptransport.ServerOptions{
			ReaderKey: cfg.ReaderKey, WriterKey: cfg.WriterKey,
			RequestsPerMinute: cfg.RequestsPerMinute, MaxBodyBytes: cfg.MaxBodyBytes, Ready: pool.Ping,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	slog.Info("server starting", "address", cfg.HTTPAddr)

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.ShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
			return err
		}
		return nil
	}
}

func openDatabase(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	startupCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	pool, err := pgxpool.New(startupCtx, dsn)
	if err != nil {
		return nil, fmt.Errorf("invalid database configuration")
	}
	if pingErr := pool.Ping(startupCtx); pingErr != nil {
		pool.Close()
		return nil, fmt.Errorf("database connection failed")
	}
	db := stdlib.OpenDBFromPool(pool)
	err = migrations.Up(startupCtx, db)
	closeErr := db.Close()
	if err != nil || closeErr != nil {
		pool.Close()
		return nil, errors.Join(err, closeErr)
	}
	return pool, nil
}

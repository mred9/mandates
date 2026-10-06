// Command server serves the profile API.
//
// Keys come from MANDATES_KEK and MANDATES_INDEX_KEY (base64, 32 bytes each).
// With -dev, missing keys are generated for the run and a profiles:read token
// is printed to stderr.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"github.com/mred9/mandates/internal/api"
	"github.com/mred9/mandates/internal/crypto"
	"github.com/mred9/mandates/internal/profile"
	"github.com/mred9/mandates/internal/store/postgres"
	"github.com/mred9/mandates/internal/store/sqlite"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", ":8080", "listen address")
	db := flag.String("db", "sqlite", "sqlite or postgres (PostgreSQL and CockroachDB)")
	dsn := flag.String("dsn", "mandates.db", "SQLite path or PostgreSQL DSN")
	dev := flag.Bool("dev", false, "dev mode: ephemeral keys if unset, in-memory token issuer")
	rps := flag.Float64("rate", 10, "requests per second per client")
	burst := flag.Int("burst", 20, "rate limit burst per client")
	flag.Parse()
	if !*dev {
		// TODO: a TokenVerifier for the real authorization server and a Vault
		// transit envelope; until then only dev mode can start.
		return errors.New("only -dev is implemented")
	}
	if *burst < 1 {
		return errors.New("-burst must be at least 1")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log := api.NewLogger(os.Stdout)

	// The API only reads profiles, so it opens only the profile store; in
	// production it connects under a role with no access to credentials.
	var store profile.Store
	switch *db {
	case "sqlite":
		conn, err := sqlite.Open(ctx, *dsn)
		if err != nil {
			return err
		}
		defer conn.Close()
		store = sqlite.NewProfileStore(conn)
	case "postgres":
		pool, err := postgres.Open(ctx, *dsn)
		if err != nil {
			return err
		}
		defer pool.Close()
		store = postgres.NewProfileStore(pool)
	default:
		return fmt.Errorf("unknown -db %q", *db)
	}

	kek, err := key("MANDATES_KEK")
	if err != nil {
		return err
	}
	indexKey, err := key("MANDATES_INDEX_KEY")
	if err != nil {
		return err
	}
	env, err := crypto.NewLocalKeyEnvelope(kek)
	if err != nil {
		return err
	}
	index, err := crypto.NewBlindIndex(indexKey)
	if err != nil {
		return err
	}

	tokens := api.NewDevTokens()
	tok, err := tokens.Mint("dev-client", []string{api.ScopeProfilesRead}, 24*time.Hour)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "dev token (profiles:read, 24h):", tok)

	srv := &http.Server{
		Addr: *addr,
		Handler: api.New(api.Config{
			Profiles: profile.NewRepository(store, env, index),
			Tokens:   tokens,
			Auditor:  api.SlogAuditor{Logger: log.With("log", "audit")},
			Logger:   log,
			Rate:     rate.Limit(*rps),
			Burst:    *burst,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "addr", *addr, "db", *db)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

// key reads a base64 key from the environment, or generates one for this run
// (dev mode only, so data written in one run can't be read in the next).
func key(name string) ([]byte, error) {
	if v := os.Getenv(name); v != "" {
		return base64.StdEncoding.DecodeString(v)
	}
	k := make([]byte, 32)
	_, err := rand.Read(k)
	fmt.Fprintf(os.Stderr, "%s unset: using an ephemeral key\n", name)
	return k, err
}

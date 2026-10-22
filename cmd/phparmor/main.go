//go:debug multipartmaxheaders=16

// Command phparmor is a hardening reverse proxy for legacy PHP stacks exposed
// to PHP2Shell. It is a stopgap, not a fix; see SPEC.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/smck83/phparmor/internal/config"
	"github.com/smck83/phparmor/internal/server"
	"github.com/smck83/phparmor/internal/telemetry"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	defaultPath := os.Getenv(config.EnvConfigPath)
	if defaultPath == "" {
		defaultPath = "/etc/phparmor/config.yaml"
	}
	configPath := flag.String("config", defaultPath, "path to the YAML config file (env "+config.EnvConfigPath+")")
	showVersion := flag.Bool("version", false, "print the version and exit")
	checkOnly := flag.Bool("check", false, "validate the config and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("phparmor %s (%s)\n%s\n", version, commit, server.StopgapNotice)
		return 0
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "phparmor: %v\n", err)
		return 2
	}
	if *checkOnly {
		fmt.Println("config OK")
		return 0
	}

	logger, level := telemetry.NewLogger(os.Stdout, cfg.LogLevel)
	logger.Warn(server.StopgapNotice, "version", version, "commit", commit)

	srv, err := server.New(cfg, server.Options{Logger: logger, LogLevel: level, Version: version, Commit: commit})
	if err != nil {
		logger.Error("startup failed", "error", err.Error())
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := srv.ReloadFile(*configPath); err != nil {
				logger.Error("config reload rejected, keeping running config", "error", err.Error())
				continue
			}
			logger.Info("config reloaded", "path", *configPath)
		}
	}()

	if err := srv.Run(ctx); err != nil {
		logger.Error("server stopped with error", "error", err.Error())
		return 1
	}
	logger.Info("stopped")
	return 0
}

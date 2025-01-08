package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/DanMolz/wiz-semgrep-connector/internal/config"
	"github.com/DanMolz/wiz-semgrep-connector/internal/collector"
)

func main() {
	cfg := config.LoadConfig()

	log.Println("Starting Wiz Semgrep Collector...")
	log.Printf("Mode: %s\n", cfg.MODE)

	// Create a context that is canceled on interrupt or termination signal
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		log.Println("Received shutdown signal, exiting...")
		cancel()
	}()

	 collector.StartCollector(ctx, cfg)
}

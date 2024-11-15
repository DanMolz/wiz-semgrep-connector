package scheduler

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/DanMolz/wiz-semgrep-connector/config"
	"github.com/DanMolz/wiz-semgrep-connector/internal/semgrep"
	"github.com/DanMolz/wiz-semgrep-connector/internal/wiz"
)

const wizFileName = "wiz_findings.json"
const semgrepFileName = "semgrep_findings.json"

func StartScheduler(ctx context.Context, cfg config.Config) {
	// Wait for the random delay before starting the scheduler
	time.Sleep(time.Duration(rand.Intn(30)) * time.Second)

	errChan := make(chan error)

	go func() {
		errChan <- fetchAndProcessFindings(ctx, cfg, "initial")
	}()

	select {
	case err := <-errChan:
		if err != nil {
			log.Fatalf("Error during initial findings collection: %v\n", err)
		}
	case <-ctx.Done():
		log.Println("Scheduler stopped")
		return
	}

	if cfg.MODE == "agent" {
		log.Println("Running in agent mode, exiting after initial connection.")
		return
	}
	
	// Start the regular ticker-based scheduler
	ticker := time.NewTicker(time.Duration(cfg.FETCH_INTERVAL) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			go func() {
				errChan <- fetchAndProcessFindings(ctx, cfg, "scheduled")
			}()
		case err := <-errChan:
			if err != nil {
				log.Fatalf("Error during scheduled findings collection: %v\n", err)
			}
		case <-ctx.Done():
			log.Println("Scheduler stopped")
			return
		}
	}
}

func fetchAndProcessFindings(ctx context.Context, cfg config.Config, phase string) error {
	log.Printf("Fetching findings from Semgrep (%s)...", phase)
	if err := runFindingsCollection(ctx, cfg); err != nil {
		return fmt.Errorf("error fetching findings: %w", err)
	}
	return nil
}

func runFindingsCollection(ctx context.Context, cfg config.Config) error {
	// Fetch the findings from Semgrep
	semgrepFindings, err := semgrep.FetchFindings(cfg)
	if err != nil {
		return logAndReturnError("Error fetching findings", err)
	}

	// Write the findings to a JSON file
	if err := semgrep.WriteFindingsToFile(semgrepFindings, semgrepFileName); err != nil {
		return logAndReturnError("Error writing findings to file", err)
	}
	log.Println("Semgrep Findings written to file successfully")

	// Log the number of findings fetched
	findingsCount := len(semgrepFindings.Findings)
	log.Printf("Findings fetched: %d\n", findingsCount)

	// Transform the findings
	wizFindings, err := semgrep.TransformFindings(semgrepFindings)
	if err != nil {
		return logAndReturnError("Error transforming findings", err)
	}

	// Write the findings to a JSON file
	if err := semgrep.WriteFindingsToFile(wizFindings, wizFileName); err != nil {
		return logAndReturnError("Error writing findings to file", err)
	}
	log.Println("Wiz Findings written to file successfully")

	// Request an upload slot from the Wiz API
	resp, err := wiz.RequestUploadSlot(ctx, cfg)
	if err != nil {
		return logAndReturnError("Error requesting upload slot", err)
	}

	// Log the upload details
	log.Printf("Upload ID: %v\n", resp.RequestSecurityScanUpload.Upload.ID)
	log.Printf("System Activity ID: %v\n", resp.RequestSecurityScanUpload.Upload.SystemActivityID)
	log.Printf("Upload URL: %v\n", resp.RequestSecurityScanUpload.Upload.URL)

	// Check if file exists
	if _, err := os.Stat(wizFileName); os.IsNotExist(err) {
		return logAndReturnError("File does not exist", err)
	}

	// Upload the JSON file to the Wiz API
	if err := wiz.S3BucketUpload(ctx, resp.RequestSecurityScanUpload.Upload.URL, wizFileName); err != nil {
		return logAndReturnError("Error uploading file to S3", err)
	}

	return nil
}

func logAndReturnError(message string, err error) error {
	log.Printf("%s: %v\n", message, err)
	return fmt.Errorf("%s: %w", message, err)
}

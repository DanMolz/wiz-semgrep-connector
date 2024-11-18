package scheduler

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/DanMolz/wiz-semgrep-connector/config"
	"github.com/DanMolz/wiz-semgrep-connector/internal/semgrep"
	"github.com/DanMolz/wiz-semgrep-connector/internal/utils"
	"github.com/DanMolz/wiz-semgrep-connector/internal/wiz"
)

const wizFileName = "wiz_findings.json"
const integrationID = "55c176cc-d155-43a2-98ed-aa56873a1ca1"

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
		log.Println("Running in agent mode, exiting after completing findings collection.")
		return
	}

	// Start the regular ticker-based scheduler
	ticker := time.NewTicker(time.Duration(cfg.FETCH_INTERVAL) * time.Hour)
	defer ticker.Stop()

	log.Printf("Collection Interval: %d hours\n", cfg.FETCH_INTERVAL)

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
	// Fetch the cloud resources from Wiz
	wizCloudResources, err := wiz.PullCloudResources(ctx, cfg)
	if err != nil {
		return logAndReturnError("Error fetching Wiz repositories", err)
	}
	// Write the cloud resources to a JSON file
	if err := utils.WriteToFile(wizCloudResources, "wiz_cloud_resources.json"); err != nil {
		return logAndReturnError("Error writing Wiz Cloud Resources to file", err)
	}
	log.Println("Wiz Cloud Resources written to file successfully")

	// Fetch the findings from Semgrep
	semgrepFindings, err := semgrep.FetchFindings(cfg)
	if err != nil {
		return logAndReturnError("Error fetching findings", err)
	}
	// Write the findings to a JSON file
	if err := utils.WriteToFile(semgrepFindings, "semgrep_findings.json"); err != nil {
		return logAndReturnError("Error writing Semgrep Findings to file", err)
	}
	log.Println("Semgrep Findings written to file successfully")

	// Log the number of repositories and findings fetched
	repoCount := len(wizCloudResources.VersionControlResources.Nodes)
	log.Printf("Wiz Cloud Resources fetched: %d\n", repoCount)
	findingsCount := len(semgrepFindings.Findings)
	log.Printf("Semgrep Findings fetched: %d\n", findingsCount)

	// Transform the findings
	wizFindings, err := transformFindings(wizCloudResources, semgrepFindings)
	if err != nil {
		return logAndReturnError("Error transforming findings", err)
	}

	// Write the findings to a JSON file
	if err := utils.WriteToFile(wizFindings, wizFileName); err != nil {
		return logAndReturnError("Error writing Wiz Findings to file", err)
	}
	log.Println("WiZ Findings written to file successfully")

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

func transformFindings(wizCloudResources wiz.WizCloudResources, semgrepFindings semgrep.SemgrepFindings) (wiz.WizFindingsSchema, error) {
	var wizFindings wiz.WizFindingsSchema
	wizFindings.IntegrationID = integrationID

	// Create a map of repositories from Wiz Cloud Resources
	wizRepoMap := make(map[string]struct{})
	for _, node := range wizCloudResources.VersionControlResources.Nodes {
		wizRepoMap[node.ProviderID] = struct{}{}
	}

	// Iterate over the findings and transform them
	for _, finding := range semgrepFindings.Findings {
		// Get the cloud platform and provider ID
		cloudPlatform, providerId := getCloudPlatformAndProviderId(finding)

		// Skip findings for repositories not present in Wiz Cloud Resources
		if _, exists := wizRepoMap[providerId]; !exists {
			log.Printf("Skipping, Repository reference not found in Wiz Cloud Resources: %s, %s\n", finding.Repository.Name, finding.Ref)
			continue
		}

		// Create the Wiz Findings data structure
		wizFindingDataSources := wiz.DataSources{
			ID:           finding.Repository.Name,
			AnalysisDate: finding.CreatedAt,
			Assets: []wiz.Assets{
				{
					AssetIdentifier: wiz.AssetIdentifier{
						CloudPlatform: cloudPlatform,
						ProviderID:    providerId,
					},
					WebAppVulnerabilityFindings: []wiz.WebAppVulnerabilityFindings{
						{
							SastFinding: wiz.SastFinding{
								CommitHash:  "",
								Filename:    finding.Location.FilePath,
								LineNumbers: fmt.Sprintf("%d-%d", finding.Location.Line, finding.Location.Column),
							},
							ID:                  fmt.Sprint(finding.ID),
							Name:                strings.Split(finding.Rule.CWE[0], ":")[0],
							DetailedName:        splitRuleName(finding.RuleName),
							Severity:            utils.CapitalizeFirstChar(finding.Severity),
							ExternalFindingLink: finding.LineOfCodeURL,
							Source:              "Semgrep",
							Remediation:         "N/A",
							Description:         fmt.Sprintf("Rule Confidence: %s. Description: %s", utils.CapitalizeFirstChar(finding.Confidence), finding.Rule.Message),
						},
					},
				},
			},
		}

		// Append the Wiz Findings data structure to the list
		wizFindings.DataSources = append(wizFindings.DataSources, wizFindingDataSources)
	}

	// Log the number of data sources
	log.Printf("WiZ Data Sources: %d will be uploaded.", len(wizFindings.DataSources))

	return wizFindings, nil
}

func getCloudPlatformAndProviderId(finding semgrep.Finding) (string, string) {
	var cloudPlatform, providerId string

	if strings.Contains(finding.Repository.URL, "github.com") {
		cloudPlatform = "GitHub"
		providerId = fmt.Sprintf("github.com##%s##%s", finding.Repository.Name, strings.Split(finding.Ref, "refs/heads/")[1])
	} else {
		cloudPlatform = "GitLab"
		providerId = fmt.Sprintf("gitlab.com##%s##%s", finding.Repository.Name, strings.Split(finding.Ref, "refs/heads/")[1])
	}

	return cloudPlatform, providerId
}

func splitRuleName(input string) string {
	if lastDotIndex := strings.LastIndex(input, "."); lastDotIndex != -1 {
		return input[:lastDotIndex]
	}
	return input
}

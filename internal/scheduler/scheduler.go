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

	// Create a Wiz client
	wizClient := wiz.NewWizClient(cfg)

	errChan := make(chan error)
	go func() {
		errChan <- fetchAndProcessFindings(ctx, cfg, wizClient, "initial")
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
				errChan <- fetchAndProcessFindings(ctx, cfg, wizClient, "scheduled")
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

func fetchAndProcessFindings(ctx context.Context, cfg config.Config, wizClient *wiz.WizClient, phase string) error {
	log.Printf("Fetching findings from Semgrep (%s)...", phase)
	if err := runFindingsCollection(ctx, cfg, wizClient); err != nil {
		return fmt.Errorf("error fetching findings: %w", err)
	}
	return nil
}

func runFindingsCollection(ctx context.Context, cfg config.Config, wizClient *wiz.WizClient) error {
	// Fetch the cloud resources from Wiz
	wizCloudResources, err := wizClient.PullCloudResources(ctx)
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
	resp, err := wizClient.RequestUploadSlot(ctx)
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
	if err := wizClient.S3BucketUpload(ctx, resp.RequestSecurityScanUpload.Upload.URL, wizFileName); err != nil {
		return logAndReturnError("Error uploading file to S3", err)
	}

	// Check the status of the enrichment
	uploadStatus := wiz.WizUploadStatus{}
	for {
		time.Sleep(5 * time.Second)
		uploadStatus, err = wizClient.GetEnrichmentStatus(ctx, resp.RequestSecurityScanUpload.Upload.SystemActivityID)
		if err != nil {
			return logAndReturnError("Error getting upload status", err)
		}
		if uploadStatus.SystemActivity.Status != "IN_PROGRESS" {
			break
		}
	}
	log.Printf("Upload Status: %v\n", uploadStatus.SystemActivity.Status)

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

		// Check if the CWE is supported
		if isSupportedCWE(strings.Split(finding.Rule.CWE[0], ":")[0]) {
			// Append the Wiz Findings data structure to the list
			wizFindings.DataSources = append(wizFindings.DataSources, wizFindingDataSources)
		}
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

func isSupportedCWE(cwe string) bool {
	supportedCWEs := []string{
		"CWE-17", "CWE-18", "CWE-19", "CWE-20", "CWE-21", "CWE-22", "CWE-59", "CWE-74", "CWE-77", "CWE-78",
		"CWE-79", "CWE-80", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-113", "CWE-115", "CWE-116",
		"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-123", "CWE-124", "CWE-125", "CWE-126", "CWE-129",
		"CWE-130", "CWE-131", "CWE-134", "CWE-146", "CWE-170", "CWE-172", "CWE-178", "CWE-182", "CWE-183",
		"CWE-184", "CWE-185", "CWE-189", "CWE-190", "CWE-191", "CWE-193", "CWE-195", "CWE-200", "CWE-201",
		"CWE-203", "CWE-208", "CWE-209", "CWE-212", "CWE-228", "CWE-240", "CWE-241", "CWE-244", "CWE-248",
		"CWE-252", "CWE-254", "CWE-255", "CWE-259", "CWE-264", "CWE-266", "CWE-268", "CWE-269", "CWE-271",
		"CWE-273", "CWE-274", "CWE-276", "CWE-279", "CWE-281", "CWE-284", "CWE-285", "CWE-287", "CWE-288",
		"CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-305", "CWE-306", "CWE-307", "CWE-310",
		"CWE-311", "CWE-312", "CWE-315", "CWE-319", "CWE-320", "CWE-321", "CWE-322", "CWE-326", "CWE-327",
		"CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-338", "CWE-345", "CWE-346", "CWE-347", "CWE-349",
		"CWE-352", "CWE-354", "CWE-358", "CWE-359", "CWE-361", "CWE-362", "CWE-367", "CWE-369", "CWE-377",
		"CWE-378", "CWE-384", "CWE-385", "CWE-388", "CWE-399", "CWE-400", "CWE-401", "CWE-404", "CWE-407",
		"CWE-415", "CWE-416", "CWE-417", "CWE-420", "CWE-425", "CWE-426", "CWE-427", "CWE-428", "CWE-434",
		"CWE-436", "CWE-440", "CWE-444", "CWE-455", "CWE-457", "CWE-459", "CWE-460", "CWE-471", "CWE-475",
		"CWE-476", "CWE-477", "CWE-494", "CWE-501", "CWE-502", "CWE-521", "CWE-522", "CWE-523", "CWE-525",
		"CWE-539", "CWE-547", "CWE-552", "CWE-565", "CWE-567", "CWE-601", "CWE-610", "CWE-611", "CWE-613",
		"CWE-614", "CWE-617", "CWE-639", "CWE-640", "CWE-646", "CWE-657", "CWE-662", "CWE-665", "CWE-667",
		"CWE-668", "CWE-669", "CWE-670", "CWE-672", "CWE-674", "CWE-680", "CWE-681", "CWE-682", "CWE-693",
		"CWE-697", "CWE-704", "CWE-706", "CWE-707", "CWE-732", "CWE-754", "CWE-755", "CWE-763", "CWE-770",
		"CWE-772", "CWE-776", "CWE-784", "CWE-786", "CWE-787", "CWE-798", "CWE-805", "CWE-823", "CWE-824",
		"CWE-829", "CWE-833", "CWE-834", "CWE-835", "CWE-838", "CWE-842", "CWE-843", "CWE-862", "CWE-863",
		"CWE-908", "CWE-909", "CWE-913", "CWE-915", "CWE-916", "CWE-917", "CWE-918", "CWE-923", "CWE-924",
		"CWE-1021", "CWE-1077", "CWE-1188", "CWE-1236", "CWE-1321",
	}

	for _, supportedCWE := range supportedCWEs {
		if cwe == supportedCWE {
			return true
		}
	}
	return false
}

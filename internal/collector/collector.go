package collector

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/DanMolz/wiz-semgrep-connector/config"
	"github.com/DanMolz/wiz-semgrep-connector/internal/semgrep"
	"github.com/DanMolz/wiz-semgrep-connector/internal/utils"
	"github.com/DanMolz/wiz-semgrep-connector/internal/wiz"
)

const (
	wizFileName     = "wiz_findings.json"
	cloudResources  = "wiz_cloud_resources.json"
	semgrepFindings = "semgrep_findings.json"
	integrationID   = "55c176cc-d155-43a2-98ed-aa56873a1ca1"
)

var supportedCWEs = map[string]struct{}{
	"CWE-17": {}, "CWE-18": {}, "CWE-19": {}, "CWE-20": {}, "CWE-21": {}, "CWE-22": {}, "CWE-59": {}, "CWE-74": {}, "CWE-77": {}, "CWE-78": {},
	"CWE-79": {}, "CWE-80": {}, "CWE-88": {}, "CWE-89": {}, "CWE-90": {}, "CWE-91": {}, "CWE-93": {}, "CWE-113": {}, "CWE-115": {}, "CWE-116": {},
	"CWE-119": {}, "CWE-120": {}, "CWE-121": {}, "CWE-122": {}, "CWE-123": {}, "CWE-124": {}, "CWE-125": {}, "CWE-126": {}, "CWE-129": {},
	"CWE-130": {}, "CWE-131": {}, "CWE-134": {}, "CWE-146": {}, "CWE-170": {}, "CWE-172": {}, "CWE-178": {}, "CWE-182": {}, "CWE-183": {},
	"CWE-184": {}, "CWE-185": {}, "CWE-189": {}, "CWE-190": {}, "CWE-191": {}, "CWE-193": {}, "CWE-195": {}, "CWE-200": {}, "CWE-201": {},
	"CWE-203": {}, "CWE-208": {}, "CWE-209": {}, "CWE-212": {}, "CWE-228": {}, "CWE-240": {}, "CWE-241": {}, "CWE-244": {}, "CWE-248": {},
	"CWE-252": {}, "CWE-254": {}, "CWE-255": {}, "CWE-259": {}, "CWE-264": {}, "CWE-266": {}, "CWE-268": {}, "CWE-269": {}, "CWE-271": {},
	"CWE-273": {}, "CWE-274": {}, "CWE-276": {}, "CWE-279": {}, "CWE-281": {}, "CWE-284": {}, "CWE-285": {}, "CWE-287": {}, "CWE-288": {},
	"CWE-290": {}, "CWE-294": {}, "CWE-295": {}, "CWE-297": {}, "CWE-300": {}, "CWE-305": {}, "CWE-306": {}, "CWE-307": {}, "CWE-310": {},
	"CWE-311": {}, "CWE-312": {}, "CWE-315": {}, "CWE-319": {}, "CWE-320": {}, "CWE-321": {}, "CWE-322": {}, "CWE-326": {}, "CWE-327": {},
	"CWE-329": {}, "CWE-330": {}, "CWE-331": {}, "CWE-335": {}, "CWE-338": {}, "CWE-345": {}, "CWE-346": {}, "CWE-347": {}, "CWE-349": {},
	"CWE-352": {}, "CWE-354": {}, "CWE-358": {}, "CWE-359": {}, "CWE-361": {}, "CWE-362": {}, "CWE-367": {}, "CWE-369": {}, "CWE-377": {},
	"CWE-378": {}, "CWE-384": {}, "CWE-385": {}, "CWE-388": {}, "CWE-399": {}, "CWE-400": {}, "CWE-401": {}, "CWE-404": {}, "CWE-407": {},
	"CWE-415": {}, "CWE-416": {}, "CWE-417": {}, "CWE-420": {}, "CWE-425": {}, "CWE-426": {}, "CWE-427": {}, "CWE-428": {}, "CWE-434": {},
	"CWE-436": {}, "CWE-440": {}, "CWE-444": {}, "CWE-455": {}, "CWE-457": {}, "CWE-459": {}, "CWE-460": {}, "CWE-471": {}, "CWE-475": {},
	"CWE-476": {}, "CWE-477": {}, "CWE-494": {}, "CWE-501": {}, "CWE-502": {}, "CWE-521": {}, "CWE-522": {}, "CWE-523": {}, "CWE-525": {},
	"CWE-539": {}, "CWE-547": {}, "CWE-552": {}, "CWE-565": {}, "CWE-567": {}, "CWE-601": {}, "CWE-610": {}, "CWE-611": {}, "CWE-613": {},
	"CWE-614": {}, "CWE-617": {}, "CWE-639": {}, "CWE-640": {}, "CWE-646": {}, "CWE-657": {}, "CWE-662": {}, "CWE-665": {}, "CWE-667": {},
	"CWE-668": {}, "CWE-669": {}, "CWE-670": {}, "CWE-672": {}, "CWE-674": {}, "CWE-680": {}, "CWE-681": {}, "CWE-682": {}, "CWE-693": {},
	"CWE-697": {}, "CWE-704": {}, "CWE-706": {}, "CWE-707": {}, "CWE-732": {}, "CWE-754": {}, "CWE-755": {}, "CWE-763": {}, "CWE-770": {},
	"CWE-772": {}, "CWE-776": {}, "CWE-784": {}, "CWE-786": {}, "CWE-787": {}, "CWE-798": {}, "CWE-805": {}, "CWE-823": {}, "CWE-824": {},
	"CWE-829": {}, "CWE-833": {}, "CWE-834": {}, "CWE-835": {}, "CWE-838": {}, "CWE-842": {}, "CWE-843": {}, "CWE-862": {}, "CWE-863": {},
	"CWE-908": {}, "CWE-909": {}, "CWE-913": {}, "CWE-915": {}, "CWE-916": {}, "CWE-917": {}, "CWE-918": {}, "CWE-923": {}, "CWE-924": {},
	"CWE-1021": {}, "CWE-1077": {}, "CWE-1188": {}, "CWE-1236": {}, "CWE-1321": {},
}

func StartCollector(ctx context.Context, cfg config.Config) {
	wizClient := wiz.NewWizClient(cfg)
	errChan := make(chan error)

	mode := os.Getenv("MODE")
	if mode == "" {
		mode = cfg.MODE
	}

	log.Printf("Starting collector in %s mode", mode)

	if strings.ToLower(mode) == "agent" {
		// Run once in agent mode
		log.Println("Running in agent mode. Starting a single findings collection...")
		collectFindingsOnce(ctx, cfg, wizClient, errChan)
	} else {
		// Run on a schedule
		log.Println("Running in schedule mode. Starting periodic findings collection...")
		utils.RandomDelay(30)
		collectFindingsPeriodically(ctx, cfg, wizClient, errChan)
	}
}

func collectFindingsOnce(ctx context.Context, cfg config.Config, wizClient *wiz.WizClient, errChan chan error) {
	go func() {
		defer close(errChan) // Close the channel to signal completion
		collectFindings(ctx, cfg, wizClient, "initial", errChan)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			log.Fatalf("Error during findings collection: %v\n", err)
		}
	case <-ctx.Done():
		log.Println("Process interrupted")
	}
	log.Println("Findings collection completed. Exiting.")
}

func collectFindingsPeriodically(ctx context.Context, cfg config.Config, wizClient *wiz.WizClient, errChan chan error) {
	// Run once immediately
	log.Println("Running initial collection in scheduled mode...")
	collectFindings(ctx, cfg, wizClient, "initial", errChan)

	ticker := time.NewTicker(time.Duration(cfg.FETCH_INTERVAL) * time.Hour)
	defer ticker.Stop()

	log.Printf("Collection interval set to %d hours", cfg.FETCH_INTERVAL)

	for {
		select {
		case <-ticker.C:
			go collectFindings(ctx, cfg, wizClient, "scheduled", errChan)
		case err := <-errChan:
			log.Printf("Error during collection: %v", err)
		case <-ctx.Done():
			log.Println("Scheduler stopped")
			return
		}
	}
}

func collectFindings(ctx context.Context, cfg config.Config, wizClient *wiz.WizClient, phase string, errChan chan<- error) {
	if err := fetchAndProcessFindings(ctx, cfg, wizClient); err != nil {
		errChan <- fmt.Errorf("%s phase failed: %w", phase, err)
	} else {
		log.Printf("%s findings collection completed successfully", phase)
	}
}

func fetchAndProcessFindings(ctx context.Context, cfg config.Config, wizClient *wiz.WizClient) error {
	if err := runFindingsCollection(ctx, cfg, wizClient); err != nil {
		return fmt.Errorf("error fetching findings: %w", err)
	}
	return nil
}

func runFindingsCollection(ctx context.Context, cfg config.Config, wizClient *wiz.WizClient) error {
	wg := &sync.WaitGroup{}
	errChan := make(chan error, 3)

	wg.Add(2)

	go fetchCloudResources(ctx, wizClient, errChan, wg)
	go fetchSemgrepFindings(cfg, errChan, wg)

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	log.Println("Findings fetched successfully. Transforming and uploading...")

	wizCloudResources, err := wiz.ReadWizCloudResources(cloudResources)
	if err != nil {
		return logAndWrapError("reading Wiz Cloud Resources", err)
	}

	semgrepFindings, err := semgrep.ReadSemgrepFindings(semgrepFindings)
	if err != nil {
		return logAndWrapError("reading Semgrep Findings", err)
	}

	wizFindings, err := transformFindings(cfg, wizCloudResources, semgrepFindings)
	if err != nil {
		return logAndWrapError("transforming findings", err)
	}

	if err := uploadFindings(ctx, wizClient, wizFindings); err != nil {
		return logAndWrapError("uploading findings", err)
	}

	return nil
}

func fetchCloudResources(ctx context.Context, wizClient *wiz.WizClient, errChan chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()
	wizCloudResources, err := wizClient.PullCloudResources(ctx)
	if err != nil {
		errChan <- logAndWrapError("fetching Wiz Cloud Resources", err)
		return
	}
	if err := utils.WriteToFile(wizCloudResources, cloudResources); err != nil {
		errChan <- logAndWrapError("writing Wiz Cloud Resources to file", err)
	}
}

func fetchSemgrepFindings(cfg config.Config, errChan chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()

	var findings semgrep.SemgrepFindings
	var err error
	if cfg.TARGET_REPO == "" {
		log.Printf("Fetching all Semgrep findings")
		findings, err = semgrep.FetchAllFindings(cfg)
	} else {
		log.Printf("Fetching Semgrep findings for repository: %s", cfg.TARGET_REPO)
		findings, err = semgrep.FetchRepositoryFindings(cfg, cfg.TARGET_REPO)
	}

	if err != nil {
		errChan <- logAndWrapError("fetching Semgrep Findings", err)
		return
	}
	if err := utils.WriteToFile(findings, semgrepFindings); err != nil {
		errChan <- logAndWrapError("writing Semgrep Findings to file", err)
	}
}

func transformFindings(cfg config.Config, wizCloudResources wiz.WizCloudResources, semgrepFindings semgrep.SemgrepFindings) (wiz.WizFindingsSchema, error) {
	var wizFindings wiz.WizFindingsSchema
	wizFindings.IntegrationID = integrationID
	unsupportedCWE := 0

	// Create a map of repositories from Wiz Cloud Resources
	wizRepoMap := make(map[string]struct{})
	for _, node := range wizCloudResources.VersionControlResources.Nodes {
		wizRepoMap[node.ProviderID] = struct{}{}
	}

	// Iterate over the findings and transform them
	for _, finding := range semgrepFindings.Findings {
		cloudPlatform, providerID := getCloudPlatformAndProviderId(finding)

		// Skip findings for repositories not present in Wiz Cloud Resources
		if _, exists := wizRepoMap[providerID]; !exists {
			log.Printf("Skipping, Repository reference not found in Wiz Cloud Resources: %s, %s", finding.Repository.Name, finding.Ref)
			continue
		}

		// Check if the CWE is supported
		cweID := strings.Split(finding.Rule.CWE[0], ":")[0]
		if !isSupportedCWE(cweID) {
			unsupportedCWE += 1
			continue
		}

		dataSource := buildDataSource(cfg, cloudPlatform, providerID, finding)
		wizFindings.DataSources = append(wizFindings.DataSources, dataSource)
	}

	log.Printf("Unsupported CWEs: %d findings are not supported by Wiz.", unsupportedCWE)
	log.Printf("Semgrep Findings: %d findings will be uploaded.", len(wizFindings.DataSources))
	return wizFindings, nil
}

func uploadFindings(ctx context.Context, wizClient *wiz.WizClient, findings wiz.WizFindingsSchema) error {
	if err := utils.WriteToFile(findings, wizFileName); err != nil {
		return logAndWrapError("writing Wiz Findings to file", err)
	}

	resp, err := wizClient.RequestUploadSlot(ctx)
	if err != nil {
		return logAndWrapError("requesting upload slot", err)
	}

	if err := wizClient.S3BucketUpload(ctx, resp.RequestSecurityScanUpload.Upload.URL, wizFileName); err != nil {
		return logAndWrapError("uploading to S3", err)
	}

	return monitorUploadStatus(ctx, wizClient, resp.RequestSecurityScanUpload.Upload.SystemActivityID)
}

func monitorUploadStatus(ctx context.Context, wizClient *wiz.WizClient, activityID string) error {
	for {
		time.Sleep(5 * time.Second)
		status, err := wizClient.GetEnrichmentStatus(ctx, activityID)
		if err != nil {
			return logAndWrapError("getting upload status", err)
		}
		if status.SystemActivity.Status != "IN_PROGRESS" {
			log.Printf("Upload completed with status: %v", status.SystemActivity.Status)
			return nil
		}
	}
}

func buildDataSource(cfg config.Config, cloudPlatform, providerID string, finding semgrep.Finding) wiz.DataSources {
	return wiz.DataSources{
		ID:           finding.Repository.Name,
		AnalysisDate: finding.CreatedAt,
		Assets: []wiz.Assets{
			{
				AssetIdentifier: wiz.AssetIdentifier{
					CloudPlatform: cloudPlatform,
					ProviderID:    providerID,
				},
				WebAppVulnerabilityFindings: []wiz.WebAppVulnerabilityFindings{
					{
						SastFinding: wiz.SastFinding{
							CommitHash:  "",
							Filename:    finding.Location.FilePath,
							LineNumbers: fmt.Sprintf("%d-%d", finding.Location.Line, finding.Location.Column),
						},
						ID:                  fmt.Sprint(finding.ID),
						Name:                splitCWEName(finding.Rule.CWE[0]),
						DetailedName:        splitRuleName(finding.Rule.Name),
						Severity:            utils.CapitalizeFirstChar(finding.Severity),
						ExternalFindingLink: generateSemgrepFindingURL(cfg, finding),
						Source:              "Semgrep",
						Remediation:         fmt.Sprintf("Source Code Remediation: %s", finding.LineOfCodeURL),
						Description: fmt.Sprintf("[Line Of Code](%s)\r\n\r\nRule Confidence: %s\r\n\r\nDescription: %s",
							finding.LineOfCodeURL,
							utils.CapitalizeFirstChar(finding.Confidence),
							finding.Rule.Message,
						),
					},
				},
			},
		},
	}
}

func generateSemgrepFindingURL(config config.Config, finding semgrep.Finding) string {
	return fmt.Sprintf("https://semgrep.dev/orgs/%s/findings/%s", config.SEMGREP_DEPLOYMENT, fmt.Sprint(finding.ID))
}

func getCloudPlatformAndProviderId(finding semgrep.Finding) (string, string) {
	if strings.Contains(finding.Repository.URL, "github.com") {
		return "GitHub", fmt.Sprintf("github.com##%s##%s", finding.Repository.Name, strings.Split(finding.Ref, "refs/heads/")[1])
	}
	return "GitLab", fmt.Sprintf("gitlab.com##%s##%s", finding.Repository.Name, strings.Split(finding.Ref, "refs/heads/")[1])
}

func splitCWEName(input string) string {
	// Find the first occurrence of a colon (:)
	if firstColonIndex := strings.Index(input, ":"); firstColonIndex != -1 {
		// Return the substring before the first colon
		result := input[:firstColonIndex]
		return result
	}
	// If no colon is found, return the whole input
	return input
}

func splitRuleName(input string) string {
	// Find the last occurrence of a dot (.)
	if lastDotIndex := strings.LastIndex(input, "."); lastDotIndex != -1 {
		// Return the substring after the last dot
		result := input[lastDotIndex+1:]
		return result
	}
	// If no dot is found, return the whole input
	return input
}

func isSupportedCWE(cwe string) bool {
	_, exists := supportedCWEs[cwe]
	return exists
}

func logAndWrapError(context string, err error) error {
	if err != nil {
		log.Printf("%s: %v", context, err)
	}
	return fmt.Errorf("%s: %w", context, err)
}

package semgrep

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/DanMolz/wiz-semgrep-connector/config"
	"github.com/DanMolz/wiz-semgrep-connector/internal/utils"
)

const (
	semgrepAPIURLTemplate = "https://semgrep.dev/api/v1/deployments/%s/findings?issue_type=sast&page_size=3000"
	integrationID         = "55c176cc-d155-43a2-98ed-aa56873a1ca1"
)

type WizFindingsSchema struct {
	IntegrationID string        `json:"integrationId"`
	DataSources   []DataSources `json:"dataSources"`
}

type DataSources struct {
	ID           string   `json:"id"`
	AnalysisDate string   `json:"analysisDate"`
	Assets       []Assets `json:"assets"`
}

type Assets struct {
	AssetIdentifier             AssetIdentifier               `json:"assetIdentifier"`
	WebAppVulnerabilityFindings []WebAppVulnerabilityFindings `json:"webAppVulnerabilityFindings"`
}

type AssetIdentifier struct {
	CloudPlatform string `json:"cloudPlatform"`
	ProviderID    string `json:"providerId"`
}

type WebAppVulnerabilityFindings struct {
	SastFinding         SastFinding `json:"sastFinding"`
	ID                  string      `json:"id"`
	Name                string      `json:"name"`
	DetailedName        string      `json:"detailedName"`
	Severity            string      `json:"severity"`
	ExternalFindingLink string      `json:"externalFindingLink"`
	Source              string      `json:"source"`
	Remediation         string      `json:"remediation"`
	Description         string      `json:"description"`
}

type SastFinding struct {
	CommitHash  string `json:"commitHash"`
	Filename    string `json:"filename"`
	LineNumbers string `json:"lineNumbers"`
}

type Repository struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Location struct {
	FilePath  string `json:"file_path"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	EndLine   int    `json:"end_line"`
	EndColumn int    `json:"end_column"`
}

type Rule struct {
	Name               string   `json:"name"`
	Message            string   `json:"message"`
	Confidence         string   `json:"confidence"`
	Category           string   `json:"category"`
	Subcategories      []string `json:"subcategories"`
	VulnerabilityClass []string `json:"vulnerability_classes"`
	CWE                []string `json:"cwe_names"`
	OWASP              []string `json:"owasp_names"`
}

type SemgrepFindings struct {
	Findings []Finding `json:"findings"`
}

type Finding struct {
	ID            int        `json:"id"`
	Ref           string     `json:"ref"`
	Repository    Repository `json:"repository"`
	LineOfCodeURL string     `json:"line_of_code_url"`
	State         string     `json:"state"`
	TriageState   string     `json:"triage_state"`
	Status        string     `json:"status"`
	Confidence    string     `json:"confidence"`
	CreatedAt     string     `json:"created_at"`
	RelevantSince string     `json:"relevant_since"`
	RuleName      string     `json:"rule_name"`
	RuleMessage   string     `json:"rule_message"`
	Location      Location   `json:"location"`
	Severity      string     `json:"severity"`
	Categories    []string   `json:"categories"`
	Rule          Rule       `json:"rule"`
}

func FetchFindings(cfg config.Config) (SemgrepFindings, error) {
	client := &http.Client{}
	semgrepURL := fmt.Sprintf(semgrepAPIURLTemplate, cfg.SEMGREP_DEPLOYMENT)
	req, err := http.NewRequest("GET", semgrepURL, nil)
	if err != nil {
		return SemgrepFindings{}, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+cfg.SEMGREP_API_TOKEN)

	resp, err := client.Do(req)
	if err != nil {
		return SemgrepFindings{}, fmt.Errorf("performing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return SemgrepFindings{}, fmt.Errorf("failed to fetch findings: %s", string(body))
	}

	var findingsResponse SemgrepFindings
	if err := json.NewDecoder(resp.Body).Decode(&findingsResponse); err != nil {
		return SemgrepFindings{}, fmt.Errorf("decoding response: %w", err)
	}

	return findingsResponse, nil
}

func WriteFindingsToFile(findings interface{}, filePath string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling findings: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}

func TransformFindings(findings SemgrepFindings) (WizFindingsSchema, error) {
	var wizFindings WizFindingsSchema
	wizFindings.IntegrationID = integrationID

	for _, finding := range findings.Findings {
		cloudPlatform, providerId := getCloudPlatformAndProviderId(finding)
		findingDescription := fmt.Sprintf("Rule Confidence: %s. Description: %s", utils.CapitalizeFirstChar(finding.Confidence), finding.Rule.Message)

		wizFindingDataSources := DataSources{
			ID:           finding.Repository.Name,
			AnalysisDate: finding.CreatedAt,
			Assets: []Assets{
				{
					AssetIdentifier: AssetIdentifier{
						CloudPlatform: cloudPlatform,
						ProviderID:    providerId,
					},
					WebAppVulnerabilityFindings: []WebAppVulnerabilityFindings{
						{
							SastFinding: SastFinding{
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
							Description:         findingDescription,
						},
					},
				},
			},
		}

		wizFindings.DataSources = append(wizFindings.DataSources, wizFindingDataSources)
	}

	return wizFindings, nil
}

func getCloudPlatformAndProviderId(finding Finding) (string, string) {
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

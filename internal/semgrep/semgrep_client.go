package semgrep

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/DanMolz/wiz-semgrep-connector/config"
)

const semgrepAPIURL = "https://semgrep.dev/api/v1/deployments/%s/findings?issue_type=sast&page=%s"

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

func FetchRepositoryFindings(cfg config.Config, repositoryName string) (SemgrepFindings, error) {
	client := &http.Client{}
	var repoFindings SemgrepFindings
	page := 0

	for {
		// Construct the paginated URL
		semgrepURL := fmt.Sprintf(semgrepAPIURL, cfg.SEMGREP_DEPLOYMENT, strconv.Itoa(page)) + "&repos=" + cfg.TARGET_REPO
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

		var pageFindings SemgrepFindings
		if err := json.NewDecoder(resp.Body).Decode(&pageFindings); err != nil {
			return SemgrepFindings{}, fmt.Errorf("decoding response: %w", err)
		}
		log.Printf("Fetched %d findings from URL %s", len(pageFindings.Findings), semgrepURL)

		// Filter findings for the given repository
		for _, finding := range pageFindings.Findings {
			if finding.Repository.Name == repositoryName {
				repoFindings.Findings = append(repoFindings.Findings, finding)
			}
		}

		// Check if there are more pages
		if len(pageFindings.Findings) < 100 {
			break
		}

		page++
	}

	return repoFindings, nil
}

func FetchAllFindings(cfg config.Config) (SemgrepFindings, error) {
	client := &http.Client{}
	var allFindings SemgrepFindings
	page := 0

	for {
		// Construct the paginated URL
		semgrepURL := fmt.Sprintf(semgrepAPIURL, cfg.SEMGREP_DEPLOYMENT, strconv.Itoa(page))
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

		var pageFindings SemgrepFindings
		if err := json.NewDecoder(resp.Body).Decode(&pageFindings); err != nil {
			return SemgrepFindings{}, fmt.Errorf("decoding response: %w", err)
		}
		log.Printf("Fetched %d findings from URL %s", len(pageFindings.Findings), semgrepURL)

		// Append findings from the current page to the main struct
		allFindings.Findings = append(allFindings.Findings, pageFindings.Findings...)

		// Check if there are more pages
		if len(pageFindings.Findings) < 100 {
			break
		}

		page++
	}

	return allFindings, nil
}

func ReadSemgrepFindings(fileName string) (SemgrepFindings, error) {
	var findings SemgrepFindings

	// Open the file
	file, err := os.Open(fileName)
	if err != nil {
		return findings, fmt.Errorf("unable to open file %s: %w", fileName, err)
	}
	defer file.Close()

	// Read the file content
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return findings, fmt.Errorf("unable to read file %s: %w", fileName, err)
	}

	// Unmarshal JSON content into struct
	if err := json.Unmarshal(data, &findings); err != nil {
		return findings, fmt.Errorf("unable to unmarshal JSON for Semgrep Findings: %w", err)
	}

	return findings, nil
}

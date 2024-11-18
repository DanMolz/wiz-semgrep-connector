package wiz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/DanMolz/wiz-semgrep-connector/config"
	"github.com/machinebox/graphql"
)

type accessToken struct {
	Token string `json:"access_token"`
}

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

type UploadRequestResponse struct {
	RequestSecurityScanUpload struct {
		Upload struct {
			ID               string `json:"id"`
			SystemActivityID string `json:"systemActivityId"`
			URL              string `json:"url"`
		} `json:"upload"`
	} `json:"requestSecurityScanUpload"`
}

type WizCloudResources struct {
	VersionControlResources struct {
		Nodes []Nodes `json:"nodes"`
	} `json:"versionControlResources"`
}

type Nodes struct {
	ID            string     `json:"id"`
	CloudPlatform string     `json:"cloudPlatform"`
	ProviderID    string     `json:"providerID"`
	Type          string     `json:"type"`
	Repository    Repository `json:"repository"`
}

type Repository struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

var httpClient = &http.Client{}

func wizAuth(ctx context.Context, cfg config.Config) (accessToken, error) {
	authData := url.Values{}
	authData.Set("grant_type", "client_credentials")
	authData.Set("audience", "wiz-api")
	authData.Set("client_id", cfg.WIZ_CLIENT_ID)
	authData.Set("client_secret", cfg.WIZ_CLIENT_SECRET)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://auth.app.wiz.io/oauth/token", strings.NewReader(authData.Encode()))
	if err != nil {
		return accessToken{}, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Encoding", "UTF-8")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return accessToken{}, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return accessToken{}, fmt.Errorf("error authenticating: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return accessToken{}, fmt.Errorf("failed reading response body: %w", err)
	}

	var at accessToken
	if err := json.Unmarshal(bodyBytes, &at); err != nil {
		return accessToken{}, fmt.Errorf("failed parsing JSON body: %w", err)
	}

	return at, nil
}

func RequestUploadSlot(ctx context.Context, cfg config.Config) (UploadRequestResponse, error) {
	at, err := wizAuth(ctx, cfg)
	if err != nil {
		return UploadRequestResponse{}, err
	}

	graphqlClient := graphql.NewClient(cfg.WIZ_API_ENDPOINT)
	graphqlRequest := graphql.NewRequest(`
        query RequestSecurityScanUpload($filename: String!) {
          requestSecurityScanUpload(filename: $filename) {
            upload {
              id
              url
              systemActivityId
            }
          }
        }
    `)

	variables := map[string]interface{}{
		"filename": "wiz_findings.json",
	}

	for k, v := range variables {
		graphqlRequest.Var(k, v)
	}

	graphqlRequest.Header.Set("Authorization", "Bearer "+at.Token)

	var graphqlResponse struct {
		RequestSecurityScanUpload struct {
			Upload struct {
				ID               string `json:"id"`
				SystemActivityID string `json:"systemActivityId"`
				URL              string `json:"url"`
			} `json:"upload"`
		} `json:"requestSecurityScanUpload"`
	}

	if err := graphqlClient.Run(ctx, graphqlRequest, &graphqlResponse); err != nil {
		return UploadRequestResponse{}, fmt.Errorf("failed reading response body: %w", err)
	}

	return graphqlResponse, nil
}

func PullCloudResources(ctx context.Context, cfg config.Config) (WizCloudResources, error) {
	at, err := wizAuth(ctx, cfg)
	if err != nil {
		return WizCloudResources{}, err
	}

	graphqlClient := graphql.NewClient(cfg.WIZ_API_ENDPOINT)
	graphqlRequest := graphql.NewRequest(`
        query VersionControlResources($first: Int, $after: String, $filterBy: VersionControlResourceFilters) {
          versionControlResources(first: $first, after: $after, filterBy: $filterBy) {
            nodes {
              id
              cloudPlatform
              providerID
              type
              repository {
                id
                name
                url
              }
            }
          }
        }
    `)

	variables := map[string]interface{}{
		"first": 500,
		"filterBy": map[string]interface{}{
			"type": []string{"REPOSITORY_BRANCH"},
		},
	}

	for k, v := range variables {
		graphqlRequest.Var(k, v)
	}

	graphqlRequest.Header.Set("Authorization", "Bearer "+at.Token)

	var graphqlResponse WizCloudResources
	if err := graphqlClient.Run(ctx, graphqlRequest, &graphqlResponse); err != nil {
		return WizCloudResources{}, fmt.Errorf("failed reading response body: %w", err)
	}

	return graphqlResponse, nil
}

func GetEnrichmentStatus(ctx context.Context, cfg config.Config, systemActivityId string) error {
	at, err := wizAuth(ctx, cfg)
	if err != nil {
		return err
	}

	graphqlClient := graphql.NewClient(cfg.WIZ_API_ENDPOINT)
	graphqlRequest := graphql.NewRequest(`
        query SystemActivity($id: ID!) {
          systemActivity(id: $id) {
            id
            status
            statusInfo
            result {
              ... on SystemActivityEnrichmentIntegrationResult {
                dataSources {
                  incoming
                  handled
                }
                findings {
                  incoming
                  handled
                }
                events {
                  incoming
                  handled
                }
                tags {
                  incoming
                  handled
                }
              }
            }
            context {
              ... on SystemActivityEnrichmentIntegrationContext {
                fileUploadId
              }
            }
          }
        }
    `)

	// Prepare the variables
	variablesJSON := `{
      "id": "` + systemActivityId + `"
    }`

	var variables map[string]interface{}

	if err := json.Unmarshal([]byte(variablesJSON), &variables); err != nil {
		log.Fatalf("Failed parsing JSON body: %v", err)
	}

	for k, v := range variables {
		graphqlRequest.Var(k, v)
	}

	graphqlRequest.Header.Set("Authorization", "Bearer "+at.Token)

	var graphqlResponse interface{}

	if err := graphqlClient.Run(context.Background(), graphqlRequest, &graphqlResponse); err != nil {
		println(graphqlResponse)
		log.Fatalf("Failed reading response body: %v", err)
	}

	fmt.Println(graphqlResponse) // your data is here!

	return nil
}

func S3BucketUpload(ctx context.Context, presignedURL string, filePath string) error {
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, presignedURL, bytes.NewReader(fileContent))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to upload file: %s", resp.Status)
	}

	log.Println("File uploaded successfully!")
	return nil
}

package wiz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

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

type WizClient struct {
	httpClient    *http.Client
	graphqlClient *graphql.Client
	cfg           config.Config
	token         accessToken
	tokenMutex    sync.Mutex
}

type WizUploadStatus struct {
	SystemActivity struct {
		ID         string      `json:"id"`
		Status     string      `json:"status"`
		StatusInfo interface{} `json:"statusInfo"`
		Result     struct {
			DataSources struct {
				Incoming int `json:"incoming"`
				Handled  int `json:"handled"`
			} `json:"dataSources"`
			Findings struct {
				Incoming int `json:"incoming"`
				Handled  int `json:"handled"`
			} `json:"findings"`
			Events struct {
				Incoming int `json:"incoming"`
				Handled  int `json:"handled"`
			} `json:"events"`
			Tags struct {
				Incoming int `json:"incoming"`
				Handled  int `json:"handled"`
			} `json:"tags"`
			UnresolvedAssets struct {
				Count int         `json:"count"`
				Ids   interface{} `json:"ids"`
			} `json:"unresolvedAssets"`
		} `json:"result"`
		Context struct {
			FileUploadID string `json:"fileUploadId"`
		} `json:"context"`
	} `json:"systemActivity"`
}

func NewWizClient(cfg config.Config) *WizClient {
	return &WizClient{
		httpClient:    &http.Client{},
		graphqlClient: graphql.NewClient(cfg.WIZ_API_ENDPOINT),
		cfg:           cfg,
	}
}

func (c *WizClient) authenticate(ctx context.Context) error {
	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()

	if c.token.Token != "" && !c.isTokenExpired() {
		return nil
	}

	authData := url.Values{}
	authData.Set("grant_type", "client_credentials")
	authData.Set("audience", "wiz-api")
	authData.Set("client_id", c.cfg.WIZ_CLIENT_ID)
	authData.Set("client_secret", c.cfg.WIZ_CLIENT_SECRET)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://auth.app.wiz.io/oauth/token", strings.NewReader(authData.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Add("Encoding", "UTF-8")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error authenticating: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed reading response body: %w", err)
	}

	var at accessToken
	if err := json.Unmarshal(bodyBytes, &at); err != nil {
		return fmt.Errorf("failed parsing JSON body: %w", err)
	}

	c.token = at
	return nil
}

func (c *WizClient) isTokenExpired() bool {
	// Implement token expiration check if needed
	return false
}

func (c *WizClient) doGraphQLRequest(ctx context.Context, req *graphql.Request, resp interface{}) error {
	if err := c.authenticate(ctx); err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+c.token.Token)
	return c.graphqlClient.Run(ctx, req, resp)
}

func (c *WizClient) RequestUploadSlot(ctx context.Context) (UploadRequestResponse, error) {
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

	var graphqlResponse UploadRequestResponse
	if err := c.doGraphQLRequest(ctx, graphqlRequest, &graphqlResponse); err != nil {
		return UploadRequestResponse{}, fmt.Errorf("failed reading response body: %w", err)
	}

	return graphqlResponse, nil
}

func (c *WizClient) PullCloudResources(ctx context.Context) (WizCloudResources, error) {
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

	var graphqlResponse WizCloudResources
	if err := c.doGraphQLRequest(ctx, graphqlRequest, &graphqlResponse); err != nil {
		return WizCloudResources{}, fmt.Errorf("failed reading response body: %w", err)
	}

	return graphqlResponse, nil
}

func (c *WizClient) GetEnrichmentStatus(ctx context.Context, systemActivityId string) (WizUploadStatus, error) {
	graphqlRequest := graphql.NewRequest(`
        query SystemActivity($id: ID!) {
        	systemActivity(id: $id) {
        		id
        		status
        		statusInfo
        		result {
        		  ...on SystemActivityEnrichmentIntegrationResult{
        			dataSources {
        			  ... IngestionStatsDetails
        			}
        			findings {
        			  ... IngestionStatsDetails
        			}
        			events {
        			  ... IngestionStatsDetails
        			}
        			tags {
        			  ... IngestionStatsDetails
        			}
        			unresolvedAssets {
        			  ... UnresolvedAssetsDetails
        			}
        		  }
        		}
        		context {
        		  ... on SystemActivityEnrichmentIntegrationContext{
        			fileUploadId
        		  }
        		}
        	}
          }

        fragment IngestionStatsDetails on EnrichmentIntegrationStats {
        	incoming
        	handled
        }

        fragment UnresolvedAssetsDetails on EnrichmentIntegrationUnresolvedAssets {
        	count
        	ids
        }
    `)

	variables := map[string]interface{}{
		"id": systemActivityId,
	}

	for k, v := range variables {
		graphqlRequest.Var(k, v)
	}

	var graphqlResponse WizUploadStatus
	if err := c.doGraphQLRequest(ctx, graphqlRequest, &graphqlResponse); err != nil {
		return WizUploadStatus{}, fmt.Errorf("failed reading response body: %w", err)
	}

	return graphqlResponse, nil
}

func (c *WizClient) S3BucketUpload(ctx context.Context, presignedURL string, filePath string) error {
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, presignedURL, bytes.NewReader(fileContent))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to upload file: %s", resp.Status)
	}

	return nil
}

func ReadWizCloudResources(fileName string) (WizCloudResources, error) {
	var resources WizCloudResources

	// Open the file
	file, err := os.Open(fileName)
	if err != nil {
		return resources, fmt.Errorf("unable to open file %s: %w", fileName, err)
	}
	defer file.Close()

	// Read the file content
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return resources, fmt.Errorf("unable to read file %s: %w", fileName, err)
	}

	// Unmarshal JSON content into struct
	if err := json.Unmarshal(data, &resources); err != nil {
		return resources, fmt.Errorf("unable to unmarshal JSON for Wiz Cloud Resources: %w", err)
	}

	return resources, nil
}
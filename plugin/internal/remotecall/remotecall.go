package remotecall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

type RemoteCall struct {
	userClusterNameURL    string
	clusterNameClusterURL map[string]*url.URL

	mappingKeyPath string
	httpClient     *http.Client
}

func InitRemoteCall(
	userClusterNameURL string,
	clusterNameClusterURL map[string]string,
	mappingKeyPath string,
) (*RemoteCall, error) {
	clusterNameClusterURLParsed := make(map[string]*url.URL, len(clusterNameClusterURL))

	for clusterName, clusterURL := range clusterNameClusterURL {
		clusterURLParsed, err := url.Parse(clusterURL)
		if err != nil {
			return nil, fmt.Errorf("error parsing URL %q: %w", clusterURL, err)
		}
		clusterNameClusterURLParsed[clusterName] = clusterURLParsed
	}

	return &RemoteCall{
		userClusterNameURL:    userClusterNameURL,
		clusterNameClusterURL: clusterNameClusterURLParsed,
		httpClient:            createHttpClient(),
		mappingKeyPath:        mappingKeyPath,
	}, nil
}

func createHttpClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
		},
	}
}

func (r *RemoteCall) GetClusterName(username string) (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(r.userClusterNameURL, username), nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	// Set custom headers if needed
	req.Header.Set("User-Agent", "SSH-gateway")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error: status code: %d", resp.StatusCode)
	}

	clusterName, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}

	// json parsing
	return string(clusterName), nil
}

func (r *RemoteCall) AuthenticateUser(key []byte, clusterURL string) (*UserKeyAuthResponse, error) {
	auth := userKeyAuth{Key: key}
	body, err := json.Marshal(auth)
	if err != nil {
		return nil, fmt.Errorf("error marshalling auth: %v", auth)
	}

	req, err := http.NewRequest("GET", clusterURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("User-Agent", "SSH-gateway")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error: status code: %d", resp.StatusCode)
	}

	authResponse := UserKeyAuthResponse{}
	err = json.NewDecoder(resp.Body).Decode(&authResponse)
	if err != nil {
		return nil, fmt.Errorf("error marshalling response body: %w", err)
	}

	return &authResponse, nil
}

func (r *RemoteCall) MapKey() ([]byte, error) {
	key, err := os.ReadFile(r.mappingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error reading mapping key: %w", err)
	}
	return key, nil
}

func (r *RemoteCall) GetUpstreamURL(clusterName string) (string, error) {
	clusterURL, ok := r.clusterNameClusterURL[clusterName]
	if !ok {
		return "", fmt.Errorf("unknown cluster %s", clusterName)
	}
	return clusterURL.String(), nil
}

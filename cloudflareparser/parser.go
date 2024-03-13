// parser.go

package cloudflareparser

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

type Result struct {
	IPv4CIDRs []string `json:"ipv4_cidrs"`
	IPv6CIDRs []string `json:"ipv6_cidrs"`
	ETag      string   `json:"etag"`
}

type Response struct {
	Result   Result `json:"result"`
	Success  bool   `json:"success"`
	Errors   []interface{}
	Messages []interface{}
}

const cf_url = "https://api.cloudflare.com/client/v4/ips"

func ParseCloudflareJSON() (string, []string, error) {
	// Make an HTTP GET request to fetch the JSON data
	resp, err := http.Get(cf_url)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	// Parse the JSON data into Response struct
	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		return "", nil, err
	}

	// Results basic check
	if response.Result.ETag == "" {
		return "", nil, errors.New("CloudFlare returned an empty ETag")
	} else if len(response.Result.IPv4CIDRs) == 0 {
		return "", nil, errors.New("CloudFlare returned an empty IP ranges list")
	}

	return response.Result.ETag, response.Result.IPv4CIDRs, nil
}

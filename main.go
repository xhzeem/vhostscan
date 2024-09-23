package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Result struct {
	IP       string            `json:"ip"`
	Vhost    string            `json:"vhost"`
	Status   int               `json:"status"`
	Length   int               `json:"length"`
	Protocol string            `json:"protocol"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
}

func readLines(filename string) ([]string, error) {
	var lines []string
	file, err := os.Open(filename)
	if err != nil {
		return lines, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func randomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func sendRequest(ip, host, protocol string, client *http.Client, maxBodySize int64) (int, http.Header, []byte, error) {
	url := fmt.Sprintf("%s://%s", protocol, ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Host = host
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	var body []byte
	if maxBodySize > 0 {
		body, err = io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	} else {
		body, err = io.ReadAll(resp.Body)
	}
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	return resp.StatusCode, resp.Header, body, nil
}

func flattenHeaders(headers http.Header) map[string]string {
	flatHeaders := make(map[string]string)
	for key, values := range headers {
		flatHeaders[key] = strings.Join(values, ", ")
	}
	return flatHeaders
}

func main() {
	// Parse command-line arguments
	ipsFile := flag.String("ips", "ips.txt", "File containing list of IPs")
	vhostsFile := flag.String("vhosts", "vhosts.txt", "File containing list of vhosts")
	outputFile := flag.String("output", "output.jsonl", "Output file in JSON Lines format")
	threads := flag.Int("threads", 10, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "HTTP request timeout in seconds")
	contentLengthDiff := flag.Int("content-diff", 100, "Content length difference threshold")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	includeHeaders := flag.Bool("include-headers", false, "Include response headers in the output")
	includeBody := flag.Bool("include-body", false, "Include response body in the output")
	maxBodySize := flag.Int64("max-body-size", 1024*1024, "Maximum size of response body to include (in bytes), 0 for unlimited")
	flag.Parse()

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	// Read IPs and vhosts from files
	ips, err := readLines(*ipsFile)
	if err != nil {
		fmt.Printf("Error reading IPs: %v\n", err)
		return
	}
	vhosts, err := readLines(*vhostsFile)
	if err != nil {
		fmt.Printf("Error reading vhosts: %v\n", err)
		return
	}

	// Prepare HTTP client
	client := &http.Client{
		Timeout: time.Duration(*timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Create output file
	outFile, err := os.Create(*outputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer outFile.Close()
	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	// Use WaitGroup to manage goroutines
	var wg sync.WaitGroup
	sem := make(chan struct{}, *threads)

	for _, ip := range ips {
		ip := ip // capture range variable
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			protocols := []string{"http", "https"}
			for _, protocol := range protocols {
				if *verbose {
					fmt.Printf("[*] Testing IP %s over %s\n", ip, protocol)
				}

				// Send request with random host
				randomHost := randomString(10) + ".com"
				baseStatus, _, baseBody, err := sendRequest(ip, randomHost, protocol, client, *maxBodySize)
				if err != nil {
					if *verbose {
						fmt.Printf("[!] Error with random host request to %s (%s): %v\n", ip, protocol, err)
					}
					continue
				}
				baseLength := len(baseBody)

				for _, vhost := range vhosts {
					// Send request with actual vhost
					status, headers, body, err := sendRequest(ip, vhost, protocol, client, *maxBodySize)
					if err != nil {
						if *verbose {
							fmt.Printf("[!] Error with vhost %s request to %s (%s): %v\n", vhost, ip, protocol, err)
						}
						continue
					}
					length := len(body)

					// Compare status codes and content lengths
					statusDiff := status != baseStatus
					lengthDiff := abs(length-baseLength) >= *contentLengthDiff

					if statusDiff || lengthDiff {
						result := Result{
							IP:       ip,
							Vhost:    vhost,
							Status:   status,
							Length:   length,
							Protocol: protocol,
						}

						if *includeHeaders {
							result.Headers = flattenHeaders(headers)
						}

						if *includeBody {
							// Encode body in base64 if necessary
							result.Body = base64.StdEncoding.EncodeToString(body)
						}

						jsonData, _ := json.Marshal(result)
						writer.WriteString(string(jsonData) + "\n")
					}
				}
			}
		}()
	}

	wg.Wait()
	fmt.Printf("Scanning completed. Results saved to %s\n", *outputFile)
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

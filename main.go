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
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Result struct {
	IP         string            `json:"ip"`
	Vhost      string            `json:"vhost"`
	Protocol   string            `json:"protocol"`
	Status     int               `json:"status"`
	BaseStatus int               `json:"base_status"`
	Length     int               `json:"length"`
	LengthDiff int               `json:"length_diff"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	Curl       string            `json:"curl"`
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

func sendRequest(ip, host, protocol string, baseClient *http.Client, maxBodySize int64) (int, http.Header, []byte, error) {
	urlStr := fmt.Sprintf("%s://%s", protocol, ip)
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Host = host

	// Clone the base transport to modify TLS settings per request
	baseTransport := baseClient.Transport.(*http.Transport)
	transport := baseTransport.Clone()

	// Create a new client with the modified transport
	client := &http.Client{
		Timeout:   baseClient.Timeout,
		Transport: transport,
		// Do not follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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

func parseIgnoredStatusCodes(s string) map[int]struct{} {
	ignoredCodes := make(map[int]struct{})
	if s == "" {
		return ignoredCodes
	}
	codes := strings.Split(s, ",")
	for _, codeStr := range codes {
		codeStr = strings.TrimSpace(codeStr)
		if codeStr == "" {
			continue
		}
		code, err := strconv.Atoi(codeStr)
		if err != nil {
			fmt.Printf("Invalid status code to ignore: %s\n", codeStr)
			continue
		}
		ignoredCodes[code] = struct{}{}
	}
	return ignoredCodes
}

func generateCurlCommand(ip, host, protocol string) string {
	return fmt.Sprintf("curl -k -H 'Host: %s' '%s://%s'", host, protocol, ip)
}

func main() {
	// Parse command-line arguments
	ipsFile := flag.String("ips", "ips.txt", "File containing list of IPs")
	vhostsFile := flag.String("vhosts", "vhosts.txt", "File containing list of vhosts")
	outputFile := flag.String("output", "output.json", "Output file in JSON format")
	threads := flag.Int("threads", 10, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "HTTP request timeout in seconds")
	contentLengthDiff := flag.Int("length-diff", 100, "Content length difference threshold")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	includeHeaders := flag.Bool("include-headers", false, "Include response headers in the output")
	includeBody := flag.Bool("include-body", false, "Include response body in the output")
	maxBodySize := flag.Int64("max-body-size", 1024*1024, "Maximum size of response body to include (in bytes), 0 for unlimited")
	ignoreStatusCodesStr := flag.String("ignore-status", "403,409", "Comma-separated list of status codes to ignore")
	proxy := flag.String("proxy", "", "Proxy URL (e.g., http://proxy:port)")
	flag.Parse()

	// Parse ignored status codes
	ignoredStatusCodes := parseIgnoredStatusCodes(*ignoreStatusCodesStr)

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	// Read IPs and vhosts from files
	ips, err := readLines(*ipsFile)
	if err != nil {
		if *verbose {
			fmt.Printf("Error reading IPs: %v\n", err)
		}
		return
	}
	vhosts, err := readLines(*vhostsFile)
	if err != nil {
		if *verbose {
			fmt.Printf("Error reading vhosts: %v\n", err)
		}
		return
	}

	// Prepare base HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if *proxy != "" {
		proxyURL, err := url.Parse(*proxy)
		if err != nil {
			if *verbose {
				fmt.Printf("Invalid proxy URL: %v\n", err)
			}
			return
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	baseClient := &http.Client{
		Timeout:   time.Duration(*timeout) * time.Second,
		Transport: transport,
	}

	// Create output file
	outFile, err := os.Create(*outputFile)
	if err != nil {
		if *verbose {
			fmt.Printf("Error creating output file: %v\n", err)
		}
		return
	}
	defer outFile.Close()
	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	// Write opening bracket for JSON array
	writer.WriteString("[\n")
	writer.Flush()

	// Channel to collect results
	resultsChan := make(chan *Result, 1000)

	// WaitGroup for writer goroutine
	var writeWg sync.WaitGroup
	writeWg.Add(1)

	// Writer goroutine
	go func() {
		defer writeWg.Done()
		firstResult := true
		for result := range resultsChan {
			result.Curl = generateCurlCommand(result.IP, result.Vhost, result.Protocol)
			resultJSON, err := json.Marshal(result)
			if err != nil {
				if *verbose {
					fmt.Printf("[!] Error marshaling JSON for %s %s: %v\n", result.IP, result.Vhost, err)
				}
				continue
			}

			// Write to output file
			if !firstResult {
				writer.WriteString(",\n")
			}
			writer.WriteString(string(resultJSON))
			writer.Flush()
			firstResult = false

			// Output to stdout as JSONL
			fmt.Println(string(resultJSON))
		}
		writer.WriteString("\n]\n")
		writer.Flush()
	}()

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
				baseStatus, _, baseBody, err := sendRequest(ip, randomHost, protocol, baseClient, *maxBodySize)
				if err != nil {
					if *verbose {
						fmt.Printf("[!] Error with random host request to %s (%s): %v\n", ip, protocol, err)
					}
					continue
				}
				baseLength := len(baseBody)

				for _, vhost := range vhosts {
					// Send request with actual vhost
					status, headers, body, err := sendRequest(ip, vhost, protocol, baseClient, *maxBodySize)
					if err != nil {
						if *verbose {
							fmt.Printf("[!] Error with vhost %s request to %s (%s): %v\n", vhost, ip, protocol, err)
						}
						continue
					}
					length := len(body)

					// Compare status codes and content lengths
					statusDiff := status != baseStatus
					lengthDiffValue := length - baseLength
					contentDiff := abs(lengthDiffValue) >= *contentLengthDiff

					// Ignore specified status codes
					if _, ignored := ignoredStatusCodes[status]; ignored {
						continue
					}

					if !statusDiff && !contentDiff {
						continue // No significant difference
					}

					result := &Result{
						IP:         ip,
						Vhost:      vhost,
						Protocol:   protocol,
						Status:     status,
						BaseStatus: baseStatus,
						Length:     length,
						LengthDiff: lengthDiffValue,
					}

					if *includeHeaders {
						result.Headers = flattenHeaders(headers)
					}

					if *includeBody {
						result.Body = base64.StdEncoding.EncodeToString(body)
					}

					// Send the result to the results channel
					resultsChan <- result
				}
			}
		}()
	}

	wg.Wait()
	close(resultsChan)
	writeWg.Wait()

	if *verbose {
		fmt.Printf("Scanning completed. Results saved to %s\n", *outputFile)
	}
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

package main

import (
	"bufio"
	"crypto/tls"
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

// Color codes for colorful output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
)

// Result struct for storing the findings
type Result struct {
	IP         string            `json:"ip"`
	Vhost      string            `json:"vhost"`
	Protocol   string            `json:"protocol"`
	Status     int               `json:"status"`
	BaseStatus int               `json:"base_status"`
	Length     int               `json:"content_length"`
	Location   string            `json:"location,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	Curl       string            `json:"curl"`
}

type ResponseData struct {
	Status                 int
	ContentType            string
	AdjustedBodyLength     int
	AdjustedLocationLength int
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
	urlStr := fmt.Sprintf("%s://%s", protocol, ip)
	req, err := http.NewRequest("GET", urlStr, nil)
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

// compareResponses compares two responses and returns true if they are considered the same
func compareResponses(resp1, resp2 ResponseData) bool {
	sameStatus := resp1.Status == resp2.Status
	sameContentType := resp1.ContentType == resp2.ContentType
	sameBodyLength := resp1.AdjustedBodyLength == resp2.AdjustedBodyLength
	sameLocationLength := resp1.AdjustedLocationLength == resp2.AdjustedLocationLength

	return sameStatus && sameContentType && sameBodyLength && sameLocationLength
}

func main() {
	// Parse command-line arguments
	ipsFile := flag.String("ips", "ips.txt", "File containing list of IPs")
	vhostsFile := flag.String("vhosts", "vhosts.txt", "File containing list of vhosts")
	outputFile := flag.String("output", "vhostscan-"+time.Now().Format("2006-01-02_15-04-05")+".json", "Output file in JSON format")
	threads := flag.Int("threads", 10, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "HTTP request timeout in seconds")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	includeHeaders := flag.Bool("include-headers", false, "Include response headers in the output")
	includeBody := flag.Bool("include-body", false, "Include response body in the output")
	maxBodySize := flag.Int64("max-body-size", 1024*1024, "Maximum size of response body to include (in bytes), 0 for unlimited")
	ignoreStatusCodesStr := flag.String("ignore-status", "403,429,500,501,502,503,504,530", "Comma-separated list of status codes to ignore")
	proxy := flag.String("proxy", "", "Proxy URL (e.g., http://proxy:port)")
	delay := flag.Int("delay", 0, "Delay between requests in milliseconds")
	noColor := flag.Bool("no-color", false, "Disable color output")
	flag.Parse()

	// Set up color variables
	useColor := !(*noColor)
	var (
		red    = ""
		green  = ""
		yellow = ""
		blue   = ""
		cyan   = ""
		reset  = ""
	)
	if useColor {
		red = ColorRed
		green = ColorGreen
		yellow = ColorYellow
		blue = ColorBlue
		cyan = ColorCyan
		reset = ColorReset
	}

	// Print banner
	banner := `
 __ __  __ __   ___   _____ ______  _____   __   ____  ____  
|  |  ||  |  | /   \ / ___/|      |/ ___/  /  ] /    ||    \ 
|  |  ||  |  ||     (   \_ |      (   \_  /  / |  o  ||  _  |
|  |  ||  _  ||  O  |\__  ||_|  |_|\__  |/  /  |     ||  |  |
|  :  ||  |  ||     |/  \ |  |  |  /  \ /   \_ |  _  ||  |  |
 \   / |  |  ||     |\    |  |  |  \    \     ||  |  ||  |  |
  \_/  |__|__| \___/  \___|  |__|   \___|\____||__|__||__|__|

`
	fmt.Println(banner)

	// Parse ignored status codes
	ignoredStatusCodes := parseIgnoredStatusCodes(*ignoreStatusCodesStr)

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	// Read IPs and vhosts from files
	ips, err := readLines(*ipsFile)
	if err != nil {
		if *verbose {
			fmt.Printf("%sError reading IPs: %v%s\n", red, err, reset)
		}
		return
	}
	vhosts, err := readLines(*vhostsFile)
	if err != nil {
		if *verbose {
			fmt.Printf("%sError reading vhosts: %v%s\n", red, err, reset)
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
				fmt.Printf("%sInvalid proxy URL: %v%s\n", red, err, reset)
			}
			return
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	baseClient := &http.Client{
		Timeout:   time.Duration(*timeout) * time.Second,
		Transport: transport,
		// Do not follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create output file
	outFile, err := os.Create(*outputFile)
	if err != nil {
		if *verbose {
			fmt.Printf("%sError creating output file: %v%s\n", red, err, reset)
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

	// Map to track reported vhost and IP combinations
	var (
		reportedResults = make(map[string]struct{})
		reportedMutex   sync.Mutex
	)

	// WaitGroup for writer goroutine
	var writeWg sync.WaitGroup
	writeWg.Add(1)

	// Writer goroutine
	go func() {
		defer writeWg.Done()
		firstResult := true
		for result := range resultsChan {
			result.Curl = fmt.Sprintf("curl -i -k -H 'Host: %s' '%s://%s'", result.Vhost, result.Protocol, result.IP)
			resultJSON, err := json.Marshal(result)
			if err != nil {
				if *verbose {
					fmt.Printf("%s[!] Error marshaling JSON for %s %s: %v%s\n", red, result.IP, result.Vhost, err, reset)
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

			// Output to stdout as formatted text
			fmt.Printf("%s[+] Found Vhost:%s %s%s%s on IP %s%s%s (%s%s%s)\n", green, reset, cyan, result.Vhost, reset, yellow, result.IP, reset, blue, result.Protocol, reset)
			fmt.Printf("    Status: %d, Base Status: %d\n", result.Status, result.BaseStatus)
			if result.Location != "" {
				fmt.Printf("    Location: %s\n", result.Location)
			}
			fmt.Printf("    Command: %s\n", result.Curl)
		}
		writer.WriteString("\n]\n")
		writer.Flush()
	}()

	// Use WaitGroup to manage goroutines
	var wg sync.WaitGroup
	sem := make(chan struct{}, *threads)

	// Iterate over IPs
	for _, ip := range ips {
		ip := ip // capture range variable
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			protocols := []string{"https", "http"}
			for _, protocol := range protocols {
				if *verbose {
					fmt.Printf("%s[*] Testing IP %s over %s%s\n", yellow, ip, protocol, reset)
				}

				// Send initial random host request
				firstRandomHost := randomString(16) + ".com"
				baseStatus, baseHeaders, baseBodyBytes, err := sendRequest(ip, firstRandomHost, protocol, baseClient, *maxBodySize)
				if err != nil {
					if *verbose {
						fmt.Printf("%s[!] Error with first random host request to %s (%s): %v%s\n", red, ip, protocol, err, reset)
					}
					continue
				}

				baseContentType := baseHeaders.Get("Content-Type")
				adjustedBaseBody := strings.ReplaceAll(string(baseBodyBytes), firstRandomHost, "")
				adjustedBaseBodyLength := len(adjustedBaseBody)

				var adjustedBaseLocationLength int
				if baseLocationHeader := baseHeaders.Get("Location"); baseLocationHeader != "" {
					adjustedBaseLocation := strings.ReplaceAll(baseLocationHeader, firstRandomHost, "")
					adjustedBaseLocationLength = len(adjustedBaseLocation)
				} else {
					adjustedBaseLocationLength = -1
				}

				baseResponse := ResponseData{
					Status:                 baseStatus,
					ContentType:            baseContentType,
					AdjustedBodyLength:     adjustedBaseBodyLength,
					AdjustedLocationLength: adjustedBaseLocationLength,
				}

				// Now test vhosts
				type StoredVhostResponse struct {
					Vhost     string
					Response  ResponseData
					Headers   http.Header
					BodyBytes []byte
				}
				storedVhostResponses := []StoredVhostResponse{}

				for _, vhost := range vhosts {
					// Delay between requests
					if *delay > 0 {
						time.Sleep(time.Duration(*delay) * time.Millisecond)
					}

					if *verbose {
						fmt.Printf("%s[*] Testing %s on %s://%s%s\n", blue, vhost, protocol, ip, reset)
					}

					// Send request with actual vhost
					status, headers, bodyBytes, err := sendRequest(ip, vhost, protocol, baseClient, *maxBodySize)
					if err != nil {
						if *verbose {
							fmt.Printf("%s[!] Error with vhost %s request to %s (%s): %v%s\n", red, vhost, ip, protocol, err, reset)
						}
						continue
					}

					// Ignore if the status is part of the ignored status codes
					if _, ignored := ignoredStatusCodes[status]; ignored {
						if *verbose {
							fmt.Printf("%s[!] Ignored status code %d for vhost %s on IP %s%s\n", yellow, status, vhost, ip, reset)
						}
						continue
					}

					// Adjust the body by removing the vhost and get its length
					body := string(bodyBytes)
					adjustedBody := strings.ReplaceAll(body, vhost, "")
					adjustedBodyLength := len(adjustedBody)

					// Get adjusted Location header and its length
					locationHeader := headers.Get("Location")
					var adjustedLocationLength int
					if locationHeader != "" {
						adjustedLocation := strings.ReplaceAll(locationHeader, vhost, "")
						adjustedLocationLength = len(adjustedLocation)
					} else {
						adjustedLocationLength = -1
					}

					contentType := headers.Get("Content-Type")

					vhostResponse := ResponseData{
						Status:                 status,
						ContentType:            contentType,
						AdjustedBodyLength:     adjustedBodyLength,
						AdjustedLocationLength: adjustedLocationLength,
					}

					// Compare with the initial base response
					if compareResponses(vhostResponse, baseResponse) {
						// Responses are the same; skip this vhost
						continue
					} else {
						// Responses are different; store for comparison with final base response
						storedVhostResponses = append(storedVhostResponses, StoredVhostResponse{
							Vhost:     vhost,
							Response:  vhostResponse,
							Headers:   headers,
							BodyBytes: bodyBytes,
						})
					}
				}

				// Send second random host request after vhost requests
				finalRandomHost := randomString(16) + ".com"
				finalBaseStatus, finalBaseHeaders, finalBaseBodyBytes, err := sendRequest(ip, finalRandomHost, protocol, baseClient, *maxBodySize)
				if err != nil {
					if *verbose {
						fmt.Printf("%s[!] Error with second random host request to %s (%s): %v%s\n", red, ip, protocol, err, reset)
					}
					continue
				}

				finalBaseContentType := finalBaseHeaders.Get("Content-Type")
				adjustedFinalBaseBody := strings.ReplaceAll(string(finalBaseBodyBytes), finalRandomHost, "")
				adjustedFinalBaseBodyLength := len(adjustedFinalBaseBody)

				var adjustedFinalBaseLocationLength int
				if finalBaseLocationHeader := finalBaseHeaders.Get("Location"); finalBaseLocationHeader != "" {
					adjustedFinalBaseLocation := strings.ReplaceAll(finalBaseLocationHeader, finalRandomHost, "")
					adjustedFinalBaseLocationLength = len(adjustedFinalBaseLocation)
				} else {
					adjustedFinalBaseLocationLength = -1
				}

				finalBaseResponse := ResponseData{
					Status:                 finalBaseStatus,
					ContentType:            finalBaseContentType,
					AdjustedBodyLength:     adjustedFinalBaseBodyLength,
					AdjustedLocationLength: adjustedFinalBaseLocationLength,
				}

				// Now validate stored vhost responses against final base response
				for _, svr := range storedVhostResponses {
					if compareResponses(svr.Response, finalBaseResponse) {
						// Vhost response matches final base response; discard
						continue
					} else {
						// Vhost response is different from both base responses; report it
						result := &Result{
							IP:         ip,
							Vhost:      svr.Vhost,
							Protocol:   protocol,
							Status:     svr.Response.Status,
							BaseStatus: baseStatus,
							Length:     len(svr.BodyBytes),
							Location:   svr.Headers.Get("Location"),
						}

						if *includeHeaders {
							result.Headers = flattenHeaders(svr.Headers)
						}

						if *includeBody {
							result.Body = string(svr.BodyBytes)
						}

						// Check if this vhost and IP combination has already been reported
						key := result.IP + "|" + result.Vhost
						reportedMutex.Lock()
						if _, exists := reportedResults[key]; !exists {
							reportedResults[key] = struct{}{}
							resultsChan <- result
						}
						reportedMutex.Unlock()
					}
				}
			}
		}(ip)
	}

	wg.Wait()
	close(resultsChan)
	writeWg.Wait()

	fmt.Printf("%sScanning completed. Results saved to %s%s\n", green, *outputFile, reset)
}

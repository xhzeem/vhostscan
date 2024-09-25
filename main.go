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

// Color codes for colorful output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

// Result struct for storing the findings
type Result struct {
	IP         string            `json:"ip"`
	Vhost      string            `json:"vhost"`
	Protocol   string            `json:"protocol"`
	Status     int               `json:"status"`
	BaseStatus int               `json:"base_status"`
	Length     int               `json:"content_length"`
	LengthDiff int               `json:"length_diff"`
	Location   string            `json:"location,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	Curl       string            `json:"curl"`
}

type VhostResult struct {
	Result                 *Result
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

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
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
	outputFile := flag.String("output", "/tmp/vhostscan-"+time.Now().Format("2006-01-02_15-04-05")+".json", "Output file in JSON format")
	threads := flag.Int("threads", 10, "Number of concurrent threads")
	timeout := flag.Int("timeout", 10, "HTTP request timeout in seconds")
	contentLengthDiff := flag.Int("length-diff", 100, "Content length difference threshold")
	verbose := flag.Bool("verbose", false, "Enable verbose output")
	includeHeaders := flag.Bool("include-headers", false, "Include response headers in the output")
	includeBody := flag.Bool("include-body", false, "Include response body in the output")
	maxBodySize := flag.Int64("max-body-size", 1024*1024, "Maximum size of response body to include (in bytes), 0 for unlimited")
	ignoreStatusCodesStr := flag.String("ignore-status", "429,500,501,502,503,504,530", "Comma-separated list of status codes to ignore")
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
			result.Curl = generateCurlCommand(result.IP, result.Vhost, result.Protocol)
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
			fmt.Printf("    Status: %d, Base Status: %d, Length Diff: %d\n", result.Status, result.BaseStatus, result.LengthDiff)
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

			protocols := []string{"http", "https"}
			for _, protocol := range protocols {
				if *verbose {
					fmt.Printf("%s[*] Testing IP %s over %s%s\n", blue, ip, protocol, reset)
				}

				// Send initial random host request
				firstRandomHost := randomString(16) + ".com"
				baseStatus, baseHeaders, baseBody, err := sendRequest(ip, firstRandomHost, protocol, baseClient, *maxBodySize)
				if err != nil {
					if *verbose {
						fmt.Printf("%s[!] Error with first random host request to %s (%s): %v%s\n", red, ip, protocol, err, reset)
					}
					continue
				}
				baseLength := len(baseBody)

				// Get adjusted Location header length for the initial request
				baseLocationHeader := baseHeaders.Get("Location")
				var adjustedBaseLocationLength int
				if baseLocationHeader != "" {
					adjustedBaseLocation := strings.Replace(baseLocationHeader, firstRandomHost, "", -1)
					adjustedBaseLocationLength = len(adjustedBaseLocation)
				} else {
					adjustedBaseLocationLength = -1
				}

				// Store vhost responses
				vhostResults := []*VhostResult{}

				for _, vhost := range vhosts {
					// Delay between requests
					if *delay > 0 {
						time.Sleep(time.Duration(*delay) * time.Millisecond)
					}

					// Send request with actual vhost
					status, headers, body, err := sendRequest(ip, vhost, protocol, baseClient, *maxBodySize)
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

					length := len(body)

					// Get adjusted Location header length for the vhost request
					locationHeader := headers.Get("Location")
					var adjustedLocationLength int
					if locationHeader != "" {
						adjustedLocation := strings.Replace(locationHeader, vhost, "", -1)
						adjustedLocationLength = len(adjustedLocation)
					} else {
						adjustedLocationLength = -1
					}

					// Compare with the initial random request
					if status != baseStatus || abs(length-baseLength) >= *contentLengthDiff || adjustedLocationLength != adjustedBaseLocationLength {
						result := &Result{
							IP:         ip,
							Vhost:      vhost,
							Protocol:   protocol,
							Status:     status,
							BaseStatus: baseStatus,
							Length:     length,
							LengthDiff: length - baseLength,
							Location:   locationHeader,
						}

						if *includeHeaders {
							result.Headers = flattenHeaders(headers)
						}

						if *includeBody {
							result.Body = base64.StdEncoding.EncodeToString(body)
						}

						// Append to vhostResults
						vhostResults = append(vhostResults, &VhostResult{
							Result:                 result,
							AdjustedLocationLength: adjustedLocationLength,
						})
					}
				}

				// Send final random host request
				finalRandomHost := randomString(16) + ".com"
				finalBaseStatus, finalBaseHeaders, finalBaseBody, err := sendRequest(ip, finalRandomHost, protocol, baseClient, *maxBodySize)
				if err != nil {
					if *verbose {
						fmt.Printf("%s[!] Error with final random host request to %s (%s): %v%s\n", red, ip, protocol, err, reset)
					}
					continue
				}
				finalBaseLength := len(finalBaseBody)

				// Get adjusted Location header length for the final request
				finalBaseLocationHeader := finalBaseHeaders.Get("Location")
				var adjustedFinalBaseLocationLength int
				if finalBaseLocationHeader != "" {
					adjustedFinalBaseLocation := strings.Replace(finalBaseLocationHeader, finalRandomHost, "", -1)
					adjustedFinalBaseLocationLength = len(adjustedFinalBaseLocation)
				} else {
					adjustedFinalBaseLocationLength = -1
				}

				// Now validate all vhost results against both random host requests
				for _, vhostResult := range vhostResults {
					result := vhostResult.Result
					adjustedLocationLength := vhostResult.AdjustedLocationLength

					statusDiff := result.Status != baseStatus && result.Status != finalBaseStatus
					lengthDiff := abs(result.Length-baseLength) >= *contentLengthDiff && abs(result.Length-finalBaseLength) >= *contentLengthDiff

					// Compare adjusted Location header lengths
					locationLengthDiff := adjustedLocationLength != adjustedBaseLocationLength && adjustedLocationLength != adjustedFinalBaseLocationLength

					if statusDiff || lengthDiff || locationLengthDiff {
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

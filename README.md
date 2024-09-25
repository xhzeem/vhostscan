# VHost Scanner

A virtual host (vhost) scanner written in Go that scans IP addresses by sending HTTP requests with various `Host` headers. The tool identifies valid vhosts by detecting significant differences in server responses when using known virtual host names compared to random hostnames. It captures and logs response details such as status codes, headers, body content, and content length differences, making it a valuable resource for security researchers and penetration testers.

## How It Works

The VHost Scanner operates by comparing server responses to distinguish valid virtual hosts from invalid ones:

1. **Baseline Requests**: For each IP address and protocol (HTTP and HTTPS), the scanner sends two requests with random hostnames. These serve as baseline responses to compare against.

2. **VHost Requests**: The scanner sends requests using the IP address and each vhost from the provided list as the `Host` header.

3. **Response Comparison**: It compares the responses from the vhost requests with the baseline responses. Differences in status codes, content lengths, and `Location` headers indicate potential valid vhosts.

4. **Result Filtering**: Only vhosts that produce responses significantly different from both baseline responses are reported. The tool ensures the same vhost and IP combination is not reported twice, even if found over both HTTP and HTTPS.

5. **Output Generation**: Findings are outputted in colorful, formatted text during execution and saved to a JSON file for further analysis.

## Installation

Install the VHost Scanner using the Go tool:

```bash
go install github.com/xhzeem/vhostscan@latest
```

## Usage

Customize the scanner through various command-line options:

```bash
vhostscan -ips <ip_list_file> -vhosts <vhost_file> -output <output_file>
```

### Command-Line Flags

- `-ips`: Path to a file containing a list of IP addresses to scan (default: `ips.txt`).
- `-vhosts`: Path to a file containing virtual host names (Host headers) for scanning (default: `vhosts.txt`).
- `-output`: File where the JSON-formatted output will be saved (default: `vhostscan-<timestamp>.json` in the current directory).
- `-threads`: Number of concurrent threads to use for scanning (default: 10).
- `-timeout`: HTTP request timeout in seconds (default: 10).
- `-length-diff`: Threshold for content length difference filtering (default: 100).
- `-include-headers`: Include HTTP response headers in the output.
- `-include-body`: Include the HTTP response body in the output.
- `-max-body-size`: Maximum size of the response body to include in the output (in bytes, default: 1 MB).
- `-ignore-status`: Comma-separated list of status codes to ignore (default: `403,409`).
- `-proxy`: Proxy URL to route requests (e.g., `http://proxy:port`).
- `-delay`: Delay between requests in milliseconds (default: 0).
- `-no-color`: Disable color output in the console.
- `-verbose`: Enable verbose output for more detailed logging.

### Example Command

```bash
vhostscan -ips ips.txt -vhosts vhosts.txt -output results.json -threads 20 -timeout 5 -length-diff 150 -include-body -include-headers -max-body-size 2048 -delay 100 -no-color -verbose
```

### How the Tool Finds a VHost

The VHost Scanner identifies valid virtual hosts by:

- **Comparing Responses**: It compares the HTTP responses from requests using the target vhost with those from baseline requests using random hostnames.
- **Analyzing Differences**: Significant differences in status codes, content lengths, or adjusted `Location` header lengths (after removing the vhost from the header) suggest the vhost may be valid.
- **Filtering Out Noise**: By sending two baseline requests with different random hostnames, the tool ensures that differences are consistent and not due to transient server behavior.
- **Avoiding Duplicates**: It reports each vhost and IP combination only once, even if found over both HTTP and HTTPS.

## Output

During execution, the tool provides real-time, color-coded output in the console, indicating discovered vhosts and relevant details.

### Console Output Example

```bash
 __ __  __ __   ___   _____ ______  _____   __   ____  ____  
|  |  ||  |  | /   \ / ___/|      |/ ___/  /  ] /    ||    \ 
|  |  ||  |  ||     (   \_ |      (   \_  /  / |  o  ||  _  |
|  |  ||  _  ||  O  |\__  ||_|  |_|\__  |/  /  |     ||  |  |
|  :  ||  |  ||     |/  \ |  |  |  /  \ /   \_ |  _  ||  |  |
 \   / |  |  ||     |\    |  |  |  \    \     ||  |  ||  |  |
  \_/  |__|__| \___/  \___|  |__|   \___|\____||__|__||__|__|                                                         

[+] Found Vhost: example.com on IP 192.168.1.1 (http)
    Status: 200, Base Status: 404, Length Diff: 1024
    Location Header: https://example.com/welcome
    Command: curl -k -H 'Host: example.com' 'http://192.168.1.1'
```

### JSON Output

The findings are also saved in a JSON-formatted file for further analysis. Each entry includes detailed information about the request and response.

#### Fields in the Output

- `ip`: The IP address that was scanned.
- `vhost`: The virtual host name used in the request.
- `protocol`: The protocol used (`http` or `https`).
- `status`: The HTTP status code returned by the server.
- `base_status`: The baseline HTTP status code from the server with a random hostname.
- `content_length`: The length of the response body.
- `length_diff`: The difference in content length compared to the baseline responses.
- `location`: The `Location` header value from the response (if present).
- `headers`: HTTP response headers (if `-include-headers` is used).
- `body`: The HTTP response body, Base64-encoded (if `-include-body` is used).
- `curl`: A cURL command replicating the request for further testing.

#### Example JSON Output

```json
[
  {
    "ip": "1.1.1.1",
    "vhost": "example.com",
    "protocol": "http",
    "status": 200,
    "base_status": 404,
    "content_length": 2048,
    "length_diff": 1024,
    "location": "https://example.com/welcome",
    "headers": {
      "Content-Type": "text/html",
      "Server": "nginx",
      "Location": "https://example.com/welcome"
    },
    "body": "PGh0bWw+PC9odG1sPg==",
    "curl": "curl -k -H 'Host: example.com' 'http://192.168.1.1'"
  }
]
```

## Limitations

- **False Positives**: Some servers may return similar responses for different hostnames, potentially leading to false positives.

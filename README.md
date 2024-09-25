# VHost Scanner

A virtual host (vhost) scanner written in Go that scans IP addresses by sending HTTP requests with various `Host` headers. The tool identifies valid vhosts by detecting significant differences in server responses when using known virtual host names compared to random hostnames. It captures and logs response details such as status codes, headers, body content, and content length, making it a valuable resource for security researchers and penetration testers.

## How It Works

The VHost Scanner operates by comparing server responses to distinguish valid virtual hosts from invalid ones:

1. **Baseline Requests**: For each IP address and protocol (HTTP and HTTPS), the scanner sends two requests with random hostnames. These serve as baseline responses to compare against.

2. **VHost Requests**: The scanner sends requests using the IP address and each vhost from the provided list as the `Host` header.

3. **Response Comparison**: It compares the responses from the vhost requests with the baseline responses. The comparison is based on:

   - **Status Codes**
   - **Content-Type Headers**
   - **Adjusted Body Lengths**: The length of the response body after removing occurrences of the vhost or random hostname.
   - **Adjusted `Location` Header Lengths**: The length of the `Location` header after removing occurrences of the vhost or random hostname.

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
- `-include-headers`: Include HTTP response headers in the output.
- `-include-body`: Include the HTTP response body in the output.
- `-max-body-size`: Maximum size of the response body to include in the output (in bytes, default: 1 MB).
- `-ignore-status`: Comma-separated list of status codes to ignore (default: `403,429,500,501,502,503,504,530`).
- `-proxy`: Proxy URL to route requests (e.g., `http://proxy:port`).
- `-delay`: Delay between requests in milliseconds (default: 0).
- `-no-color`: Disable color output in the console.
- `-verbose`: Enable verbose output for more detailed logging.

### Example Command

```bash
vhostscan -ips ips.txt -vhosts vhosts.txt -output results.json -include-body -include-headers
```

### How the Tool Finds a VHost

The VHost Scanner identifies valid virtual hosts by:

- **Comparing Responses**: It compares the HTTP responses from requests using the target vhost with those from baseline requests using random hostnames.

- **Analyzing Differences**: Significant differences in status codes, content types, body lengths, or `Location` header lengths suggest the vhost may be valid.

  - **Adjusted Body Length**: The length of the response body after removing occurrences of the vhost form it.
  - **Adjusted `Location` Header Length**: The length of the `Location` header after removing occurrences of the vhost from it.

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
    Status: 200, Base Status: 404
    Location: https://example.com/welcome
    Command: curl -i -k -H 'Host: example.com' 'http://192.168.1.1'
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
- `location`: The `Location` header value from the response (if present).
- `headers`: HTTP response headers (if `-include-headers` is used).
- `body`: The HTTP response body (if `-include-body` is used).
- `curl`: A cURL command replicating the request for further testing.

#### Example JSON Output

```json
[
  {
    "ip": "192.168.1.1",
    "vhost": "example.com",
    "protocol": "http",
    "status": 200,
    "base_status": 404,
    "content_length": 2048,
    "location": "https://example.com/welcome",
    "headers": {
      "Content-Type": "text/html",
      "Server": "nginx",
      "Location": "https://example.com/welcome"
    },
    "body": "<html><body>Welcome to example.com</body></html>",
    "curl": "curl -i -k -H 'Host: example.com' 'http://192.168.1.1'"
  }
]
```

## Limitations

- **False Positives**: Some servers may return similar responses for different hostnames, potentially leading to false positives.
- **Ignored Status Codes**: Be cautious with the `-ignore-status` flag, as ignoring certain status codes might cause you to miss valid vhosts.

## Tips

- **Adjust Ignored Status Codes**: Modify the `-ignore-status` flag to suit your target environment. The default ignored status codes are `403,429,500,501,502,503,504,530`.

- **Use Verbose Mode**: Enable `-verbose` to get detailed logs, which can help in troubleshooting and understanding the scanning process.

- **Include Headers and Body**: Use `-include-headers` and `-include-body` flags to capture more details in the output, which can be helpful for in-depth analysis.

- **Adjust Threads and Delays**: Use the `-threads` and `-delay` options to control the load on the target servers and avoid triggering rate limits or detection.

## License

This project is licensed under the MIT License.

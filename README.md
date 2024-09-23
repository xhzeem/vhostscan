# VHost Scanner

A virtual host (vhost) scanner written in Go that scans IP addresses by sending HTTP requests with various `Host` headers. This tool captures and logs response details such as status codes, headers, body content, and content length differences, making it a useful resource for security researchers and penetration testers.

## Features

- **Host header manipulation**: Identify valid vhosts by sending requests to IP addresses with different `Host` headers.
- **Multithreading**: Perform concurrent scans to increase efficiency.
- **Response filtering**: Filter based on content length differences and ignored status codes.
- **Customizable output**: Optionally include response headers and bodies in the JSON output.
- **Proxy support**: Route requests through a specified proxy server.

## Installation

Install the vhost scanner directly from the repository using the Go tool:

```bash
go install github.com/xhzeem/vhostscan@latest
```

## Usage

The vhost scanner can be customized through various command-line options:

```bash
vhostscan -ips <ip_list_file> -vhosts <vhost_file> -output <output_file>
```

### Command-Line Flags

- `-ips`: Path to a file containing a list of IP addresses to scan (default: `ips.txt`).
- `-vhosts`: Path to a file containing virtual host names (Host headers) for scanning (default: `vhosts.txt`).
- `-output`: File where the JSON-formatted output will be saved (default: `output.json`).
- `-threads`: Number of concurrent threads to use for scanning (default: 10).
- `-timeout`: HTTP request timeout in seconds (default: 10).
- `-length-diff`: Threshold for content length difference filtering (default: 100).
- `-include-headers`: Include HTTP response headers in the output.
- `-include-body`: Include the HTTP response body in the output.
- `-max-body-size`: Maximum size of the response body to include in the output (default: 1 MB).
- `-ignore-status`: Comma-separated list of status codes to ignore (default: `403,409`).
- `-proxy`: Proxy URL to route requests (e.g., `http://proxy:port`).
- `-verbose`: Enable verbose output for more detailed logging.

### Example Command

```bash
vhostscan -ips ips.txt -vhosts vhosts.txt -output result.json -threads 20 -timeout 5 -length-diff 150 -include-body -include-headers -max-body-size 2048
```

## Output

The tool produces a JSON-formatted output, which includes detailed information for each scanned combination of IP address and virtual host. The fields in the output include:

- `ip`: The IP address that was scanned.
- `vhost`: The virtual host name used in the request.
- `protocol`: The protocol used (HTTP or HTTPS).
- `status`: The HTTP status code returned by the server.
- `base_status`: The baseline HTTP status code from the server without a host header.
- `length`: The length of the response body.
- `length_diff`: The difference in content length compared to a baseline response.
- `headers`: HTTP response headers (if `-include-headers` is used).
- `body`: The HTTP response body (if `-include-body` is used).
- `curl`: A cURL command replicating the request for further testing.

## Example Output

```json
{
  "ip": "192.168.1.1",
  "vhost": "example.com",
  "protocol": "https",
  "status": 200,
  "base_status": 404,
  "length": 512,
  "length_diff": 50,
  "headers": {
    "Content-Type": "text/html",
    "Server": "nginx"
  },
  "body": "base64=",
  "curl": "curl -k -H 'Host: example.com' https://192.168.1.1"
}
```

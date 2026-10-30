![Banner](banner.png)

# net-dns-query

**Project Description:**

net-dns-query is a cybersecurity tool used to perform DNS queries for specific hostnames. It is designed to perform basic network operations, such as name resolution and IP address retrieval. The tool utilizes the Python standard library socket module to resolve hostnames; it has no third-party dependencies.

**Installation:**

1. Clone the GitHub repository using the command:
   ```
   git clone https://github.com/ShadowStrikeHQ/net-dns-query.git
   ```
2. Navigate to the project directory:
   ```
   cd net-dns-query
   ```
3. Install required dependencies using pip:
   ```
   pip install -r requirements.txt
   ```

**Usage Examples:**

The tool can be used with the following command-line arguments:

```
usage: main.py [-h] [--type TYPE] [--server SERVER] [--port PORT]
               [--timeout TIMEOUT] [--retries RETRIES] [--version]
               hostname

positional arguments:
  hostname           The hostname to query.

options:
  -h, --help         show this help message and exit
  --type TYPE        DNS record type (default: A). Note: resolution is performed
                     with getaddrinfo, so the resolved addresses are returned
                     regardless of the requested record type.
  --server SERVER    DNS server IP address (default: system default).
  --port PORT        DNS server port (default: 53).
  --timeout TIMEOUT  Query timeout in seconds (default: 5).
  --retries RETRIES  Number of query retries (default: 3).
  --version          show program's version number and exit
```

**Examples:**

* Resolve `localhost`:
   ```
   python main.py localhost
   ```

* Resolve `example.com` with two retries:
   ```
   python main.py example.com --retries 2
   ```

**Security Warnings and Considerations:**

* The tool should not be used for malicious purposes, such as phishing or spamming.
* DNS queries may reveal information about the user's network configuration or browsing history.

**License:**

This tool is licensed under the GNU General Public License v3.0 (GPL-3.0).
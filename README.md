![Banner](banner.png)

# net-dns-query

**Project Description:**

net-dns-query is a cybersecurity tool used to perform DNS queries for specific hostnames. It is designed to perform basic network operations, such as name resolution and IP address retrieval. The tool uses only the Python standard library. Without a server option it resolves hostnames with the system resolver. With `--server`, it builds a DNS wire format query and sends it over UDP to the named server and port, then prints the answers returned by that server for the requested record type. Supported record types with `--server` are A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, and TXT.

**Installation:**

1. Clone the GitHub repository using the command:
   ```
   git clone https://github.com/ShadowGuard-AI/net-dns-query.git
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
  --type TYPE        DNS record type (default: A). With --server, the query
                     asks for this record type. Without --server, the system
                     resolver is used and the returned addresses are returned
                     regardless of the requested record type.
  --server SERVER    DNS server IP address (default: system default). When
                     given, a DNS query is sent to this server over UDP.
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

* Ask a specific DNS server for the AAAA record of `example.com`:
   ```
   python main.py example.com --type AAAA --server 1.1.1.1
   ```

If the named server does not answer, returns an error, or returns no records of the requested type, the tool reports the failure and exits with a non-zero status.

**Security Warnings and Considerations:**

* The tool should not be used for malicious purposes, such as phishing or spamming.
* DNS queries may reveal information about the user's network configuration or browsing history.

**License:**

This tool is licensed under the GNU General Public License v3.0 (GPL-3.0).
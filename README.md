# net-dns-query

**Project Description:**

net-dns-query is a cybersecurity tool used to perform DNS queries for specific hostnames. It is designed to perform basic network operations, such as name resolution and IP address retrieval. The tool utilizes the socket and requests libraries to interact with the network and perform DNS queries.

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
usage: main.py [-h] [-d DOMAIN] [-t TYPE] [-a] [-v]

Perform DNS queries for specific hostnames.

optional arguments:
  -h, --help          show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain name to query (default: google.com)
  -t TYPE, --type TYPE
                        Type of DNS query to perform (default: A)
  -a, --all            Perform all types of DNS queries (A, AAAA, MX, NS, CNAME, SOA)
  -v, --verbose       Enable verbose output
```

**Examples:**

* Perform an A record query for `google.com`:
   ```
   python main.py -d google.com
   ```

* Perform all types of DNS queries for `example.com`:
   ```
   python main.py -d example.com -a
   ```

**Security Warnings and Considerations:**

* The tool should not be used for malicious purposes, such as phishing or spamming.
* DNS queries may reveal information about the user's network configuration or browsing history.

**License:**

This tool is licensed under the GNU General Public License v3.0 (GPL-3.0).
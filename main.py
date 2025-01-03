import socket
import argparse
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the command-line arguments for the tool.
    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="net-dns-query: A tool to perform DNS queries for specific hostnames."
    )
    parser.add_argument("hostname", type=str, help="The hostname to query.")
    parser.add_argument("--type", type=str, default="A", help="DNS record type (default: A).")
    parser.add_argument("--server", type=str, help="DNS server IP address (default: system default).")
    parser.add_argument("--port", type=int, default=53, help="DNS server port (default: 53).")
    parser.add_argument("--timeout", type=int, default=5, help="Query timeout in seconds (default: 5).")
    parser.add_argument("--retries", type=int, default=3, help="Number of query retries (default: 3).")
    parser.add_argument("--version", action="version", version="net-dns-query 1.0")
    return parser.parse_args()

def perform_dns_query(hostname, record_type="A", server=None, port=53, timeout=5, retries=3):
    """
    Performs a DNS query for the specified hostname and record type.
    Args:
        hostname (str): The hostname to query.
        record_type (str): The type of DNS record to query (default: A).
        server (str): DNS server to use (default: None).
        port (int): Port of the DNS server (default: 53).
        timeout (int): Query timeout in seconds (default: 5).
        retries (int): Number of retries in case of failure (default: 3).
    Returns:
        list: Resolved addresses or details based on record type.
    Raises:
        Exception: If the query fails after specified retries.
    """
    for attempt in range(retries):
        try:
            logging.info(f"Attempting DNS query for {hostname} (type: {record_type}, attempt: {attempt + 1})")
            if server:
                logging.info(f"Using custom DNS server: {server}:{port}")
                socket.setdefaulttimeout(timeout)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.connect((server, port))
            result = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            addresses = [res[4][0] for res in result if res[0] == socket.AF_INET or res[0] == socket.AF_INET6]
            logging.info(f"Query successful for {hostname}. Resolved addresses: {addresses}")
            return addresses
        except socket.gaierror as e:
            logging.error(f"DNS query failed for {hostname}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error occurred: {e}")
        if attempt < retries - 1:
            logging.info(f"Retrying ({attempt + 2}/{retries})...")
    raise Exception(f"Failed to resolve {hostname} after {retries} attempts.")

def main():
    """
    Main entry point for the DNS query tool.
    """
    args = setup_argparse()
    try:
        results = perform_dns_query(
            hostname=args.hostname,
            record_type=args.type,
            server=args.server,
            port=args.port,
            timeout=args.timeout,
            retries=args.retries
        )
        print(f"Resolved addresses for {args.hostname}: {results}")
    except Exception as e:
        logging.error(f"DNS query failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
import socket
import argparse
import logging
import random
import struct
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

RECORD_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
}
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
    parser.add_argument("--type", type=str, default="A", help="DNS record type (default: A). With --server, the query asks for this record type. Without --server, the system resolver is used and the returned addresses are returned regardless of the requested record type.")
    parser.add_argument("--server", type=str, help="DNS server IP address (default: system default). When given, a DNS query is sent to this server over UDP.")
    parser.add_argument("--port", type=int, default=53, help="DNS server port (default: 53).")
    parser.add_argument("--timeout", type=int, default=5, help="Query timeout in seconds (default: 5).")
    parser.add_argument("--retries", type=int, default=3, help="Number of query retries (default: 3).")
    parser.add_argument("--version", action="version", version="net-dns-query 1.0")
    return parser.parse_args()

def build_dns_query(hostname, qtype):
    """Builds a DNS wire format query for hostname and qtype."""
    # The transaction id is the only thing tying a UDP reply back to this query. UDP gives me no connection, so I generate it here and check it on the way in below.
    txid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for label in hostname.rstrip(".").split("."):
        if not label:
            continue
        # I encode each label on its own and check the encoded length, not the raw length. A short looking name in another script can pass 63 bytes once it is punycode, and the wire format counts encoded bytes.
        encoded = label.encode("idna")
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long: {label}")
        qname += struct.pack(">B", len(encoded)) + encoded
    qname += b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    return txid, header + question

def parse_dns_name(data, offset):
    """Parses a possibly compressed DNS name. Returns (name, next offset)."""
    labels = []
    jumped = False
    next_offset = offset
    seen = set()
    while True:
        if offset >= len(data):
            raise ValueError("DNS name runs past the end of the response.")
        # A hostile or broken server can point a compressed name back at itself. I track every offset I visit so that loop raises here instead of spinning forever on one packet.
        if offset in seen:
            raise ValueError("DNS name compression loop in response.")
        seen.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            # After a jump, the caller still needs the offset just past the original pointer, not past the pointed to name. I only move next_offset the first time, which is the part of DNS compression people usually get wrong.
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Truncated DNS name pointer in response.")
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        label = data[offset:offset + length]
        if len(label) != length:
            raise ValueError("Truncated DNS label in response.")
        labels.append(label.decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), next_offset

def format_rdata(data, offset, rdlength, rtype):
    """Formats one record's data as text for the record types this tool supports."""
    rdata = data[offset:offset + rdlength]
    if rtype == 1 and rdlength == 4:
        return socket.inet_ntoa(rdata)
    if rtype == 28 and rdlength == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (2, 5, 12):
        name, _ = parse_dns_name(data, offset)
        return name
    if rtype == 15 and rdlength > 2:
        preference = struct.unpack(">H", rdata[:2])[0]
        name, _ = parse_dns_name(data, offset + 2)
        return f"{preference} {name}"
    if rtype == 16:
        parts = []
        pos = 0
        while pos < len(rdata):
            ln = rdata[pos]
            parts.append(rdata[pos + 1:pos + 1 + ln].decode("utf-8", "replace"))
            pos += 1 + ln
        return "".join(parts)
    if rtype == 33 and rdlength > 6:
        priority, weight, port = struct.unpack(">HHH", rdata[:6])
        name, _ = parse_dns_name(data, offset + 6)
        return f"{priority} {weight} {port} {name}"
    if rtype == 6:
        mname, pos = parse_dns_name(data, offset)
        rname, pos = parse_dns_name(data, pos)
        numbers = struct.unpack(">IIIII", data[pos:pos + 20])
        return f"{mname} {rname} {numbers[0]} {numbers[1]} {numbers[2]} {numbers[3]} {numbers[4]}"
    # For a record type I do not format, hex is the honest fallback. Guessing at a text shape I do not know would look like an answer and could be completely wrong.
    return rdata.hex()

def parse_dns_response(data, expected_txid, expected_qtype):
    """Parses a DNS response and returns the answer strings for the queried type."""
    if len(data) < 12:
        raise ValueError("DNS response is too short.")
    txid, flags, qdcount, ancount = struct.unpack(">HHHH", data[:8])
    if txid != expected_txid:
        raise ValueError("DNS response ID does not match the query ID.")
    rcode = flags & 0x000F
    if rcode != 0:
        raise ValueError(f"DNS server returned error code {rcode}.")
    offset = 12
    for _ in range(qdcount):
        _, offset = parse_dns_name(data, offset)
        offset += 4
    answers = []
    for _ in range(ancount):
        _, offset = parse_dns_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("Truncated DNS answer in response.")
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            raise ValueError("Truncated DNS record data in response.")
        # A response can carry CNAMEs and other types on the way to the answer I asked for. I filter by the requested type here, so a CNAME chain alone counts as no records, which matches what query_dns_server promises its caller.
        if rtype == expected_qtype:
            answers.append(format_rdata(data, offset, rdlength, rtype))
        offset += rdlength
    return answers

def query_dns_server(hostname, record_type, server, port, timeout):
    """
    Sends one DNS wire query for hostname to server:port over UDP and
    returns the answers from that server for the requested record type.
    Raises OSError, socket.timeout, or ValueError on failure, and
    ValueError when the server returns no records of the requested type.
    """
    qtype_name = record_type.upper()
    if qtype_name not in RECORD_TYPES:
        supported = ", ".join(sorted(RECORD_TYPES))
        raise ValueError(f"Unsupported record type: {record_type}. Supported types: {supported}.")
    qtype = RECORD_TYPES[qtype_name]
    txid, query = build_dns_query(hostname, qtype)
    # I pick the family from the server string because getaddrinfo would resolve a name here and I want this path to talk only to the server I was given. A colon means the caller handed me an IPv6 literal.
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.send(query)
        data = sock.recv(4096)
        answers = parse_dns_response(data, txid, qtype)
    finally:
        sock.close()
    if not answers:
        raise ValueError(f"DNS server {server}:{port} returned no {qtype_name} records for {hostname}.")
    return answers

def perform_dns_query(hostname, record_type="A", server=None, port=53, timeout=5, retries=3):
    """
    Performs a DNS query for the specified hostname and record type.
    Args:
        hostname (str): The hostname to query.
        record_type (str): The type of DNS record to query (default: A).
        server (str): DNS server to use (default: None). When given, the
            query is sent to that server over UDP. When omitted, the
            system resolver is used.
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
                addresses = query_dns_server(hostname, record_type, server, port, timeout)
                logging.info(f"Query successful for {hostname}. Resolved addresses: {addresses}")
                return addresses
            # Without a server this path is a different tool: the system resolver decides everything and the record type argument is ignored. I keep that split explicit because callers are surprised when --type MX still returns addresses here.
            result = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            addresses = [res[4][0] for res in result if res[0] == socket.AF_INET or res[0] == socket.AF_INET6]
            if not addresses:
                raise Exception(f"No addresses returned for {hostname}.")
            logging.info(f"Query successful for {hostname}. Resolved addresses: {addresses}")
            return addresses
        except socket.gaierror as e:
            logging.error(f"DNS query failed for {hostname}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error occurred: {e}")
        # I retry resolver failures and server failures the same way, which is a tradeoff. A bad hostname will burn all three attempts before it fails, but a flaky UDP reply gets the second chances it needs.
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

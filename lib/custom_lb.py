import socket
import threading
import time
import requests
import logging
import argparse
import socks # PySocks

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')

# Shared state for the best proxy
# Needs a lock for thread-safe updates and reads
_best_proxy_lock = threading.Lock()
_best_proxy = None # Will be a tuple (host, port)
_target_proxies = [] # List of (host, port) tuples

# Gstatic URL for health checks
GSTATIC_URL = "http://clients3.google.com/generate_204"
HEALTH_CHECK_TIMEOUT = 5 # seconds
MONITORING_INTERVAL = 60 # seconds

def check_proxy_health(proxy_host, proxy_port):
    """Checks the health of a single SOCKS5 proxy by timing a request to GSTATIC_URL."""
    session = requests.Session()
    session.proxies = {
        'http': f'socks5h://{proxy_host}:{proxy_port}',
        'https': f'socks5h://{proxy_host}:{proxy_port}'
    }
    try:
        start_time = time.time()
        response = session.get(GSTATIC_URL, timeout=HEALTH_CHECK_TIMEOUT)
        end_time = time.time()
        if response.status_code == 204:
            latency = end_time - start_time
            logging.info(f"Proxy {proxy_host}:{proxy_port} healthy, latency: {latency:.4f}s")
            return latency
        else:
            logging.warning(f"Proxy {proxy_host}:{proxy_port} unhealthy, status: {response.status_code}")
            return float('inf')
    except requests.exceptions.RequestException as e:
        logging.error(f"Proxy {proxy_host}:{proxy_port} error: {e}")
        return float('inf')

def monitor_proxies():
    """Periodically checks all target proxies and updates the best one."""
    global _best_proxy
    while True:
        current_best_latency = float('inf')
        current_best_proxy_candidate = None

        if not _target_proxies:
            logging.warning("Monitor: No target proxies configured.")
            with _best_proxy_lock:
                _best_proxy = None # Clear best proxy if none are available
            time.sleep(MONITORING_INTERVAL)
            continue

        for host, port in _target_proxies:
            latency = check_proxy_health(host, port)
            if latency < current_best_latency:
                current_best_latency = latency
                current_best_proxy_candidate = (host, port)

        with _best_proxy_lock:
            if current_best_proxy_candidate:
                if _best_proxy != current_best_proxy_candidate:
                    logging.info(f"New best proxy: {current_best_proxy_candidate[0]}:{current_best_proxy_candidate[1]} with latency {current_best_latency:.4f}s")
                    _best_proxy = current_best_proxy_candidate
                else:
                    logging.info(f"Best proxy remains {current_best_proxy_candidate[0]}:{current_best_proxy_candidate[1]}")
            elif _best_proxy is not None:
                logging.warning("No healthy proxy found, clearing current best proxy.")
                _best_proxy = None
            else:
                logging.info("No healthy proxy found and no best proxy was set.")


        time.sleep(MONITORING_INTERVAL)

def get_best_proxy():
    """Returns the current best proxy in a thread-safe manner."""
    with _best_proxy_lock:
        return _best_proxy

def handle_client_connection(client_socket, client_address):
    """Handles a single client connection, forwarding it through the best SOCKS5 proxy."""
    logging.info(f"Accepted connection from {client_address}")
    proxy_socket = None # Ensure proxy_socket is defined for the finally block

    try:
        # 1. Get the current best SOCKS proxy
        upstream_proxy = get_best_proxy()
        if not upstream_proxy:
            logging.error(f"No healthy upstream SOCKS proxy available for {client_address}. Closing connection.")
            # Note: We can't send a SOCKS error yet as we haven't done the handshake. Just close.
            client_socket.close()
            return

        upstream_host, upstream_port = upstream_proxy
        logging.info(f"Selected upstream SOCKS proxy {upstream_host}:{upstream_port} for {client_address}")

        # 2. SOCKS5 handshake with the client (Version identifier/method selection)
        # This part remains the same as the original code.
        version_id_msg = client_socket.recv(2)
        if not version_id_msg or len(version_id_msg) < 2:
            logging.warning(f"Client {client_address} sent incomplete version/nmethods. Closing.")
            client_socket.close(); return

        sock_version, nmethods = version_id_msg[0], version_id_msg[1]
        if sock_version != 0x05:
            logging.error(f"Unsupported SOCKS version from {client_address}: {sock_version}"); client_socket.close(); return

        client_methods = client_socket.recv(nmethods)
        if 0x00 not in client_methods:
            logging.error(f"Client {client_address} does not support NO AUTH method. Closing.")
            client_socket.sendall(b'\x05\xFF'); client_socket.close(); return

        client_socket.sendall(b'\x05\x00') # Select NO AUTH method

        # 3. SOCKS5 client request (get destination from client)
        # This part also remains the same.
        client_req_header = client_socket.recv(4)
        if not client_req_header or len(client_req_header) < 4:
            logging.warning(f"Client {client_address} sent incomplete request header. Closing."); client_socket.close(); return
        
        req_ver, req_cmd, _, req_atyp = client_req_header
        if req_ver != 0x05 or req_cmd != 0x01: # Check for SOCKSv5 CONNECT
            logging.error(f"Unsupported request from {client_address}: VER={req_ver}, CMD={req_cmd}. Sending error.")
            client_socket.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00'); client_socket.close(); return

        if req_atyp == 0x01: # IPv4
            dst_addr_bytes = client_socket.recv(4)
        elif req_atyp == 0x03: # Domain name
            domain_len_byte = client_socket.recv(1)
            domain_len = domain_len_byte[0]
            dst_addr_bytes = domain_len_byte + client_socket.recv(domain_len)
        elif req_atyp == 0x04: # IPv6
            dst_addr_bytes = client_socket.recv(16)
        else:
            logging.error(f"Unsupported ATYP from {client_address}: {req_atyp}. Sending error.")
            client_socket.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00'); client_socket.close(); return
        
        dst_port_bytes = client_socket.recv(2)
        if len(dst_addr_bytes) < 1 or len(dst_port_bytes) < 2: # Basic check
             logging.warning(f"Client {client_address} sent incomplete address/port. Closing."); client_socket.close(); return

        # 4. Connect and handshake with the upstream SOCKS proxy
        # *** THIS IS THE MAIN CORRECTED SECTION ***
        logging.debug(f"Connecting to upstream proxy {upstream_host}:{upstream_port}")
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.settimeout(10)
        proxy_socket.connect((upstream_host, upstream_port))

        # Perform SOCKS5 handshake with upstream proxy (we offer NO AUTH)
        proxy_socket.sendall(b'\x05\x01\x00')
        server_choice = proxy_socket.recv(2)
        if len(server_choice) < 2 or server_choice[0] != 0x05 or server_choice[1] != 0x00:
            raise socks.SOCKS5Error(f"Upstream proxy {upstream_host}:{upstream_port} did not accept NO AUTH method. Reply: {server_choice.hex()}")
        logging.debug(f"Handshake with upstream proxy {upstream_host}:{upstream_port} successful.")

        # 5. Forward client's request to upstream proxy
        upstream_request = client_req_header + dst_addr_bytes + dst_port_bytes
        proxy_socket.sendall(upstream_request)

        # 6. Relay reply from upstream proxy back to client
        # This logic is complex, so we read and forward it chunk by chunk to be safe.
        proxy_reply_header = proxy_socket.recv(4)
        if not proxy_reply_header or len(proxy_reply_header) < 4:
            raise ConnectionAbortedError("Upstream proxy closed connection before sending reply header.")
        
        client_socket.sendall(proxy_reply_header)
        reply_atyp = proxy_reply_header[3]
        
        bnd_len = 0
        if reply_atyp == 0x01: bnd_len = 4 # IPv4
        elif reply_atyp == 0x04: bnd_len = 16 # IPv6
        elif reply_atyp == 0x03: # Domain
            len_byte = proxy_socket.recv(1)
            client_socket.sendall(len_byte)
            bnd_len = len_byte[0]
        
        # Forward BND.ADDR and BND.PORT
        bnd_full = proxy_socket.recv(bnd_len + 2) # Address + 2-byte port
        client_socket.sendall(bnd_full)

        # 7. Relay data
        if proxy_reply_header[1] == 0x00: # Success
            logging.info(f"SOCKS connection established for {client_address} via {upstream_host}:{upstream_port}. Relaying data.")
            relay_data(client_socket, proxy_socket, client_address)
        else:
            logging.error(f"Upstream SOCKS proxy {upstream_host}:{upstream_port} failed request for {client_address}. REP: {proxy_reply_header[1]}.")
            # Error reply has been forwarded, just close.

    except (socket.error, socks.SOCKS5Error, BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
        logging.error(f"Error during SOCKS relay for {client_address}: {e}")
        # Try to send a general failure to client if the connection is still open
        if not client_socket._closed:
            try:
                client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            except socket.error:
                pass # Ignore if we can't even send the error
    finally:
        if client_socket and not client_socket._closed:
            client_socket.close()
        if proxy_socket and not proxy_socket._closed:
            proxy_socket.close()
        logging.info(f"Closed connection for {client_address}")

def relay_data(sock1, sock2, client_address):
    """Relays data between two sockets until one closes or an error occurs."""
    done_event = threading.Event()

    def _forward(s_from, s_to, direction):
        try:
            while not done_event.is_set():
                data = s_from.recv(4096)
                if not data: # Connection closed by peer
                    break
                s_to.sendall(data)
        except (socket.error, BrokenPipeError, ConnectionResetError) as e:
            if not done_event.is_set(): # Avoid logging if already shutting down
                 logging.debug(f"Socket error during relay ({direction}) for {client_address}: {e}")
        finally:
            done_event.set() # Signal the other forwarder to stop

    # Start forwarding in both directions
    t1 = threading.Thread(target=_forward, args=(sock1, sock2, "client_to_proxy"))
    t2 = threading.Thread(target=_forward, args=(sock2, sock1, "proxy_to_client"))
    t1.daemon = True # Ensure threads don't block program exit
    t2.daemon = True
    t1.start()
    t2.start()

    # Wait for either direction to complete (or error out)
    done_event.wait()

    # Attempt to close sockets if they aren't already
    for s in [sock1, sock2]:
        if not s._closed:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass # Ignore errors if already closed or problematic
            finally:
                s.close()
    logging.debug(f"Relay finished for {client_address}")


def start_server(listen_host, listen_port):
    """Starts the SOCKS5 proxy server and listens for connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((listen_host, listen_port))
        server_socket.listen(128) # Max backlog connections
        logging.info(f"Custom LB SOCKS5 Proxy listening on {listen_host}:{listen_port}")
    except socket.error as e:
        logging.error(f"Failed to bind or listen on {listen_host}:{listen_port}: {e}")
        return

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client_connection, args=(client_socket, client_address))
            client_thread.daemon = True # Don't let threads block exit
            client_thread.start()
        except KeyboardInterrupt:
            logging.info("Server shutting down on KeyboardInterrupt.")
            break
        except socket.error as e:
            logging.error(f"Socket error during accept: {e}")
            # Potentially add a small delay here if accept is failing rapidly
            time.sleep(0.1)

    server_socket.close()
    logging.info("Server stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom SOCKS5 Load Balancer for Tor.")
    parser.add_argument("--listen-host", type=str, required=True, help="Host to listen on (e.g., 127.0.0.1)")
    parser.add_argument("--listen-port", type=int, required=True, help="Port to listen on (e.g., 16378)")
    parser.add_argument("--tor-proxies", type=str, required=True,
                        help="Comma-separated list of Tor SOCKS5 proxies (e.g., 127.0.0.1:9050,127.0.0.1:9051)")

    args = parser.parse_args()

    # Parse Tor proxies
    try:
        for proxy_str in args.tor_proxies.split(','):
            if not proxy_str.strip(): continue
            host, port_str = proxy_str.strip().split(':')
            _target_proxies.append((host, int(port_str)))
        if not _target_proxies:
            logging.error("No Tor proxies provided or failed to parse. Exiting.")
            exit(1)
        logging.info(f"Target Tor SOCKS proxies: {_target_proxies}")
    except ValueError as e:
        logging.error(f"Invalid format for --tor-proxies: {args.tor_proxies}. Error: {e}. Exiting.")
        exit(1)

    # Start the monitoring thread
    monitor_thread = threading.Thread(target=monitor_proxies)
    monitor_thread.daemon = True # So it exits when the main thread exits
    monitor_thread.start()

    # Start the server
    try:
        start_server(args.listen_host, args.listen_port)
    except Exception as e:
        logging.critical(f"Unhandled exception in server: {e}", exc_info=True)
    finally:
        logging.info("Custom LB shutting down.")

# Ensure this file is executable: chmod +x lib/custom_lb.py
# Example usage:
# python3 lib/custom_lb.py --listen-host 127.0.0.1 --listen-port 16378 --tor-proxies 127.0.0.1:9050,127.0.0.1:9051,127.0.0.1:9052
#
# To test with curl:
# curl --socks5-hostname 127.0.0.1:16378 http://httpbin.org/ip
# (Note: --socks5-hostname is important for curl to send hostname, if your SOCKS proxy expects it for name resolution)
# Or simply:
# curl --proxy socks5h://127.0.0.1:16378 http://httpbin.org/ip
# (socks5h does DNS resolution through the proxy)

# Dependencies:
# pip install requests pysocks
# or for system:
# sudo apt-get install python3-requests python3-pysocks (Debian/Ubuntu)
# sudo yum install python3-requests python3-PySocks (Fedora/CentOS) - check exact package name for PySocks
#
# Notes on SOCKS5 implementation:
# - This is a basic SOCKS5 proxy implementation, focusing on the CONNECT command.
# - It only supports the "NO AUTHENTICATION REQUIRED" (0x00) method.
# - Error handling for SOCKS protocol steps is included.
# - The `socks.create_connection` from PySocks handles the client part of connecting to the upstream Tor SOCKS proxy.
# - The server part (accepting SOCKS connections from applications) is implemented manually.
# - `socks5h` in requests/curl means DNS resolution happens via the proxy. This is generally what you want with Tor.
#
# Improvements for production:
# - More robust error handling and recovery in monitoring and client handling.
# - Potentially use asyncio for higher concurrency if many connections are expected, though threading is fine for moderate loads.
# - More sophisticated health checks (e.g., multiple URLs, retry mechanisms).
# - Configuration via a file instead of just command-line args for more complex setups.
# - Signal handling for graceful shutdown (SIGINT is handled by default Python, SIGTERM might need explicit handling).
# - Better logging control (e.g., log levels from args).
# - PID file creation/management if run as a daemon.

# For the specific use case of multitor:
# - The bash scripts will call this Python script.
# - The list of Tor SOCKS ports will be dynamically generated by the bash script and passed to --tor-proxies.
# - stdout/stderr from this script should be captured by multitor's logging.
# - The listen-host and listen-port will be fixed (e.g., 127.0.0.1 and a new port like 16378).
# - The health check URL is hardcoded to gstatic's 204, as per requirements.
# - The 60-second monitoring interval is also per requirements.
# - The `daemon = True` for threads is important so they don't prevent the script from exiting if the main thread is killed by multitor.
# - The script is designed to be killed by multitor (e.g., SIGTERM or SIGKILL) when multitor shuts down.
#   A more graceful shutdown could be implemented if multitor sends SIGTERM and this script catches it.
#   However, for now, daemon threads + process kill is acceptable for this integration.
# - The `socks.SOCKS5` constant is from the `socks` module (PySocks).
# - The `socks.create_connection` is a helper from PySocks that simplifies making an outgoing SOCKS connection.
#   It handles the SOCKS handshake with the *upstream* Tor proxy.
# - The code *before* `proxy_socket.sendall(client_req_header + dst_addr_bytes + dst_port_bytes)` is this script acting as a *SOCKS server* to the *client application*.
# - The code *after* that, involving `proxy_socket.recv` and `proxy_socket.sendall`, is this script acting as a *SOCKS client* to the *upstream Tor proxy*.
# - The use of `socks5h://` for `requests` is important to ensure DNS resolution also goes through Tor.

# Final check on proxy types for requests:
# socks5://<user>:<pass>@<host>:<port> - SOCKS5 proxy
# socks5h://<user>:<pass>@<host>:<port> - SOCKS5 proxy, DNS resolved through proxy
# For Tor, we want DNS resolution through the proxy, so 'socks5h' is correct.
# Since Tor by default doesn't use user/pass, it simplifies to 'socks5h://{proxy_host}:{proxy_port}'

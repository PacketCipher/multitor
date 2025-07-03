import socket
import threading
import time
import requests
import logging
import argparse
import socks # PySocks, used for potential error types
from concurrent.futures import ThreadPoolExecutor
import stem
import stem.control
from stem import CircStatus
from stem.control import EventType

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')

# --- Shared state and trigger mechanism ---
TOP_N_PROXIES = None # The 'N' in "Top-N" round-robin
CHECK_MODE = None
_shared_state_lock = threading.Lock()
# Master list of ALL healthy proxies, sorted by performance (best first).
_healthy_sorted_proxies = []
# The derived list of the top N proxies used for round-robin.
_top_proxies = []
# Index for round-robin selection. Must be accessed under the lock.
_round_robin_index = 0
# Original list of proxies from arguments remains the same.
_target_proxies = []
# This event is set if the number of healthy proxies drops below N.
_full_recheck_needed_event = threading.Event()

# --- CONSTANTS for health checks ---
PING_MONITORING_INTERVAL = 1 * 60 * 60
DOWNLOAD_MONITORING_INTERVAL = 4 * 60 * 60

def check_proxy_ping_health(proxy_host, proxy_port, num_rounds=10, requests_per_round=10):
    """Measures proxy performance by running multiple rounds of parallel requests."""
    TEST_URL = "http://connectivitycheck.gstatic.com/generate_204"
    HEALTH_CHECK_TIMEOUT = 5 # seconds

    total_requests = num_rounds * requests_per_round
    logging.info(
        f"--- Starting Performance Test for {proxy_host}:{proxy_port} ---\n"
        f"Configuration: {num_rounds} rounds, {requests_per_round} parallel requests per round."
    )
    session = requests.Session()
    session.proxies = {
        'http': f'socks5h://{proxy_host}:{proxy_port}',
        'https': f'socks5h://{proxy_host}:{proxy_port}'
    }
    def _make_single_request():
        try:
            start_time = time.time()
            response = session.get(TEST_URL, timeout=HEALTH_CHECK_TIMEOUT)
            end_time = time.time()
            if response.status_code == 204:
                return end_time - start_time
            return HEALTH_CHECK_TIMEOUT
        except requests.exceptions.RequestException:
            return HEALTH_CHECK_TIMEOUT

    all_latencies = []
    with ThreadPoolExecutor(max_workers=requests_per_round * num_rounds) as executor:
        futures = [executor.submit(_make_single_request) for _ in range(total_requests)]
        all_latencies = [f.result() for f in futures]

    overall_avg_latency = sum(all_latencies) / len(all_latencies) if all_latencies else HEALTH_CHECK_TIMEOUT
    success_count = sum(1 for lat in all_latencies if lat < HEALTH_CHECK_TIMEOUT)
    success_rate = (success_count / total_requests) * 100

    logging.info(f"--- Performance Test Summary for {proxy_host}:{proxy_port} ---")
    logging.info(f"Successful requests: {success_count}/{total_requests} ({success_rate:.1f}%)")
    logging.info(f"Overall avg latency: {overall_avg_latency:.4f}s (includes penalties)")
    logging.info("---------------------------------")
    return overall_avg_latency

def check_proxy_download_health(proxy_host, proxy_port, num_downloads=1):
    """Measures the average time it takes to download a test file via a proxy."""
    DOWNLOAD_URL = "https://proof.ovh.net/files/1Mb.dat"
    DOWNLOAD_TIMEOUT = 30 # in seconds

    logging.info(f"--- Starting Download Time Test for {proxy_host}:{proxy_port} ---")
    session = requests.Session()
    session.proxies = {
        'http': f'socks5h://{proxy_host}:{proxy_port}',
        'https': f'socks5h://{proxy_host}:{proxy_port}'
    }
    all_durations = []
    for i in range(num_downloads):
        try:
            start_time = time.time()
            response = session.get(DOWNLOAD_URL, timeout=DOWNLOAD_TIMEOUT)
            response.raise_for_status()
            duration = time.time() - start_time
            all_durations.append(duration)
        except requests.exceptions.RequestException:
            all_durations.append(DOWNLOAD_TIMEOUT)
    overall_avg_time = sum(all_durations) / len(all_durations) if all_durations else DOWNLOAD_TIMEOUT
    logging.info(f"--- Download Test Summary for {proxy_host}:{proxy_port}: Avg time {overall_avg_time:.2f}s ---")
    return overall_avg_time

def get_control_port(socks_port):
    """Derives the Tor control port from a SOCKS port."""
    return int(socks_port) + 900

def create_circuit_event_handler(proxy_tuple):
    """
    Factory for an event handler that removes a failing proxy from the healthy list
    and triggers a full re-check if the number of healthy proxies drops below N.
    """
    host, port = proxy_tuple
    def handler(event):
        if event.status == CircStatus.CLOSED:
            with _shared_state_lock:
                if proxy_tuple in _healthy_sorted_proxies:
                    logging.warning(
                        f"Tor circuit event ({event.status}) for proxy {host}:{port}. "
                        f"Reactively removing it from the healthy list."
                    )
                    _healthy_sorted_proxies.remove(proxy_tuple)

                    global _top_proxies, _round_robin_index
                    new_top_proxies = _healthy_sorted_proxies[:TOP_N_PROXIES]
                    if _top_proxies != new_top_proxies:
                        logging.info(f"Top-N list updated due to removal. New list: {new_top_proxies}")
                        _top_proxies = new_top_proxies
                        _round_robin_index = 0

                    logging.info(f"Total healthy proxies: {len(_healthy_sorted_proxies)}. Active top-N: {len(_top_proxies)}.")

                    if len(_healthy_sorted_proxies) < TOP_N_PROXIES:
                        logging.error(f"Healthy proxies ({len(_healthy_sorted_proxies)}) < N ({TOP_N_PROXIES}). "
                                      f"Triggering immediate full re-check.")
                        _full_recheck_needed_event.set()
    return handler

def _update_proxy_lists(health_data):
    """
    Takes health data, sorts it, and updates both the master healthy list
    and the derived top-N list for round-robin.
    """
    global _healthy_sorted_proxies, _top_proxies, _round_robin_index
    sorted_proxies_with_metric = sorted(health_data.items(), key=lambda item: item[1])
    new_healthy_sorted = [proxy for proxy, metric in sorted_proxies_with_metric]

    with _shared_state_lock:
        _healthy_sorted_proxies = new_healthy_sorted
        new_top_proxies = _healthy_sorted_proxies[:TOP_N_PROXIES]

        if not new_top_proxies:
            logging.warning("No healthy proxies found after full check. Active proxy list is empty.")
        elif _top_proxies != new_top_proxies:
            logging.info(f"Updating proxy lists. New top-N list: {new_top_proxies}")
            _round_robin_index = 0
        else:
            logging.info(f"Top-N proxies list remains unchanged: {new_top_proxies}")

        _top_proxies = new_top_proxies
        logging.info(f"Full list of healthy proxies updated ({len(_healthy_sorted_proxies)} total): {_healthy_sorted_proxies}")

def monitor_proxies(control_password):
    """
    Monitors proxy health. Runs a full check periodically or if healthy proxies < N.
    """
    if CHECK_MODE == 0:
        check_func = check_proxy_ping_health
        MONITORING_INTERVAL = PING_MONITORING_INTERVAL
    elif CHECK_MODE == 1:
        check_func = check_proxy_download_health
        MONITORING_INTERVAL = DOWNLOAD_MONITORING_INTERVAL
    else:
        logging.error(f"Invalid CHECK_MODE '{CHECK_MODE}'. Monitor thread exiting.")
        return

    def _run_full_check_cycle():
        health_data = {}
        if not _target_proxies:
            logging.warning("Monitor: No target proxies configured.")
            return

        logging.info(f"Starting full health check on all target proxies: {_target_proxies}")
        for host, port in _target_proxies:
            try:
                performance_metric = check_func(host, port)
                health_data[(host, port)] = performance_metric
            except Exception as e:
                logging.error(f"Error during health check for proxy {host}:{port}: {e}", exc_info=False)
        _update_proxy_lists(health_data)
        logging.info("--- Full health check cycle complete. ---")

    logging.info("--- Running initial health check on all target proxies... ---")
    _run_full_check_cycle()

    controllers = []
    for host, port in _target_proxies:
        try:
            controller = stem.control.Controller.from_port(address=host, port=get_control_port(port))
            controller.authenticate(password=control_password)
            handler = create_circuit_event_handler((host, port))
            controller.add_event_listener(handler, EventType.CIRC)
            logging.info(f"Successfully connected to Tor control port for {host}:{port}.")
            controllers.append(controller)
        except Exception as e:
            logging.warning(f"Failed to connect/auth with Tor control for {host}:{port}: {e}.")

    while True:
        event_was_set = _full_recheck_needed_event.wait(timeout=MONITORING_INTERVAL)
        if event_was_set:
            logging.info("--- Event triggered (healthy proxies < N). Starting full re-check... ---")
            _full_recheck_needed_event.clear()
        else:
            logging.info(f"--- Periodic interval ({MONITORING_INTERVAL}s) reached. Starting full re-check... ---")
        _run_full_check_cycle()

    for controller in controllers:
        try:
            controller.close()
        except Exception:
            pass

def select_proxy_round_robin():
    """Selects a proxy from the top N list using a round-robin strategy."""
    global _round_robin_index
    with _shared_state_lock:
        if not _top_proxies:
            return None

        selected_proxy = _top_proxies[_round_robin_index % len(_top_proxies)]
        _round_robin_index += 1
        return selected_proxy

def handle_client_connection(client_socket, client_address):
    """Handles a single client connection by forwarding it through a selected SOCKS5 proxy."""
    logging.info(f"Accepted connection from {client_address}")
    proxy_socket = None

    try:
        upstream_proxy = select_proxy_round_robin()
        if not upstream_proxy:
            logging.error(f"No healthy upstream SOCKS proxy for {client_address}. Closing connection.")
            client_socket.close()
            return

        upstream_host, upstream_port = upstream_proxy
        logging.info(f"Selected upstream SOCKS proxy {upstream_host}:{upstream_port} for {client_address}")

        # SOCKS5 handshake with client
        version_id_msg = client_socket.recv(2)
        if not version_id_msg or version_id_msg[0] != 0x05:
            client_socket.close()
            return
        nmethods = version_id_msg[1]
        client_methods = client_socket.recv(nmethods)
        if 0x00 not in client_methods:
            client_socket.sendall(b'\x05\xFF')
            client_socket.close()
            return
        client_socket.sendall(b'\x05\x00')

        # Get destination request from client
        client_req_header = client_socket.recv(4)
        if not client_req_header or client_req_header[0] != 0x05 or client_req_header[1] != 0x01:
            client_socket.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            client_socket.close()
            return
        req_atyp = client_req_header[3]
        if req_atyp == 0x01: # IPv4
            dst_addr_bytes = client_socket.recv(4)
        elif req_atyp == 0x03: # Domain name
            domain_len_byte = client_socket.recv(1)
            domain_len = domain_len_byte[0]
            dst_addr_bytes = domain_len_byte + client_socket.recv(domain_len)
        elif req_atyp == 0x04: # IPv6
            dst_addr_bytes = client_socket.recv(16)
        else:
            client_socket.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            client_socket.close()
            return
        dst_port_bytes = client_socket.recv(2)

        # Connect to upstream SOCKS proxy
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.settimeout(10)
        proxy_socket.connect((upstream_host, upstream_port))
        proxy_socket.sendall(b'\x05\x01\x00') # Handshake with upstream
        server_choice = proxy_socket.recv(2)
        if not server_choice or server_choice[0] != 0x05 or server_choice[1] != 0x00:
            raise socks.SOCKS5Error("Upstream proxy auth failed")

        # Forward client's original request to upstream
        upstream_request = client_req_header + dst_addr_bytes + dst_port_bytes
        proxy_socket.sendall(upstream_request)

        # Relay upstream proxy's response back to our client
        proxy_reply_header = proxy_socket.recv(4)
        if not proxy_reply_header:
             raise ConnectionAbortedError("Upstream proxy did not send reply header.")
        client_socket.sendall(proxy_reply_header)
        reply_atyp = proxy_reply_header[3]
        bnd_len = 0
        if reply_atyp == 0x01: bnd_len = 4 + 2 # IPv4 + port
        elif reply_atyp == 0x04: bnd_len = 16 + 2 # IPv6 + port
        elif reply_atyp == 0x03:
            len_byte = proxy_socket.recv(1)
            client_socket.sendall(len_byte)
            bnd_len = len_byte[0] + 2 # domain + port
        # Relay the rest of the bind address and port
        bnd_full = proxy_socket.recv(bnd_len)
        client_socket.sendall(bnd_full)

        # Relay data if connection was successful
        if proxy_reply_header[1] == 0x00:
            logging.info(f"SOCKS connection established for {client_address}. Relaying data.")
            relay_data(client_socket, proxy_socket, client_address)

    except (socket.error, socks.SOCKS5Error, BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
        logging.error(f"Error during SOCKS relay for {client_address}: {e}")
        if not client_socket._closed:
            try:
                client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            except socket.error:
                pass
    finally:
        if client_socket and not client_socket._closed:
            client_socket.close()
        if proxy_socket and not proxy_socket._closed:
            proxy_socket.close()
        logging.info(f"Closed connection for {client_address}")

def relay_data(sock1, sock2, client_address):
    """Relays data between two sockets until one closes or an error occurs."""
    done_event = threading.Event()
    def _forward(s_from, s_to):
        try:
            while not done_event.is_set():
                data = s_from.recv(4096)
                if not data:
                    break
                s_to.sendall(data)
        except (socket.error, BrokenPipeError, ConnectionResetError):
            pass
        finally:
            done_event.set()

    t1 = threading.Thread(target=_forward, args=(sock1, sock2))
    t2 = threading.Thread(target=_forward, args=(sock2, sock1))
    t1.daemon = True
    t2.daemon = True
    t1.start()
    t2.start()
    done_event.wait()
    for s in [sock1, sock2]:
        if not s._closed:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except socket.error:
                pass
            finally:
                s.close()

def start_server(listen_host, listen_port):
    """Starts the SOCKS5 proxy server and listens for connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((listen_host, listen_port))
        server_socket.listen(128)
        logging.info(f"Custom LB SOCKS5 Proxy listening on {listen_host}:{listen_port}")
        logging.info(f"Strategy: Round-robin on top {TOP_N_PROXIES} proxies.")
        logging.info("Full re-check triggered periodically or if healthy proxies < N.")
    except socket.error as e:
        logging.error(f"Failed to bind or listen on {listen_host}:{listen_port}: {e}")
        return

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client_connection, args=(client_socket, client_address), daemon=True)
            client_thread.start()
        except KeyboardInterrupt:
            logging.info("Server shutting down.")
            break
        except socket.error as e:
            logging.error(f"Socket error during accept: {e}")
    server_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom SOCKS5 Load Balancer for Tor with advanced health checks.")
    parser.add_argument("--listen-host", type=str, required=True, help="Host to listen on")
    parser.add_argument("--listen-port", type=int, required=True, help="Port to listen on")
    parser.add_argument("--tor-proxies", type=str, required=True, help="Comma-separated list of Tor SOCKS5 proxies")
    parser.add_argument("--top-n-proxies", type=int, required=True, help="Round-robin over the Top N fastest proxies.")
    parser.add_argument("--check-mode", type=int, required=True, choices=[0, 1], help="0 = Ping Check, 1 = Download Check")
    parser.add_argument("--tor-control-password", type=str, default="", help="Password for the Tor control ports. Default is empty for no auth or cookie auth.")

    args = parser.parse_args()

    try:
        proxies_list = []
        for proxy_str in args.tor_proxies.split(','):
            if not proxy_str.strip():
                continue
            host, port_str = proxy_str.strip().split(':')
            proxies_list.append((host, int(port_str)))
        _target_proxies = proxies_list
        if not _target_proxies:
            raise ValueError("No valid proxies were provided.")
        logging.info(f"Target Tor SOCKS proxies: {_target_proxies}")
    except ValueError as e:
        logging.error(f"Invalid format for --tor-proxies: {args.tor_proxies}. Error: {e}. Exiting.")
        exit(1)

    TOP_N_PROXIES = args.top_n_proxies
    if TOP_N_PROXIES > len(_target_proxies):
        logging.warning(f"--top-n-proxies ({TOP_N_PROXIES}) > total proxies ({len(_target_proxies)}). Using {len(_target_proxies)}.")
        TOP_N_PROXIES = len(_target_proxies)

    CHECK_MODE = args.check_mode

    logging.info("Waiting 10 minutes for Tor instances to initialize...")
    time.sleep(10 * 60)

    monitor_thread = threading.Thread(target=monitor_proxies, args=(args.tor_control_password,), daemon=True)
    monitor_thread.start()

    logging.info("Waiting up to 5 minutes for the initial health check to complete...")
    time.sleep(5 * 60)
    with _shared_state_lock:
        if not _top_proxies:
            logging.warning("Initial health check found no working proxies. Starting server anyway.")

    try:
        start_server(args.listen_host, args.listen_port)
    except Exception as e:
        logging.critical(f"Unhandled exception in server: {e}", exc_info=True)
    finally:
        logging.info("Custom LB shutting down.")
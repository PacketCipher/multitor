import socket
import threading
import time
import requests
import logging
import argparse
import socks
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import stem
import stem.control
import stem.response
from stem import CircStatus, GuardStatus, StatusType
from stem.control import EventType
from stem import Signal
import statistics

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')

# --- Shared state and trigger mechanism ---
TOP_N_PROXIES = None
CHECK_MODE = None
bootstrapped_controllers = None
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
# Packet stats
packet_stats_per_proxy = {}
packet_stats_n_packets_threshold = 100
packet_stats_packet_loss_threshold = 0.5

# --- CONSTANTS for health checks ---
PING_MONITORING_INTERVAL = 1 * 60 * 60
DOWNLOAD_MONITORING_INTERVAL = 12 * 60 * 60

def check_proxy_ping_health(proxy_host, proxy_port, num_rounds=10, requests_per_round=10):
    """Measures proxy performance by running multiple rounds of parallel requests."""
    TEST_URL = "http://connectivitycheck.gstatic.com/generate_204"
    HEALTH_CHECK_TIMEOUT = 5 # seconds
    HEALTH_CHECK_TIMEOUT_PENALTY = 99999

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
            return HEALTH_CHECK_TIMEOUT_PENALTY
        except requests.exceptions.RequestException:
            return HEALTH_CHECK_TIMEOUT_PENALTY

    all_latencies = []
    with ThreadPoolExecutor(max_workers=requests_per_round * num_rounds) as executor:
        futures = [executor.submit(_make_single_request) for _ in range(total_requests)]
        all_latencies = [f.result() for f in futures]

    # overall_avg_latency = sum(all_latencies) / len(all_latencies) if all_latencies else HEALTH_CHECK_TIMEOUT_PENALTY
    overall_avg_latency = statistics.median(all_latencies)
    success_count = sum(1 for lat in all_latencies if lat < HEALTH_CHECK_TIMEOUT_PENALTY)
    success_rate = (success_count / total_requests) * 100

    logging.info(f"--- Performance Test Summary for {proxy_host}:{proxy_port} ---")
    logging.info(f"Successful requests: {success_count}/{total_requests} ({success_rate:.1f}%)")
    logging.info(f"Overall avg latency: {overall_avg_latency:.4f}s (includes penalties)")
    logging.info("---------------------------------")
    return overall_avg_latency if overall_avg_latency != HEALTH_CHECK_TIMEOUT_PENALTY else None

def check_proxy_download_health(proxy_host, proxy_port, num_downloads=1):
    """Measures the average time it takes to download a test file via a proxy."""
    DOWNLOAD_URL = "https://proof.ovh.net/files/1Mb.dat"
    DOWNLOAD_TIMEOUT = 30 # in seconds
    DOWNLOAD_TIMEOUT_PENALTY = 99999

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
            all_durations.append(DOWNLOAD_TIMEOUT_PENALTY)
    # overall_avg_time = sum(all_durations) / len(all_durations) if all_durations else DOWNLOAD_TIMEOUT_PENALTY
    overall_avg_time = statistics.median(all_durations)

    logging.info(f"--- Download Test Summary for {proxy_host}:{proxy_port}: Avg time {overall_avg_time:.2f}s ---")
    return overall_avg_time if overall_avg_time != DOWNLOAD_TIMEOUT_PENALTY else None

def get_control_port(socks_port):
    """Derives the Tor control port from a SOCKS port."""
    return int(socks_port) + 900

def trigger_reactive_removal(proxy_tuple, reason):
    """
    Central function to handle a reactive failure.
    It removes the failed proxy and only triggers a full re-check if the
    number of healthy proxies falls below the critical threshold.
    """
    with _shared_state_lock:
        if proxy_tuple in _healthy_sorted_proxies:
            logging.warning(f"REACTIVE TRIGGER ({reason}) for proxy {proxy_tuple}. Removing from active pool.")
            _healthy_sorted_proxies.remove(proxy_tuple)

            # Rebuild the top-N list from the now smaller healthy list
            global _top_proxies, _round_robin_index
            new_top_proxies = _healthy_sorted_proxies[:TOP_N_PROXIES]
            if _top_proxies != new_top_proxies:
                _top_proxies = new_top_proxies
                _round_robin_index = 0
                logging.info(f"Top-N list updated due to removal. New list: {new_top_proxies}")

            # Conditionally trigger a full re-check
            if len(_healthy_sorted_proxies) <= TOP_N_PROXIES:
                logging.error(f"Healthy proxies ({len(_healthy_sorted_proxies)}) dropped below threshold ({TOP_N_PROXIES}). Triggering emergency re-check.")
                _full_recheck_needed_event.set()
            
            controller = bootstrapped_controllers[proxy_tuple]
            controller.signal(Signal.HUP)
            logging.info(f"Tor Reloaded For {proxy_tuple}")
        else:
            logging.info(f"Reactive trigger for {proxy_tuple} ignored as it was already removed.")

def _update_proxy_lists(health_data):
    """
    Takes health data from a full check, sorts it, and updates the global proxy lists.
    """
    global _healthy_sorted_proxies, _top_proxies, _round_robin_index
    # Lower score is better (faster)
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

def _run_full_check_cycle():
    """Performs a health check on all target proxies and updates the global lists."""
    if CHECK_MODE == 0:
        check_func = check_proxy_ping_health
    elif CHECK_MODE == 1:
        check_func = check_proxy_download_health
    else:
        logging.error(f"Invalid CHECK_MODE '{CHECK_MODE}'. Cannot run check cycle.")
        return

    health_data = {}
    if not _target_proxies:
        logging.warning("Monitor: No target proxies configured.")
        return

    logging.info(f"Starting full health check audit on all target proxies: {_target_proxies}")
    for host, port in _target_proxies:
        try:
            performance_metric = check_func(host, port)
            if performance_metric is not None:
                health_data[(host, port)] = performance_metric
        except Exception as e:
            logging.error(f"Error during health check for proxy {host}:{port}: {e}", exc_info=False)
    _update_proxy_lists(health_data)
    logging.info("--- Full health check audit complete. ---")

# --- FIXED & CORRECT EVENT HANDLERS ---
def generic_guard_handler(proxy_tuple, event):
    """Handles GUARD events. This logic was correct."""
    if event.status in [GuardStatus.DOWN, GuardStatus.BAD]:
        logging.warning(f"Proxy {proxy_tuple} reported guard status: {event.status}. Triggering removal.")
        trigger_reactive_removal(proxy_tuple, f"GUARD {event.status}")

def generic_status_handler(proxy_tuple, event):
    """
    FIXED: Handles only STATUS_CLIENT events.
    Reacts directly to the event's content, avoiding a redundant getinfo call.
    """
    if event.action == "BOOTSTRAP":
        progress = int(event.arguments.get('PROGRESS', -1))
        tag = event.arguments.get('TAG', 'unknown')

        # Any bootstrap event that isn't the final "done" one implies it's not ready.
        if tag != 'done' or progress < 100:
            logging.info(f"Proxy {proxy_tuple} is (re)bootstrapping (progress {progress}%, tag: {tag}). Removing from active pool.")
            trigger_reactive_removal(proxy_tuple, f"BOOTSTRAP RESTART (progress {progress}%)")

def network_liveness_handler(proxy_tuple, event):
    """
    NEW: Handles only NETWORK_LIVENESS events. This is a separate event type
    from STATUS_CLIENT and needs its own handler.
    """
    # As per the stem unittests, the status is on the event object directly.
    if event.status == "DOWN":
        logging.warning(f"Proxy {proxy_tuple} reported network is DOWN. Triggering removal.")
        trigger_reactive_removal(proxy_tuple, "NETWORK LIVENESS DOWN")

def monitor_proxies():
    """
    Monitors proxy health. Reacts to GUARD, STATUS, and NETWORK_LIVENESS events,
    with a periodic check as a fallback.
    """
    global bootstrapped_controllers

    # Wait a minute for the Tor processes to start up before connecting.
    logging.info("Waiting 1 minute for Tor processes to start up...")
    time.sleep(60)

    # Wait for all Tor instances to bootstrap before starting.
    bootstrapped_controllers = wait_for_all_to_bootstrap(_target_proxies, args.tor_control_password)

    # Run the first health check to populate proxy lists before serving traffic.
    logging.info("All proxies bootstrapped. Performing initial health check...")
    _run_full_check_cycle()

    with _shared_state_lock:
        if not _top_proxies:
            logging.warning("Initial health check found no working proxies. Starting server anyway.")

    # Start Checking
    if CHECK_MODE == 0:
        MONITORING_INTERVAL = PING_MONITORING_INTERVAL
    elif CHECK_MODE == 1:
        MONITORING_INTERVAL = DOWNLOAD_MONITORING_INTERVAL
    else:
        logging.error(f"Invalid CHECK_MODE '{CHECK_MODE}'. Monitor thread exiting.")
        return

    # --- FIXED: Register all three distinct handlers for the correct event types ---
    for proxy_tuple, controller in bootstrapped_controllers.items():
        guard_handler = partial(generic_guard_handler, proxy_tuple)
        status_handler = partial(generic_status_handler, proxy_tuple)
        liveness_handler = partial(network_liveness_handler, proxy_tuple)

        try:
            controller.add_event_listener(guard_handler, EventType.GUARD)
            controller.add_event_listener(status_handler, EventType.STATUS_CLIENT)
            controller.add_event_listener(liveness_handler, EventType.NETWORK_LIVENESS)
            logging.info(f"Event listeners (GUARD, STATUS_CLIENT, NETWORK_LIVENESS) added for {proxy_tuple}")
        except Exception as e:
            logging.error(f"Failed to add event listeners for {proxy_tuple}: {e}")


    while True:
        event_was_set = _full_recheck_needed_event.wait(timeout=MONITORING_INTERVAL)
        if event_was_set:
            logging.info("--- Emergency threshold breached. Starting full re-check audit... ---")
            _full_recheck_needed_event.clear()
        else:
            logging.info(f"--- Periodic interval ({MONITORING_INTERVAL}s) reached. Starting fallback re-check audit... ---")
        _run_full_check_cycle()

    for controller in bootstrapped_controllers.values():
        try:
            controller.close()
        except Exception:
            pass


def select_proxy_round_robin():
    """Selects a proxy from the top N list using a round-robin strategy."""
    global _round_robin_index
    with _shared_state_lock:
        if not _top_proxies:
            return None # No healthy proxies available

        # Select proxy using round-robin logic
        selected_proxy = _top_proxies[_round_robin_index % len(_top_proxies)]
        _round_robin_index += 1

        # Prevent the index from growing indefinitely (optional, but good practice)
        if _round_robin_index > 1000000:
             _round_robin_index = 0

        return selected_proxy

def handle_client_connection(client_socket, client_address):
    """Handles a single client connection, forwarding it through a selected SOCKS5 proxy."""
    logging.info(f"Accepted connection from {client_address}")
    proxy_socket = None # Ensure proxy_socket is defined for the finally block

    try:
        # --- Use the round-robin selection function ---
        upstream_proxy = select_proxy_round_robin()
        if not upstream_proxy:
            logging.error(f"No healthy upstream SOCKS proxy available for {client_address}. Closing connection.")
            client_socket.close()
            return

        upstream_host, upstream_port = upstream_proxy
        logging.info(f"Selected upstream SOCKS proxy {upstream_host}:{upstream_port} for {client_address} via round-robin")

        # 2. SOCKS5 handshake with the client (Version identifier/method selection)
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
        if len(dst_addr_bytes) < 1 or len(dst_port_bytes) < 2:
             logging.warning(f"Client {client_address} sent incomplete address/port. Closing."); client_socket.close(); return

        # 4. Connect and handshake with the upstream SOCKS proxy
        logging.debug(f"Connecting to upstream proxy {upstream_host}:{upstream_port}")
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.settimeout(10)
        proxy_socket.connect((upstream_host, upstream_port))

        proxy_socket.sendall(b'\x05\x01\x00')
        server_choice = proxy_socket.recv(2)
        if len(server_choice) < 2 or server_choice[0] != 0x05 or server_choice[1] != 0x00:
            raise socks.SOCKS5Error(f"Upstream proxy {upstream_host}:{upstream_port} did not accept NO AUTH method. Reply: {server_choice.hex()}")
        logging.debug(f"Handshake with upstream proxy {upstream_host}:{upstream_port} successful.")

        # 5. Forward client's request to upstream proxy
        upstream_request = client_req_header + dst_addr_bytes + dst_port_bytes
        proxy_socket.sendall(upstream_request)

        # 6. Relay reply from upstream proxy back to client
        proxy_reply_header = proxy_socket.recv(4)
        if not proxy_reply_header or len(proxy_reply_header) < 4:
            raise ConnectionAbortedError("Upstream proxy closed connection before sending reply header.")

        client_socket.sendall(proxy_reply_header)
        reply_atyp = proxy_reply_header[3]

        bnd_len = 0
        if reply_atyp == 0x01: bnd_len = 4
        elif reply_atyp == 0x04: bnd_len = 16
        elif reply_atyp == 0x03:
            len_byte = proxy_socket.recv(1)
            client_socket.sendall(len_byte)
            bnd_len = len_byte[0]

        bnd_full = proxy_socket.recv(bnd_len + 2)
        client_socket.sendall(bnd_full)

        # 7. Relay data
        if proxy_reply_header[1] == 0x00: # Success
            logging.info(f"SOCKS connection established for {client_address} via {upstream_host}:{upstream_port}. Relaying data.")
            relay_data(client_socket, proxy_socket, client_address)
        else:
            logging.error(f"Upstream SOCKS proxy {upstream_host}:{upstream_port} failed request for {client_address}. REP: {proxy_reply_header[1]}.")
        
        if upstream_proxy:
            packet_stats_per_proxy[upstream_proxy]["Successful"] += 1

    except (socket.error, socks.SOCKS5Error, BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
        logging.error(f"Error during SOCKS relay for {client_address} via {upstream_proxy}: {e}")
        if upstream_proxy:
            packet_stats_per_proxy[upstream_proxy]["Failed"] += 1
            if (packet_stats_per_proxy[upstream_proxy]["Successful"] + packet_stats_per_proxy[upstream_proxy]["Failed"]) > packet_stats_n_packets_threshold:
                if packet_stats_per_proxy[upstream_proxy]["Failed"] / (packet_stats_per_proxy[upstream_proxy]["Successful"] + packet_stats_per_proxy[upstream_proxy]["Failed"]) > packet_stats_packet_loss_threshold:
                    trigger_reactive_removal(upstream_proxy, "SOCKS FAILURE")
                    packet_stats_per_proxy[upstream_proxy] = {"Successful": 0, "Failed": 0}
        
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

    def _forward(s_from, s_to, direction):
        try:
            while not done_event.is_set():
                data = s_from.recv(4096)
                if not data:
                    break
                s_to.sendall(data)
        except (socket.error, BrokenPipeError, ConnectionResetError) as e:
            if not done_event.is_set():
                 logging.debug(f"Socket error during relay ({direction}) for {client_address}: {e}")
        finally:
            done_event.set()

    t1 = threading.Thread(target=_forward, args=(sock1, sock2, "client_to_proxy"))
    t2 = threading.Thread(target=_forward, args=(sock2, sock1, "proxy_to_client"))
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
    logging.debug(f"Relay finished for {client_address}")

def start_server(listen_host, listen_port):
    """Starts the SOCKS5 proxy server and listens for connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((listen_host, listen_port))
        server_socket.listen(128)
        logging.info(f"Custom LB SOCKS5 Proxy listening on {listen_host}:{listen_port}")
        logging.info(f"Strategy: Round-robin top {TOP_N_PROXIES} proxies.")
    except socket.error as e:
        logging.error(f"Failed to bind or listen on {listen_host}:{listen_port}: {e}")
        return

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client_connection, args=(client_socket, client_address))
            client_thread.daemon = True
            client_thread.start()
        except KeyboardInterrupt:
            logging.info("Server shutting down on KeyboardInterrupt.")
            break
        except socket.error as e:
            logging.error(f"Socket error during accept: {e}")
            time.sleep(0.1)

    server_socket.close()
    logging.info("Server stopped.")

def is_bootstrapped(controller):
    """Checks if a Tor instance is fully bootstrapped by querying its control port."""
    try:
        response = controller.get_info("status/bootstrap-phase")
        # Use stem's response parser, similar to the example code.
        status = stem.response.ControlLine(response)
        while not status.is_empty():
            if status.is_next_mapping():
                key, value = status.pop_mapping(quoted=status.is_next_quoted())
                if key == "PROGRESS" and int(value) == 100:
                    return True
            else:
                # Discard other parts of the line we don't care about.
                status.pop(quoted=status.is_next_quoted())
    except (stem.InvalidResponse, ValueError) as e:
        logging.error(f"Error parsing bootstrap status for {controller.get_socket().getpeername()}: {e}")
    except stem.SocketError:
        # Re-raise socket errors to be handled by the caller.
        raise
    except Exception as e:
        logging.error(f"Unexpected error checking bootstrap status for {controller.get_socket().getpeername()}: {e}")
    return False

def wait_for_all_to_bootstrap(target_proxies, control_password):
    """
    Connects to all Tor controllers and waits until each one reports 100%
    bootstrap progress. Returns a dict of connected controllers.
    """
    global _top_proxies

    logging.info("Waiting for all Tor instances to initialize and bootstrap...")
    bootstrapped_controllers = {}
    proxies_to_check = set(target_proxies)

    start_time = time.time()
    
    while proxies_to_check:
        newly_bootstrapped_proxies = set()
        for proxy_tuple in proxies_to_check:
            host, port = proxy_tuple
            controller = bootstrapped_controllers.get(proxy_tuple)

            try:
                # If we don't have a controller, try to establish one.
                if not controller or not controller.is_alive():
                    controller = stem.control.Controller.from_port(address=host, port=get_control_port(port))
                    controller.authenticate(password=control_password)
                    bootstrapped_controllers[proxy_tuple] = controller
                    logging.info(f"Successfully connected to Tor control for {proxy_tuple}.")
                
                # Check the bootstrap status.
                if is_bootstrapped(controller):
                    newly_bootstrapped_proxies.add(proxy_tuple)

            except Exception as e:
                logging.warning(f"Cannot connect/check {proxy_tuple} for bootstrap status: {e}. Will retry.")
        
        if newly_bootstrapped_proxies:
            proxies_to_check -= newly_bootstrapped_proxies
            for p in newly_bootstrapped_proxies:
                logging.info(f"Proxy {p} is fully bootstrapped.")
                with _shared_state_lock:
                    _top_proxies.append(p)
        
        if proxies_to_check:
            logging.info(f"Still waiting for {len(proxies_to_check)} proxies to bootstrap: {list(proxies_to_check)}")
            time.sleep(10) # Wait before re-polling remaining proxies.
        
        current_time = time.time()
        if current_time - start_time > 30 * 60:
            for proxy_tuple in proxies_to_check:
                # Free-Up Memory & CPU #
                controller = bootstrapped_controllers[proxy_tuple]
                controller.signal(Signal.SHUTDOWN)
                target_proxies.remove(proxy_tuple)
            break

    logging.info("All target Tor instances are bootstrapped.")
    return bootstrapped_controllers

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
    
    for proxy in _target_proxies:
        packet_stats_per_proxy[proxy] = {"Successful": 0, "Failed": 0}

    TOP_N_PROXIES = args.top_n_proxies
    if TOP_N_PROXIES > len(_target_proxies):
        logging.warning(f"--top-n-proxies ({TOP_N_PROXIES}) > total proxies ({len(_target_proxies)}). Using {len(_target_proxies)}.")
        TOP_N_PROXIES = len(_target_proxies)

    CHECK_MODE = args.check_mode

    # Start the monitor thread with the already connected controllers.
    monitor_thread = threading.Thread(target=monitor_proxies, args=(), daemon=True)
    monitor_thread.start()

    try:
        start_server(args.listen_host, args.listen_port)
    except Exception as e:
        logging.critical(f"Unhandled exception in server: {e}", exc_info=True)
    finally:
        logging.info("Custom LB shutting down.")
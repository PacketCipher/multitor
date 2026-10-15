import socket
import select
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
from api_client import ApiClient

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')

# API client for managing Tor instances
api_client = ApiClient()

# --- Shared state and trigger mechanism ---
_shared_state_lock = threading.Lock()
TOP_N_PROXIES = None
CHECK_MODE = None
bootstrapped_controllers = None
entry_guards = {}
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
# Track proxies that have been reactively demoted since the last full check
_demoted_proxies = set()
# Packet stats
packet_stats_per_proxy = {}
packet_stats_n_packets_threshold = 100
packet_stats_packet_loss_threshold = 0.5
packet_stats_enable_demote = True

# Max concurrent client connections to prevent thread exhaustion
MAX_CONCURRENT_CLIENTS = 500
_client_semaphore = threading.BoundedSemaphore(MAX_CONCURRENT_CLIENTS)

# --- CONSTANTS for health checks ---
PING_MONITORING_INTERVAL = 1 * 60 * 60
DOWNLOAD_MONITORING_INTERVAL = 12 * 60 * 60

def _recv_exact(sock, num_bytes):
    """Helper to receive exactly num_bytes from a socket."""
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def check_proxy_ping(proxy_host, proxy_port, num_rounds=10, requests_per_round=10):
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
    with ThreadPoolExecutor(max_workers=requests_per_round) as executor:
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
    overall_avg_latency = overall_avg_latency if overall_avg_latency != HEALTH_CHECK_TIMEOUT_PENALTY else None
    return overall_avg_latency, success_rate

class TotalTimeout(Exception):
    """Custom exception for total download timeout."""
    pass

def check_proxy_download_full(proxy_host, proxy_port, num_downloads=1, total_timeout=200):
    """
    Measures the median time it takes to download a test file via a proxy,
    enforcing a total time limit for the download.
    """
    DOWNLOAD_URL = "https://proof.ovh.net/files/10Mb.dat"
    # A penalty value significantly higher than any possible timeout
    DOWNLOAD_TIMEOUT_PENALTY = 99999
    # A reasonable connect/read timeout for establishing the connection and getting the first byte
    # This prevents the initial request from hanging indefinitely.
    INITIAL_REQUEST_TIMEOUT = (15, 30) # (connect_timeout, read_timeout)

    logging.info(f"--- Starting Download Time Test for {proxy_host}:{proxy_port} (Total Timeout: {total_timeout}s) ---")
    session = requests.Session()
    session.proxies = {
        'http': f'socks5h://{proxy_host}:{proxy_port}',
        'httpss': f'socks5h://{proxy_host}:{proxy_port}'
    }
    all_durations = []
    
    for i in range(num_downloads):
        start_time = time.time()
        try:
            # Use stream=True to avoid downloading the entire content at once.
            # This lets us control the download process.
            with session.get(DOWNLOAD_URL, stream=True, timeout=INITIAL_REQUEST_TIMEOUT) as response:
                response.raise_for_status()
                # We will write to a null-like object to consume the download content
                # without saving it to memory or disk.
                # In Python 3, io.BytesIO() is a good in-memory buffer.
                # For very large files, you might use open(os.devnull, 'wb')
                from io import BytesIO
                downloaded_content = BytesIO()
                for chunk in response.iter_content(chunk_size=8192):
                    # Check the total elapsed time on each chunk
                    if time.time() - start_time > total_timeout:
                        raise TotalTimeout(f"Download exceeded total timeout of {total_timeout} seconds.")  
                    downloaded_content.write(chunk)
            # If the loop completes without raising TotalTimeout, the download was successful and within the time limit.
            duration = time.time() - start_time
            all_durations.append(duration)
            logging.info(f"Download {i+1}/{num_downloads} success in {duration:.2f}s")
        except (requests.exceptions.RequestException, TotalTimeout) as e:
            # Catch connection errors, bad status codes, AND our custom total timeout.
            logging.warning(f"Download {i+1}/{num_downloads} failed: {e}")
            all_durations.append(DOWNLOAD_TIMEOUT_PENALTY)
            
    overall_median_time = statistics.median(all_durations) if all_durations else DOWNLOAD_TIMEOUT_PENALTY
    success_count = sum(1 for lat in all_durations if lat < DOWNLOAD_TIMEOUT_PENALTY)
    success_rate = (success_count / num_downloads) * 100

    logging.info(f"--- Download Test Summary for {proxy_host}:{proxy_port}: Median time {overall_median_time:.2f}s ---")
    overall_median_time = overall_median_time if overall_median_time < DOWNLOAD_TIMEOUT_PENALTY else None
    return overall_median_time, success_rate

def check_proxy_download_fixed(proxy_host, proxy_port, num_tests=1, test_duration=10):
    """
    Measures the median download speed (bytes/sec) through a proxy over a fixed time period.

    Args:
        proxy_host (str): The hostname or IP address of the proxy server.
        proxy_port (int): The port number of the proxy server.
        num_tests (int): The number of times to run the test to calculate a median.
        test_duration (int): The duration in seconds for each download test.

    Returns:
        tuple: A tuple containing:
            - median_speed_bps (float): The median download speed in bytes per second. 
                                        Returns 0.0 if all tests fail.
            - success_rate (float): The percentage of successful test runs.
    """
    # Use a larger file to ensure the download doesn't finish before the test duration
    # for most internet speeds.
    DOWNLOAD_URL = "https://proof.ovh.net/files/100Mb.dat"
    
    # A reasonable connect/read timeout for establishing the connection and getting the first byte.
    # This prevents the initial request from hanging indefinitely.
    INITIAL_REQUEST_TIMEOUT = (15, 30) # (connect_timeout, read_timeout)

    logging.info(f"--- Starting Download Speed Test for {proxy_host}:{proxy_port} ({num_tests} tests, {test_duration}s each) ---")
    
    session = requests.Session()
    session.proxies = {
        'http': f'socks5h://{proxy_host}:{proxy_port}',
        'https': f'socks5h://{proxy_host}:{proxy_port}'
    }
    
    all_speeds = []

    for i in range(num_tests):
        total_bytes_downloaded = 0
        start_time = time.time()
        
        try:
            # Use stream=True to control the download process chunk by chunk.
            with session.get(DOWNLOAD_URL, stream=True, timeout=INITIAL_REQUEST_TIMEOUT) as response:
                response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
                
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        # The download finished before the timer ran out
                        break
                        
                    total_bytes_downloaded += len(chunk)
                    
                    # Check if the test duration has been reached
                    if time.time() - start_time >= test_duration:
                        break
            
            # The download loop finished (either by timeout or completion)
            actual_duration = time.time() - start_time
            
            # Calculate speed in bytes per second. Avoid division by zero.
            speed_bps = (total_bytes_downloaded / actual_duration) if actual_duration > 0 else 0
            all_speeds.append(speed_bps)

            # Log results in human-readable format (MB and MB/s)
            downloaded_mb = total_bytes_downloaded / (1024 * 1024)
            speed_mbps = speed_bps / (1024 * 1024)
            logging.info(f"Test {i+1}/{num_tests} success: Downloaded {downloaded_mb:.2f} MB in {actual_duration:.2f}s (Speed: {speed_mbps:.2f} MB/s)")

        except requests.exceptions.RequestException as e:
            # Catch connection errors, timeouts, etc.
            logging.warning(f"Test {i+1}/{num_tests} failed: {e}")
            # A failed test has a speed of 0 bytes/sec
            all_speeds.append(0.0)
            
    # --- Final calculations ---
    median_speed_bps = statistics.median(all_speeds) if all_speeds else 0.0
    
    # A test is considered successful if its speed was greater than 0
    success_count = sum(1 for speed in all_speeds if speed > 0)
    success_rate = (success_count / num_tests) * 100 if num_tests > 0 else 0

    median_speed_mbps = median_speed_bps / (1024 * 1024)
    logging.info(f"--- Speed Test Summary for {proxy_host}:{proxy_port}: Median Speed {median_speed_mbps:.2f} MB/s | Success Rate: {success_rate:.1f}% ---")
    
    if median_speed_bps <= 0:
        return None, 0.0

    median_speed_bps = 1 / median_speed_bps # Inverse It For Ascending Sort
    return median_speed_bps, success_rate

def get_control_port(socks_port):
    """Derives the Tor control port from a SOCKS port."""
    return int(socks_port) + 900

def trigger_reactive_removal(proxy_tuple, reason):
    """
    Central function to handle a reactive failure.
    Instead of permanently removing the failed proxy, it moves it to the end
    of the list and updates the top-N proxies.
    """
    global _demoted_proxies
    controller_to_reload = None

    with _shared_state_lock:
        if proxy_tuple in _healthy_sorted_proxies:
            logging.warning(f"REACTIVE TRIGGER ({reason}) for proxy {proxy_tuple}. Moving to end of active pool.")
            # Move to end of the list instead of removing
            _healthy_sorted_proxies.remove(proxy_tuple)
            _healthy_sorted_proxies.append(proxy_tuple)
            _demoted_proxies.add(proxy_tuple)

            # Rebuild the top-N list from the rearranged healthy list
            global _top_proxies, _round_robin_index
            new_top_proxies = _healthy_sorted_proxies[:TOP_N_PROXIES]
            if _top_proxies != new_top_proxies:
                _top_proxies = new_top_proxies
                _round_robin_index = 0
                logging.info(f"Top-N list updated due to demotion. New list: {new_top_proxies}")

            # Conditionally trigger a full re-check if available undemoted healthy proxies fall below TOP_N
            available_healthy = len(_healthy_sorted_proxies) - len(_demoted_proxies)
            if available_healthy < TOP_N_PROXIES:
                logging.error(f"Healthy un-demoted proxies ({available_healthy}) dropped below threshold ({TOP_N_PROXIES}). Triggering emergency re-check.")
                _demoted_proxies.clear()
                _full_recheck_needed_event.set()

            # Reset packet statistics for this proxy so it can be re-evaluated later
            if proxy_tuple in packet_stats_per_proxy:
                packet_stats_per_proxy[proxy_tuple] = {"Successful": 0, "Failed": 0}

            if bootstrapped_controllers and proxy_tuple in bootstrapped_controllers:
                controller_to_reload = bootstrapped_controllers[proxy_tuple]
        else:
            logging.info(f"Reactive trigger for {proxy_tuple} ignored as it was already removed.")

    # Execute Tor reload OUTSIDE the lock in a daemon thread so an unresponsive controller doesn't lock up all connections
    if controller_to_reload:
        def _async_hup(ctrl, pt):
            try:
                ctrl.signal(Signal.HUP)
                logging.info(f"Tor Reloaded For {pt}")
            except Exception as ex:
                logging.warning(f"Failed to reload Tor for {pt}: {ex}")
        threading.Thread(target=_async_hup, args=(controller_to_reload, proxy_tuple), daemon=True).start()

def _record_proxy_result(proxy_tuple, success, reason="SOCKS FAILURE"):
    """Records packet stats and reactively triggers demotion if error rate is too high."""
    if not proxy_tuple:
        return
    should_demote = False
    with _shared_state_lock:
        if proxy_tuple not in packet_stats_per_proxy:
            packet_stats_per_proxy[proxy_tuple] = {"Successful": 0, "Failed": 0}
        if success:
            packet_stats_per_proxy[proxy_tuple]["Successful"] += 1
        else:
            packet_stats_per_proxy[proxy_tuple]["Failed"] += 1
            total = packet_stats_per_proxy[proxy_tuple]["Successful"] + packet_stats_per_proxy[proxy_tuple]["Failed"]
            if total > packet_stats_n_packets_threshold:
                if packet_stats_per_proxy[proxy_tuple]["Failed"] / total > packet_stats_packet_loss_threshold:
                    should_demote = True

    if should_demote and packet_stats_enable_demote:
        trigger_reactive_removal(proxy_tuple, reason)

def _update_proxy_lists(health_data):
    """
    Takes health data from a full check, sorts it, and updates the global proxy lists.
    """
    global _healthy_sorted_proxies, _top_proxies, _round_robin_index, _demoted_proxies
    # Lower score is better (faster). Failed proxies with float('inf') sort to the end.
    sorted_proxies_with_metric = sorted(health_data.items(), key=lambda item: item[1])
    new_healthy_sorted = [proxy for proxy, metric in sorted_proxies_with_metric]

    with _shared_state_lock:
        _demoted_proxies.clear() # Reset demoted tracker on full check cycle update
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

    # Pause Tor instances that are not in the top proxies list
    # (Kept active across all healthy proxies so fallbacks can serve traffic)
    healthy_ports = [p[1] for p in _healthy_sorted_proxies]
    api_client.pause_all_except(healthy_ports)

def _run_full_check_cycle():
    """Performs a health check on all target proxies and updates the global lists."""
    # Resume all Tor instances before running the health checks
    api_client.resume_all()

    if CHECK_MODE == 0:
        check_func = check_proxy_ping
    elif CHECK_MODE == 1:
        check_func = check_proxy_download_fixed
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
            # Ping Filter & Download Sort #
            # ping_median, ping_success_rate  = check_proxy_ping(host, port)
            # download_median, download_success_rate  = check_proxy_download_fixed(host, port)
            # if ping_median is not None and download_median is not None:
            #     if ping_success_rate > 50:
            #         health_data[(host, port)] = download_median
            # Ping | Download Sort #
            check_median, check_success_rate = check_func(host, port)
            if check_median is not None and check_success_rate > 0:
                health_data[(host, port)] = check_median
            else:
                # Proxy failed check: assign infinity so it sorts to the end of the list
                logging.warning(f"Proxy {host}:{port} failed check. Adding to end of list.")
                health_data[(host, port)] = float('inf')
        except Exception as e:
            logging.error(f"Error during health check for proxy {host}:{port}: {e}. Adding to end of list.", exc_info=False)
            health_data[(host, port)] = float('inf')
    _update_proxy_lists(health_data)
    logging.info("--- Full health check audit complete. ---")

def store_entry_guards(bootstrapped_controllers):
    for proxy_tuple, controller in bootstrapped_controllers.items():
        guards = []
        try:
            for circ in sorted(controller.get_circuits()):
                if circ.status != CircStatus.BUILT:
                    continue
                guard_fingerprint = circ.path[0][0] # [First Node Of Circuit][Fingerprint]
                guards.append(guard_fingerprint)
            if guards:
                most_frequent_guard = max(set(guards), key=guards.count)
                entry_guards[proxy_tuple] = most_frequent_guard
        except Exception as e:
            logging.warning(f"Error fetching guards for {proxy_tuple}: {e}")

# --- FIXED & CORRECT EVENT HANDLERS ---
def generic_guard_handler(proxy_tuple, event):
    """Handles GUARD events. This logic was correct."""
    if event.status in [GuardStatus.DOWN, GuardStatus.BAD]:
        if event.endpoint_fingerprint == entry_guards.get(proxy_tuple):
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
    logging.info("All proxies bootstrapped. Performing initial health check...")

    # Store Initial Entry Guards
    store_entry_guards(bootstrapped_controllers)

    # Run Initial Check
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
            api_client.resume_all()
            _full_recheck_needed_event.clear()
        else:
            logging.info(f"--- Periodic interval ({MONITORING_INTERVAL}s) reached. Starting fallback re-check audit... ---")
        store_entry_guards(bootstrapped_controllers)
        _run_full_check_cycle()

    for controller in bootstrapped_controllers.values():
        try:
            controller.close()
        except Exception:
            pass

def get_candidate_proxies():
    """
    Returns an ordered list of proxies for a request:
    1. First tries the proxy selected by round-robin from top N.
    2. On failure, iterates sequentially through the rest of _healthy_sorted_proxies
       until the end of the list (wrapping around so no healthy proxy is missed).
    """
    global _round_robin_index
    with _shared_state_lock:
        pool = list(_healthy_sorted_proxies) if _healthy_sorted_proxies else list(_top_proxies)
        if not pool:
            return []

        # Select proxy using round-robin logic
        if _top_proxies:
            selected_proxy = _top_proxies[_round_robin_index % len(_top_proxies)]
            _round_robin_index += 1
        else:
            selected_proxy = pool[_round_robin_index % len(pool)]
            _round_robin_index += 1

        # Prevent the index from growing indefinitely (optional, but good practice)
        if _round_robin_index > 1000000:
            _round_robin_index = 0

        # Build candidate list starting from selected_proxy and continuing
        # through _healthy_sorted_proxies to the end of the list.
        if selected_proxy in pool:
            idx = pool.index(selected_proxy)
            candidates = pool[idx:] + pool[:idx]
        else:
            candidates = [selected_proxy] + [p for p in pool if p != selected_proxy]

        return candidates

def select_proxy_round_robin():
    """Selects a proxy from the top N list using a round-robin strategy."""
    candidates = get_candidate_proxies()
    return candidates[0] if candidates else None

def handle_client_connection(client_socket, client_address):
    """Handles a single client connection, forwarding it through a selected SOCKS5 proxy."""
    logging.info(f"Accepted connection from {client_address}")
    proxy_socket = None # Ensure proxy_socket is defined for the finally block

    try:
        # Enforce connection timeout on client socket to avoid hanging threads
        client_socket.settimeout(10)

        # 2. SOCKS5 handshake with the client (Version identifier/method selection)
        version_id_msg = _recv_exact(client_socket, 2)
        if not version_id_msg or len(version_id_msg) < 2:
            logging.warning(f"Client {client_address} sent incomplete version/nmethods. Closing.")
            client_socket.close(); return

        sock_version, nmethods = version_id_msg[0], version_id_msg[1]
        if sock_version != 0x05:
            logging.error(f"Unsupported SOCKS version from {client_address}: {sock_version}"); client_socket.close(); return

        client_methods = _recv_exact(client_socket, nmethods)
        if not client_methods or 0x00 not in client_methods:
            logging.error(f"Client {client_address} does not support NO AUTH method. Closing.")
            client_socket.sendall(b'\x05\xFF'); client_socket.close(); return

        client_socket.sendall(b'\x05\x00') # Select NO AUTH method

        # 3. SOCKS5 client request (get destination from client)
        client_req_header = _recv_exact(client_socket, 4)
        if not client_req_header or len(client_req_header) < 4:
            logging.warning(f"Client {client_address} sent incomplete request header. Closing."); client_socket.close(); return

        req_ver, req_cmd, _, req_atyp = client_req_header
        if req_ver != 0x05 or req_cmd != 0x01: # Check for SOCKSv5 CONNECT
            logging.error(f"Unsupported request from {client_address}: VER={req_ver}, CMD={req_cmd}. Sending error.")
            client_socket.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00'); client_socket.close(); return

        if req_atyp == 0x01: # IPv4
            dst_addr_bytes = _recv_exact(client_socket, 4)
        elif req_atyp == 0x03: # Domain name
            domain_len_byte = _recv_exact(client_socket, 1)
            if not domain_len_byte:
                logging.warning(f"Client {client_address} sent incomplete domain length. Closing."); client_socket.close(); return
            domain_len = domain_len_byte[0]
            domain_bytes = _recv_exact(client_socket, domain_len)
            if not domain_bytes:
                logging.warning(f"Client {client_address} sent incomplete domain body. Closing."); client_socket.close(); return
            dst_addr_bytes = domain_len_byte + domain_bytes
        elif req_atyp == 0x04: # IPv6
            dst_addr_bytes = _recv_exact(client_socket, 16)
        else:
            logging.error(f"Unsupported ATYP from {client_address}: {req_atyp}. Sending error.")
            client_socket.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00'); client_socket.close(); return

        dst_port_bytes = _recv_exact(client_socket, 2)
        if not dst_addr_bytes or not dst_port_bytes or len(dst_addr_bytes) < 1 or len(dst_port_bytes) < 2:
            logging.warning(f"Client {client_address} sent incomplete address/port. Closing."); client_socket.close(); return

        upstream_request = client_req_header + dst_addr_bytes + dst_port_bytes

        # --- Use the round-robin selection function ---
        candidate_proxies = get_candidate_proxies()
        if not candidate_proxies:
            logging.error(f"No healthy upstream SOCKS proxy available for {client_address}. Closing connection.")
            client_socket.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            client_socket.close()
            return

        connected_proxy = None

        for upstream_proxy in candidate_proxies:
            upstream_host, upstream_port = upstream_proxy
            logging.info(f"Selected upstream SOCKS proxy {upstream_host}:{upstream_port} for {client_address} via round-robin")
            temp_proxy_socket = None
            try:
                # 4. Connect and handshake with the upstream SOCKS proxy
                logging.debug(f"Connecting to upstream proxy {upstream_host}:{upstream_port}")
                temp_proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_proxy_socket.settimeout(10)
                temp_proxy_socket.connect((upstream_host, upstream_port))

                temp_proxy_socket.sendall(b'\x05\x01\x00')
                server_choice = _recv_exact(temp_proxy_socket, 2)
                if not server_choice or len(server_choice) < 2 or server_choice[0] != 0x05 or server_choice[1] != 0x00:
                    raise socks.SOCKS5Error(f"Upstream proxy {upstream_host}:{upstream_port} did not accept NO AUTH method. Reply: {server_choice.hex() if server_choice else 'None'}")
                logging.debug(f"Handshake with upstream proxy {upstream_host}:{upstream_port} successful.")

                # 5. Forward client's request to upstream proxy
                temp_proxy_socket.sendall(upstream_request)

                # 6. Relay reply from upstream proxy back to client
                proxy_reply_header = _recv_exact(temp_proxy_socket, 4)
                if not proxy_reply_header or len(proxy_reply_header) < 4:
                    raise ConnectionAbortedError("Upstream proxy closed connection before sending reply header.")

                if proxy_reply_header[1] != 0x00:
                    raise socks.SOCKS5Error(f"Upstream proxy {upstream_host}:{upstream_port} failed request for {client_address}. REP: {proxy_reply_header[1]}.")

                reply_atyp = proxy_reply_header[3]
                if reply_atyp == 0x01: # IPv4
                    bnd_data = _recv_exact(temp_proxy_socket, 6)
                elif reply_atyp == 0x04: # IPv6
                    bnd_data = _recv_exact(temp_proxy_socket, 18)
                elif reply_atyp == 0x03: # Domain name
                    len_byte = _recv_exact(temp_proxy_socket, 1)
                    if not len_byte:
                        raise ConnectionAbortedError("Failed to read bound domain length from upstream proxy.")
                    bnd_len = len_byte[0]
                    rest = _recv_exact(temp_proxy_socket, bnd_len + 2)
                    if not rest:
                        raise ConnectionAbortedError("Failed to read bound domain/port from upstream proxy.")
                    bnd_data = len_byte + rest
                else:
                    raise socks.SOCKS5Error(f"Unsupported ATYP from upstream proxy: {reply_atyp}")

                if not bnd_data:
                    raise ConnectionAbortedError("Failed to read bound address/port from upstream proxy.")

                client_socket.sendall(proxy_reply_header + bnd_data)

                connected_proxy = upstream_proxy
                proxy_socket = temp_proxy_socket
                break

            except (socket.error, socks.SOCKS5Error, BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
                logging.warning(f"Upstream proxy {upstream_host}:{upstream_port} failed for {client_address}: {e}. Trying next proxy in list...")
                if temp_proxy_socket:
                    try:
                        temp_proxy_socket.close()
                    except Exception:
                        pass
                _record_proxy_result(upstream_proxy, success=False)
                continue

        if not connected_proxy or not proxy_socket:
            logging.error(f"All candidate upstream proxies failed for {client_address}.")
            if not client_socket._closed:
                try:
                    client_socket.sendall(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
                except socket.error:
                    pass
            return

        # 7. Relay data
        # Success
        upstream_host, upstream_port = connected_proxy
        logging.info(f"SOCKS connection established for {client_address} via {upstream_host}:{upstream_port}. Relaying data.")
        relay_data(client_socket, proxy_socket, client_address)
        _record_proxy_result(connected_proxy, success=True)

    except (socket.error, socks.SOCKS5Error, BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as e:
        logging.error(f"Error during SOCKS relay for {client_address}: {e}")
    finally:
        if client_socket and not client_socket._closed:
            client_socket.close()
        if proxy_socket and not proxy_socket._closed:
            proxy_socket.close()
        logging.info(f"Closed connection for {client_address}")

def relay_data(sock1, sock2, client_address):
    """
    Relays data between two sockets until one closes or an error occurs.
    Single-threaded implementation using select to prevent thread exhaustion.
    """
    sockets = [sock1, sock2]
    sock1.settimeout(60)
    sock2.settimeout(60)

    try:
        while True:
            rlist, _, xlist = select.select(sockets, [], sockets, 60)
            if xlist or not rlist:
                break
            for s in rlist:
                other = sock2 if s is sock1 else sock1
                data = s.recv(8192)
                if not data:
                    return
                other.sendall(data)
    except (socket.error, BrokenPipeError, ConnectionResetError) as e:
        logging.debug(f"Socket error during relay for {client_address}: {e}")
    finally:
        for s in sockets:
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
            # Prevent 'can't start new thread' by capping total concurrent threads
            if not _client_semaphore.acquire(blocking=False):
                logging.warning(f"Connection limit reached ({MAX_CONCURRENT_CLIENTS}). Dropping {client_address}")
                client_socket.close()
                continue

            def _worker_wrapper(cs, ca):
                try:
                    handle_client_connection(cs, ca)
                finally:
                    _client_semaphore.release()

            client_thread = threading.Thread(target=_worker_wrapper, args=(client_socket, client_address))
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
        for proxy_tuple in list(proxies_to_check):
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
                    if p not in _top_proxies:
                        _top_proxies.append(p)
        
        if proxies_to_check:
            logging.info(f"Still waiting for {len(proxies_to_check)} proxies to bootstrap: {list(proxies_to_check)}")
            time.sleep(10) # Wait before re-polling remaining proxies.
        
        current_time = time.time()
        if current_time - start_time > 30 * 60:
            for proxy_tuple in list(proxies_to_check):
                # Free-Up Memory & CPU #
                controller = bootstrapped_controllers.get(proxy_tuple)
                if controller:
                    try:
                        controller.signal(Signal.SHUTDOWN)
                    except Exception:
                        pass
                    bootstrapped_controllers.pop(proxy_tuple, None)
                if proxy_tuple in target_proxies:
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
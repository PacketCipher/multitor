import requests
import logging

class ApiClient:
    def __init__(self, base_url="http://127.0.0.1:5001"):
        self.base_url = base_url

    def pause_tor_instance(self, socks_port):
        try:
            response = requests.post(f"{self.base_url}/pause/{socks_port}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error pausing Tor instance on port {socks_port}: {e}")
            return None

    def resume_tor_instance(self, socks_port):
        try:
            response = requests.post(f"{self.base_url}/resume/{socks_port}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error resuming Tor instance on port {socks_port}: {e}")
            return None

    def get_pid(self, socks_port):
        try:
            response = requests.get(f"{self.base_url}/pid/{socks_port}")
            response.raise_for_status()
            return response.json().get('pid')
        except requests.exceptions.RequestException as e:
            logging.error(f"Error getting PID for Tor instance on port {socks_port}: {e}")
            return None

    def pause_all_except(self, top_proxies):
        try:
            response = requests.post(f"{self.base_url}/pause_all_except", json={'top_proxies': top_proxies})
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error pausing Tor instances: {e}")
            return None

    def resume_all(self):
        try:
            response = requests.post(f"{self.base_url}/resume_all")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error resuming all Tor instances: {e}")
            return None

    def update_pid(self, socks_port, pid):
        try:
            response = requests.post(f"{self.base_url}/update_pid", json={'socks_port': socks_port, 'pid': pid})
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error updating PID for Tor instance on port {socks_port}: {e}")
            return None

import argparse
import netifaces
import uuid
import requests
import threading
import time
from queue import Queue

def get_ip_address(interface):
    addresses = netifaces.ifaddresses(interface)
    ip_info = addresses.get(netifaces.AF_INET)
    if not ip_info:
        raise ValueError(f"No IPv4 address found for interface {interface}")
    return ip_info[0]['addr']

def fetch_host_info(api_url, agent_uuid, ip_address, host_info_queue):
    while True:
        data = {
            'ip_address': ip_address,
            'agent_uuid': agent_uuid
        }
        try:
            response = requests.post(api_url, json=data)
            response.raise_for_status()
            host_info = response.json()
            host_info_queue.put(host_info)
            print(f"Fetched host info: {host_info}")
        except requests.RequestException as e:
            print(f"Failed to fetch host info: {e}")
        time.sleep(10)  # Fetch every 10 seconds

def connect_to_hosts(host_info_queue, connection_results):
    while True:
        if not host_info_queue.empty():
            host_info = host_info_queue.get()
            hosts = host_info.get('hosts', [])
            ports = host_info.get('ports', [])
            for host in hosts:
                try:
                    host_uuid = host['agent_uuid']
                    ip = host['ip_address']
                except KeyError:
                    print("Host info missing required data")
                    continue   
                for port in ports:
                    try:
                        # Simulate connection attempt
                        print(f"Attempting to connect to {ip}:{port} (Host UUID: {host_uuid})")
                        # Here you would add actual connection logic
                        connection_results[(ip, port)] = 'success'
                    except Exception as e:
                        connection_results[(ip, port)] = f'failure: {e}'
        time.sleep(5)  # Attempt connections every 5 seconds

def main():
    parser = argparse.ArgumentParser(description="Bind this agent to a specific network interface.")
    parser.add_argument('interface', type=str, help="The network interface to bind to (e.g., eth0, wlan0).")
    parser.add_argument('api_url', type=str, help="The URL of the remote central API.")
    args = parser.parse_args()

    try:
        ip_address = get_ip_address(args.interface)
    except ValueError as e:
        print(e)
        return

    agent_uuid = str(uuid.uuid4())

    host_info_queue = Queue()
    connection_results = {}

    fetch_thread = threading.Thread(target=fetch_host_info, args=(args.api_url, agent_uuid, ip_address, host_info_queue))
    connect_thread = threading.Thread(target=connect_to_hosts, args=(host_info_queue, connection_results))

    fetch_thread.start()
    connect_thread.start()

    fetch_thread.join()
    connect_thread.join()

if __name__ == '__main__':
    main()
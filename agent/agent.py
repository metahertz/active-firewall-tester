import argparse
import netifaces
import uuid
import requests
import threading
import time
import socket
import json
from queue import Queue
from datetime import datetime

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
            response = requests.post(f"{api_url}/api/agent", json=data)
            response.raise_for_status()
            host_info = response.json()
            host_info_queue.put(host_info)
            print(f"Fetched host info: {host_info}")
        except requests.RequestException as e:
            print(f"Failed to fetch host info: {e}")
        time.sleep(10)  # Fetch every 10 seconds

def connect_to_hosts(host_listening_queue, connection_results, agent_uuid, api_url):
    while True:
        if not host_listening_queue.empty():
            host_info = host_listening_queue.get()
            hosts = host_info.get('hosts', [])
            ports = host_info.get('ports', [])
            #Always an empty results dict.
            #connection_results = {}
            for host in hosts:
                try:
                    host_uuid = host['agent_uuid']
                    ip = host['ip_address']
                    #Dont scan our own self/agent.
                    if host_uuid == agent_uuid:
                        continue
                except KeyError:
                    print("Host info missing required data")
                    continue   
                for port in ports:
                    try:
                        print(f"Attempting to connect to {ip}:{port['port_number']} (Host UUID: {host_uuid})")
                        # Create a socket object
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(5)  # Set a timeout for the connection
                            s.connect((ip, port['port_number']))
                            s.sendall(b'{"agent_uuid": "' + agent_uuid.encode('utf-8') + b'"}')
                            data = s.recv(4096)
                        
                        # Try to parse the received data as JSON
                        # Format connection_results in a useful way for building a graph
                        try:
                            response = json.loads(data.decode('utf-8'))
                            if ip not in connection_results:
                                connection_results[ip] = {}
                            connection_results[ip][port['port_number']] = {
                            'status': 'success',
                            'bool': True,
                            'timestamp': datetime.now().isoformat(),
                            'response': response
                        }            
                            print(f"Connection to {ip}:{port['port_number']} successful.")
                        except json.JSONDecodeError:
                            if ip not in connection_results:
                                connection_results[ip] = {}
                            connection_results[ip][port['port_number']] = {
                                'status': 'failure',
                                'bool': False,
                                'timestamp': datetime.now().isoformat(),
                                'error': 'Invalid JSON response'
                            }
                            print(f"Connection to {ip}:{port['port_number']} failed: Invalid JSON response.")
                    except Exception as e:
                        if ip not in connection_results:
                            connection_results[ip] = {}
                        connection_results[ip][port['port_number']] = {
                            'status': 'failure',
                            'bool': False,
                            'timestamp': datetime.now().isoformat(),
                            'error': str(e)
                        }
                        print(f"Connection to {ip}:{port['port_number']} failed: {str(e)}")


            # Send connection results back to the API server
            # Format in a useful way for building a graph
            try:
                payload = {
                    'agent_uuid': agent_uuid,
                    'connection_results': connection_results,
                    'timestamp': datetime.now().isoformat()
                }
                response = requests.post(f"{api_url}/api/results", json=payload)
                if response.status_code == 200:
                    print("Connection results successfully sent to the API server.")
                else:
                    print(f"Failed to send connection results to the API server: {response.status_code}")
            except Exception as e:
                print(f"Error sending connection results to the API server: {str(e)}")
        
        time.sleep(5)  # Attempt connections every 5 seconds

def open_sockets(host_info_queue, agent_uuid, host_listening_queue):
    while True:
        if not host_info_queue.empty():
            host_info = host_info_queue.get()
            ports = host_info.get('ports', [])
            for port in ports:
                try:
                    # Open TCP socket
                    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    tcp_socket.bind(('', port['port_number']))
                    tcp_socket.listen(5)
                    print(f"TCP socket opened on port {port['port_number']}")

                    # Open UDP socket
                    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_socket.bind(('', port['port_number']))
                    print(f"UDP socket opened on port {port['port_number']}")

                    # Handle incoming TCP connections
                    threading.Thread(target=handle_tcp_connections, args=(tcp_socket, agent_uuid)).start()
                    # Handle incoming UDP connections
                    threading.Thread(target=handle_udp_connections, args=(udp_socket, agent_uuid)).start()
                except Exception as e:
                    print(f"Failed to open socket on port. (TODO/BUG: Existing listeners will trigger this error) {port['port_number']}: {e}")
            # Re-queue the host_info for other readers via a new queue #HACKY #BUG #TODO
            host_listening_queue.put(host_info)

def handle_tcp_connections(tcp_socket, agent_uuid):
    while True:
        conn, addr = tcp_socket.accept()
        response = json.dumps({
            'agent_uuid': agent_uuid,
            'timestamp': datetime.now().isoformat()
        })
        conn.sendall(response.encode('utf-8'))
        conn.close()

def handle_udp_connections(udp_socket, agent_uuid):
    while True:
        data, addr = udp_socket.recvfrom(1024)
        response = json.dumps({
            'agent_uuid': agent_uuid,
            'timestamp': datetime.now().isoformat()
        })
        udp_socket.sendto(response.encode('utf-8'), addr)

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
    host_listening_queue = Queue()
    connection_results = {}


    fetch_thread = threading.Thread(target=fetch_host_info, args=(args.api_url, agent_uuid, ip_address, host_info_queue))
    connect_thread = threading.Thread(target=connect_to_hosts, args=(host_listening_queue, connection_results, agent_uuid, args.api_url))
    socket_thread = threading.Thread(target=open_sockets, args=(host_info_queue, agent_uuid, host_listening_queue))

    fetch_thread.start()
    connect_thread.start()
    socket_thread.start()

    fetch_thread.join()
    connect_thread.join()
    socket_thread.join()

if __name__ == '__main__':
    main()
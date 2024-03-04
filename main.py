# Import NMAP Module
import nmap
# Import Concurret.futures module - Used to scan multiple ports at same time
import concurrent.futures
# Import time module for pause between functions
import time
# Import tabulate module for results displays
from tabulate import tabulate
# Import Datetime module
from datetime import datetime
# Import ipaddresss module for input validation
import ipaddress

# Global Variables for times and results
port_results = None    # Port scan results
last_port_scan = None  # Last port scan time
host_results = None    # Host scan results
last_host_scan = None  # Last host scan time

### Functions for Input Validation ###
# Function to validate integer inputs
def get_integer_input(prompt):
    while True:
        try:
            # Check if user input is an integer, if integer return value
            user_input = int(input(prompt))
            return user_input
        # If value not integer, return an error and prompt input
        except ValueError:
            print("Invalid Input")

# Function to validate port input
def get_port(prompt):
    while True:
        try:
            # Check if user input is an integer
            port_input = int(input(prompt))
            # Check if the integer is within the specified range
            if 1 <= port_input <= 65535:
                return port_input
            else:
                print("Port must be between 1 and 65535")
        except ValueError:
            print("Invalid Input")

# Function to validate port range input
def validate_port_range():
    while True:
        start_port = get_port("Enter Start Port: ")
        end_port = get_port("Enter End Port: ")
        
        if start_port is None or end_port is None:
            print("Invalid port range. Please try again.")
            continue

        if start_port <= end_port:
            port_range = f"{start_port}-{end_port}"
            return port_range
        else:
            print("Start Port cannot be larger than End Port.")

# Function to validation network address and subnet mask input
def get_network(prompt):
    while True:
        # Prompt input for network address
        network_address = input(prompt)
        try:
            # Create an IPv4 network object from the input
            ipaddress.IPv4Network(network_address)
            # If successful, return the address
            return network_address
        except ValueError:
            # IError handling for invalid user input
            print("Invalid Network Address.")


# Function to display main menu and options
def main_menu():
    global last_port_scan
    global last_host_scan
    print('''
  ______                              ______       _             
 / _____)             _              (_____ \     | |            
( (____  _____ ____ _| |_  ____ _   _ _____) )   _| |  ___ _____ 
 \____ \| ___ |  _ (_   _)/ ___) | | |  ____/ | | | | /___) ___ |
 _____) ) ____| | | || |_| |   | |_| | |    | |_| | ||___ | ____|
(______/|_____)_| |_| \__)_|    \__  |_|    |____/ \_|___/|_____)
                               (____/                                    
''')
    print("Last Port Scan at: ", last_port_scan, "\nLast Host Scan at: ", last_host_scan)
    print('''\nWelcome to SentryPulse!
    1: Port Scanner
    2: Host Discovery Scan
    0: Exit Program
        ''')

# Function to scan ports based on user input
def port_scanner(target, port_range, scan_type=1):

    # Global variables to store results and scan time
    global port_results      # Port Scan Results
    global last_port_scan    # Last Port Scan Results

    # Function to perform the port scan
    def port_scan(target, port_range, scan_type=1):
        try:
            # Create an instance of PortScanner from NMAP library
            scanner = nmap.PortScanner()

            # Map numbers to scan arguments
            scan_mapping = {1: '-sS', 2: '-sT', 3: '-sA'}
            # Error handling if scan type selection not in scan argument mapping
            if scan_type not in scan_mapping:
                print("Invalid Option. Defaulting to TCP SYN Scan")
                scan_type = 1
            
            # Perform the port scan with given inputs
            scanner.scan(hosts=target, arguments=f'{scan_type} -p {port_range} -sV')
            # Create an empty list to store results
            results = []

            # Iterate through each of the scan results and extract information
            for host in scanner.all_hosts():
                for port in scanner[host].all_tcp():
                    port_info = scanner[host]['tcp'][port]
                    service = port_info['name']
                    version = port_info.get('product', '')
                    results.append([host, 'tcp', port, port_info['state'], service, version])
            return results
        # Error handling for PortScanner Errors
        except nmap.PortScannerError as e:
            print(f"An error occurred during scanning: {e}")
            return []
    
    try:
        # Set last port scan time
        last_port_scan = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Display scan start time
        print("Scan Started at:", last_port_scan)

        # Use concurrent ThreatPoolExecutor for concurrent scanning of ports
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            future = executor.submit(port_scan, target, port_range, scan_type)
            port_results = future.result()
    # Error Handling for exceptions occurred during port scanning
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    # Display scan results or error if no results obtained
    if port_results:
        print("Port Scanning Results:")
        print(tabulate(port_results, headers=["Host", "Protocol", "Port", "State", "Service", "Version"], tablefmt="grid"))
    else:
        print("No results to display.")

# Function to scan for hosts on target netwrok
def host_discovery(network):

    # Global variables to store results and scan time
    global host_results      # Host Scan Results
    global last_host_scan    # Last Host Scan Time
    
    try:
        # Set last host discovery scan time
        last_host_scan = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Display scan start time
        print("Scan Started at:", last_host_scan)
        # Create an instance of PortScanner from NMAP library
        scanner = nmap.PortScanner()
        # Perform the port scan with given inputs
        scanner.scan(hosts=network, arguments='-sn')
        # Create an empty list to store results
        hosts_list = []

        # Iterating through each host found by the scanner
        for host in scanner.all_hosts():
            # Check if the host is up
            if scanner[host]['status']['state'] == 'up':
                # Retrieve hostname if available, otherwise assign 'Unknown'
                hostname = scanner[host]['hostnames'][0]['name'] if scanner[host]['hostnames'] else 'Unknown'
                # Retrieve MAC address if available, otherwise assign 'Unknown'
                mac = scanner[host]['addresses'].get('mac', 'Unknown')
                # Add results to host list 
                hosts_list.append([host, mac, hostname])

    # Error handling for NMAP errors 
    except nmap.PortScannerError as e:
        print(f"Error while scanning network: {e}")
        return []
    # Error handling for other errors not captured
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []
    
    # Display scan results or error if no results obtained
    if hosts_list:
        print("Hosts Discovered:")
        print(tabulate(hosts_list, headers=["IP", "MAC", "Hostname"], tablefmt="grid"))
        host_results = hosts_list
    else:
        print("No hosts found.")

if __name__ == '__main__':
    while True:
        # Dislay Main Menu and option input
        main_menu()
        menu_option = get_integer_input("Select an Option: ")
        if menu_option == 0:
            # Exit the program
            print("Exiting Program. Goodbye!")
            time.sleep(2)
            exit()
        elif menu_option == 1:
            # Port Scanner Function
            target = input("Enter target IP address or hostname: ")
            port_range = validate_port_range()
            scan_type = get_integer_input("Select Scan Type (1: TCP SYN, 2: TCP Connect, 3: TCP ACK): ")
            port_scanner(target, port_range, scan_type)
        elif menu_option == 2:
            # Host Discovery Function
            network = get_network("Enter Target Network(e.g. 10.10.10.0/24): ")
            host_discovery(network)  
        else:
            # Error handling for invalid option input
            print("Invalid Option")
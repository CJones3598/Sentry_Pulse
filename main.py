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
os_results = None      # OS Scan Results
last_os_scan = None    # Last OS Scan time


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

# Function to get IP input from the user
def get_ip_input(prompt):
    while True:
        try:
            # Prompt user input for network address
            network = input(prompt)
            if '-' not in network:
                # Create an IPv4 network object from the input
                ipaddress.IPv4Network(network)
                # If successful, return the address
                return network
            elif '-' in network:
                # Split the input by '-' to get start and end addresses
                parts = network.split('-')
                # Check if there are 2 parts to the network address
                if len(parts) == 2:
                    # Define start and end and split further
                    start, end = parts
                    start_parts = start.split('.')
                    # Ensure start part of address contains 4 sections
                    if len(start_parts) == 4:
                        # Check each part of the start address is a valid number and has a maximum of 3 digits
                        if all(part.isdigit() and len(part) <= 3 for part in start_parts):
                            # Check each part of the start address is within the valid range (0-255)
                            if all(0 <= int(part) <= 255 for part in start_parts):
                                # Check the end part is a valid number and has a maximum of 3 digits
                                if end.isdigit() and 0 <= int(end) <= 255 and len(end) <= 3:
                                    # Ensure the fourth part of the start address is less than or equal to the end part
                                    if int(start_parts[3]) <= int(end):
                                        # If conditions are met, return  network address
                                        return network
            # If no conditions are met, raise a Error
            raise ValueError("Invalid input.")
        # Error handling for values adn exceptions
        except ValueError as e:
            print("Error:", e)
        except Exception as e:
            print("Error:", e)


# Function to check status of each of the scan types
def scan_status():
    # Check each of the global variables for values, return status
    port_status = last_port_scan if 'last_port_scan' in globals() and last_port_scan is not None else "Not Completed"
    host_status = last_host_scan if 'last_host_scan' in globals() and last_host_scan is not None else "Not Completed"
    os_status = last_os_scan if 'last_os_scan' in globals() and last_os_scan is not None else "Not Completed"
    port_result_status = "Available" if 'port_results' in globals() and port_results is not None else "Not Available"
    host_result_status = "Available" if 'host_results' in globals() and host_results is not None else "Not Available"
    os_results_status = "Available" if 'os_results' in globals() and os_results is not None else "Not Available"
    # Display Status of each scan
    print(f"Last Scan: \nPort Scan: {port_status}, Host Scan: {host_status}, OS Scan: {os_status}")
    print(f"Results Available: \nPort Scan: {port_result_status}, Host Scan: {host_result_status}, OS Scan: {os_results_status}")

# Function to display main menu and options
def main_menu():
    print('''
  ______                              ______       _             
 / _____)             _              (_____ \     | |            
( (____  _____ ____ _| |_  ____ _   _ _____) )   _| |  ___ _____ 
 \____ \| ___ |  _ (_   _)/ ___) | | |  ____/ | | | | /___) ___ |
 _____) ) ____| | | || |_| |   | |_| | |    | |_| | ||___ | ____|
(______/|_____)_| |_| \__)_|    \__  |_|    |____/ \_|___/|_____)
                               (____/                                    
''')
    scan_status()
    print('''\nWelcome to SentryPulse!
    1: Port Scanner
    2: Host Discovery Scan
    3: OS Discovery Scan
    4: Create Report
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

# Function to scan hosts for OS information
def os_discovery(target):

    # Global variables to store results and scan time
    global os_results       # OS Scan Results
    global last_os_scan     # Last OS Scan Time

    try:
        # Set last host discovery scan time
        last_os_scan = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Display scan start time
        print("Scan Started at:", last_os_scan)
        # Create an instance of PortScanner from NMAP library
        scanner = nmap.PortScanner()
        # Perform OS discovery scan
        scanner.scan(hosts=target, arguments='-O')
        
        # Create an empty list to store results
        results = []
        # Function to process scanning for a single host
        def process_host(host):
            # Access and modify the results list defined outside function
            nonlocal results
            # Extracting OS information for the current host from the scanner
            os_match = scanner[host]['osmatch']
            # Checking if OS information is available
            if os_match:
                # If OS information is available, iterate through each OS info
                for os_info in os_match:
                    # Add results to list
                    results.append([host, os_info['name'], os_info['accuracy']])
            else:
                # If no OS information found, add message indicating to the results list
                results.append([host, "No OS information found", "N/A"])

        # Use ThreadPoolExecutor to scan hosts concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            # Submit tasks for each host
            futures = [executor.submit(process_host, host) for host in scanner.all_hosts()]
            # Wait for all tasks to complete
            concurrent.futures.wait(futures)
            
    # Error handling for NMAP errors 
    except nmap.PortScannerError as e:
        print(f"Error while scanning: {e}")
        return []
    # Error handling for other errors not captured
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return []

    # Display scan results or error if no results obtained
    if results:
        print(tabulate(results, headers=["IP Address", "Operating System", "Match %"], tablefmt="grid"))
        os_results = results
    else:
        print("No results to display")

# Function to create a report for scan results
def create_report():
    # Global Variable for scan results and scan times
    global port_results, host_results, os_results
    global last_port_scan, last_host_scan,last_os_scan

    # Input for naming report file
    file_name = input("Enter File Name: ")
    # Date calculation for filename and report time
    date = datetime.now().strftime('%Y-%m-%d')
    # Input for report title
    title = input("Enter Report Title: ")

    formatted_ports = tabulate(port_results, headers=["Host", "Protocol", "Port", "State", "Service", "Version"], tablefmt="grid")
    formatted_hosts = tabulate(host_results, headers=["IP", "MAC", "Hostname"], tablefmt="grid")
    formatted_os = tabulate(os_results, headers=["IP Address", "Operating System", "Match %"], tablefmt="grid")

    # Section to write results to file
    with open(f"{file_name}-{date}.txt", "w") as report_file:
        report_file.write(f"Report Title: {title}\n")
        report_file.write(f"Date: {date}\n\n")
        
        report_file.write("\nPort Scan Results:")
        report_file.write(f"Port Scan Completed at: {last_port_scan}\n")
        report_file.write(formatted_ports)
        report_file.write("\nHost Discovery Results:\n")
        report_file.write(f"Host Scan Completed at: {last_host_scan}\n")
        report_file.write(formatted_hosts)
        report_file.write("\nOS Discovery Results:\n")
        report_file.write(f"OS Scan Completed at: {last_os_scan}\n")
        report_file.write(formatted_os)


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
        elif menu_option == 3:
            # OS Discovery Function
            target = get_ip_input("Enter target IP address(e.g.'10.10.1.1','10.10.1.1-10'or'10.10.1.0/24'): ")
            os_discovery(target)
        elif menu_option == 4:
            # Create Report Function
            # Check if all results are available
            if port_results and host_results and os_results is not None:
                # If all results are available continue to report creation
                create_report()
            else:
                while True:
                    # If not all results are available, prompt confirmation
                    print("Some results are not available. Would you like to continue? 0:No 1:Yes ")
                    report_choice = get_integer_input("Select Option: ")
                    if report_choice == 0:
                        # Exit to main menu
                        break
                    elif report_choice == 1:
                        # Proceed to report creation
                        create_report()
                        break
                    else:
                        # Error handling for invalid option input
                        print("Invalid Option")
        else:
            # Error handling for invalid option input
            print("Invalid Option")
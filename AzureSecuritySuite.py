# -*- coding: utf-8 -*-
import os
import platform
import shutil
import subprocess
import time
import json
import sys
import argparse
from colorama import init, Fore, Style
import logging
from datetime import datetime
import requests
from pathlib import Path
import csv
from html import escape
from typing import Dict, List
from report_generator import generate_html_report

# Initialize colorama for cross-platform color support
init(autoreset=True) 

# Create logs directory if it doesn't exist
log_dir = 'azuresecuritysuitelogs'
os.makedirs(log_dir, exist_ok=True)

__version__ = "1.0.0"

def get_unique_log_filename(subscription_name):
    """Generate a unique log filename, adding a counter if necessary."""
    base_filename = datetime.now().strftime(f"%Y-%m-%d_%H-%M-%S_{subscription_name}")
    counter = 0
    while True:
        # If no counter is needed, use the base filename
        if counter == 0:
            log_filename = f"{base_filename}.log"
        else:
            # Add counter if a file with the same name exists
            log_filename = f"{base_filename}_{counter}.log"
        
        # Check if file exists
        log_filepath = os.path.join(log_dir, log_filename)
        if not os.path.exists(log_filepath):
            return log_filepath
        counter += 1

def configure_logging(subscription_name):
    """Configure logging with a guaranteed unique filename."""
    try:
        # Reset logging configuration
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
            
        log_filepath = get_unique_log_filename(subscription_name)
        if not log_filepath:
            raise ValueError("Failed to generate log filepath")
            
        print(f"\n{Fore.CYAN}Setting up logging...{Style.RESET_ALL}")
        print(f"Log file will be created at: {log_filepath}")
        
        # Create logs directory if it doesn't exist
        os.makedirs(os.path.dirname(log_filepath), exist_ok=True)
        
        logging.basicConfig(
            filename=log_filepath,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Test logging
        logging.info("=== New Scanning Session Started ===")
        logging.info(f"Subscription: {subscription_name}")
        print(f"{Fore.GREEN}✓ Logging configured successfully{Style.RESET_ALL}")
        return True
        
    except Exception as e:
        print(f"{Fore.RED}Error setting up logging: {str(e)}{Style.RESET_ALL}")
        return False

def clear_screen():
    """Clear the terminal screen based on OS."""
    os.system('cls' if platform.system() == 'Windows' else 'clear') 

def print_banner(update_available=False, latest_version=None):
    """Display a professional and colorful banner with ASCII art."""
    clear_screen()
    terminal_width = shutil.get_terminal_size().columns
    ascii_art = r"""
     ___                           ___                                                              
    (   )                         (   )                                                             
  .-.| |       ,--.    ___ .-.     | |   ___    ___ .-. .-.        ,--.     .--.    .--.    .--.    
 /   \ |      /   |   (   )   \    | |  (   )  (   )   '   \      /   |    /    \  (_  |   /    \   
|  .-. |     / .' |    | ' .-. ;   | |  ' /     |  .-.  .-. ;    / /| |   ;  ,-. '   | |  |  .-. ;  
| |  | |    / / | |    |  / (___)  | |,' /      | |  | |  | |   / / | |   | |  | |   | |  |  |(___) 
| |  | |   / /  | |    | |         | .  '.      | |  | |  | |  / /  | |   | |  | |   | |  |  |      
| |  | |  /  `--' |-.  | |         | | `. \     | |  | |  | | /  `--' |-. | |  | |   | |  |  | ___  
| '  | |  `-----| |-'  | |         | |   \ .    | |  | |  | | `-----| |-' | '  | |   | |  |  '(   ) 
' `-'  /        | |    | |         | |    \ .   | |  | |  | |       | |   '  `-' |   | |  '  `-' |  
 `.__,'        (___)  (___)       (___ ) (___) (___)(___)(___)     (___)   `.__. |  (___)  `.__,'   
                                                                           ( `-' ;                  
                                                                            `.__.                   
    """.strip().splitlines()

    # Calculate the width of the ASCII art
    ascii_width = max(len(line) for line in ascii_art)
    border_width = max(ascii_width, terminal_width)

    # Create the top and bottom borders
    top_border = f"{Fore.CYAN}╔{'═' * (border_width - 2)}╗{Style.RESET_ALL}"
    bottom_border = f"{Fore.CYAN}╚{'═' * (border_width - 2)}╝{Style.RESET_ALL}"

    # Center each line of the ASCII art
    centered_ascii_art = "\n".join(line.center(border_width) for line in ascii_art)

    # Print the banner with centered text and color
    banner = f"""
{top_border}
{centered_ascii_art}
{bottom_border}
{Fore.CYAN}╔{'═' * (terminal_width-2)}╗
║{' ' * (terminal_width-2)}║
║{Style.BRIGHT + Fore.MAGENTA + ' Welcome to '.center(terminal_width-2)}║
║{Style.BRIGHT + Fore.YELLOW + ' Azure Security Scanner (AzureSecuritySuite) '.center(terminal_width-2)}║
║{' ' * (terminal_width-2)}║
║{Style.BRIGHT + Fore.GREEN + 'Created by D4rkm4g1c (Consultant)'.center(terminal_width-2)}║
║{' ' * (terminal_width-2)}║
║{Style.BRIGHT + Fore.GREEN + f' Version {__version__} - 2024-12-03'.center(terminal_width-2)}║"""

    # Add update notification if available
    if update_available and latest_version:
        banner += f"""
║{' ' * (terminal_width-2)}║
║{Style.BRIGHT + Fore.YELLOW + f' Update Available! Version {latest_version} '.center(terminal_width-2)}║
║{Style.BRIGHT + Fore.YELLOW + ' Run with --update to upgrade '.center(terminal_width-2)}║"""

    banner += f"""
║{' ' * (terminal_width-2)}║
╚{'═' * (terminal_width-2)}╝{Style.RESET_ALL}
"""
    print(banner)

def sanitize_input(user_input, input_type="numeric", allowed_range=None):
    """
    Sanitize user input based on expected type and range.
    
    Args:
        user_input (str): The raw input from user
        input_type (str): Expected type ("numeric", "text", "choice")
        allowed_range (tuple): Optional tuple of (min, max) for numeric inputs
    
    Returns:
        tuple: (is_valid, sanitized_value, error_message)
    """
    try:
        if not user_input.strip():
            return False, None, "Input cannot be empty"

        if input_type == "numeric":
            # Remove any whitespace and check if it's a number
            cleaned_input = user_input.strip()
            if not cleaned_input.isdigit():
                return False, None, "Please enter a valid number"
            
            value = int(cleaned_input)
            if allowed_range:
                min_val, max_val = allowed_range
                if not (min_val <= value <= max_val):
                    return False, None, f"Please enter a number between {min_val} and {max_val}"
            return True, value, None

        elif input_type == "text":
            # Remove dangerous characters and excessive whitespace
            cleaned_input = " ".join(user_input.strip().split())
            if not cleaned_input:
                return False, None, "Input cannot be empty"
            return True, cleaned_input, None

        elif input_type == "choice":
            cleaned_input = user_input.strip().lower()
            if cleaned_input not in ['y', 'n', 'yes', 'no']:
                return False, None, "Please enter 'y' or 'n'"
            return True, cleaned_input in ['y', 'yes'], None

    except Exception as e:
        logging.error(f"Input sanitization error: {str(e)}")
        return False, None, "Invalid input format"

def handle_error(error, context=None):
    """
    Handle errors and provide user-friendly messages and suggestions.
    
    Args:
        error (Exception): The caught exception
        context (str): Additional context about where the error occurred
    """
    error_type = type(error).__name__
    error_msg = str(error)
    
    # Common error messages and suggestions
    error_suggestions = {
        "ConnectionError": (
            "Network connection error",
            ["Check your internet connection", 
             "Verify Azure CLI is properly configured",
             "Check if Azure services are available"]
        ),
        "AuthenticationError": (
            "Authentication failed",
            ["Try clearing your cached credentials (Option 1)",
             "Log in again using 'az login' (Option 2)",
             "Verify your Azure account has necessary permissions"]
        ),
        "PermissionError": (
            "Permission denied",
            ["Verify you have necessary Azure role assignments",
             "Check if your account has MFA requirements",
             "Try logging in again with elevated permissions"]
        ),
        "ValueError": (
            "Invalid value provided",
            ["Check if the input matches the expected format",
             "Verify all required parameters are provided",
             "Ensure the values are within acceptable ranges"]
        ),
        "FileNotFoundError": (
            "Required file not found",
            ["Verify the file path is correct",
             "Check if the file exists in the expected location",
             "Ensure you have read permissions for the file"]
        )
    }

    # Get error details
    error_details = error_suggestions.get(error_type, 
        ("An unexpected error occurred", 
         ["Try restarting the script",
          "Check the logs for more details",
          "Contact support if the issue persists"])
    )

    # Log the error
    logging.error(f"Error in {context}: {error_type} - {error_msg}")

    # Display user-friendly error message
    print(f"\n{Fore.RED}Error: {error_details[0]}{Style.RESET_ALL}")
    print(f"{Fore.RED}Details: {error_msg}{Style.RESET_ALL}")
    
    # Display suggestions
    print(f"\n{Fore.YELLOW}Suggestions to resolve:{Style.RESET_ALL}")
    for suggestion in error_details[1]:
        print(f"{Fore.YELLOW}• {suggestion}{Style.RESET_ALL}")

def display_menu(title, options, prompt="Select an option: ", show_back=False):
    """Display a menu with a title and options."""
    logging.info(f"Displaying menu: {title}")
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{title}:{Style.RESET_ALL}")
    
    # Calculate the valid range for menu options
    min_value = 0 if show_back else 1
    max_value = len(options)
    
    for idx, option in enumerate(options, 1):
        print(f"{Fore.GREEN}{idx}.{Style.RESET_ALL} {option}")
    if show_back:
        print(f"{Fore.RED}0.{Style.RESET_ALL} Back to Previous Menu")
    
    while True:
        try:
            # Get user input and sanitize it
            choice = input(f"{Fore.YELLOW}{prompt}{Style.RESET_ALL}")
            is_valid, value, error_message = sanitize_input(
                choice, 
                input_type="numeric", 
                allowed_range=(min_value, max_value)
            )
            
            if is_valid:
                return value
            else:
                print(f"{Fore.RED}{error_message}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Please enter a number between {min_value} and {max_value}{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Operation cancelled by user{Style.RESET_ALL}")
            return None
        except Exception as e:
            handle_error(e, "menu selection")
            continue

def show_spinner(text):
    """Show a spinner while processing."""
    spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '', '⠏']
    i = 0
    while True:
        print(f"\r{Fore.CYAN}{spinner[i]} {text}{Style.RESET_ALL}", end='', flush=True)
        i = (i + 1) % len(spinner)
        yield

def log_query_execution(query, output_file, success):
    """Log the execution of a query."""
    if success:
        logging.info(f"Query executed successfully: {query} -> {output_file}")
    else:
        logging.error(f"Query execution failed: {query}")

def run_steampipe_query(query, output_file):
    """Run a Steampipe query and save the output to a file."""
    try:
        # Log the full Steampipe command
        steampipe_cmd = [
            "steampipe",
            "query",
            query,
            "--output",
            "csv",
            "--header=false"
        ]
        logging.info(f"Executing Steampipe command: {' '.join(steampipe_cmd)}")
        print(f"\n{Fore.CYAN}Executing query...{Style.RESET_ALL}")
        
        # Check if steampipe is installed
        try:
            subprocess.run(["steampipe", "--version"], check=True, capture_output=True)
        except subprocess.CalledProcessError:
            raise RuntimeError("Steampipe is not installed or not in PATH")
        
        # Use asyncio for non-blocking IO
        process = subprocess.Popen(steampipe_cmd, 
                               stdout=subprocess.PIPE, 
                               stderr=subprocess.PIPE, 
                               text=True,
                               bufsize=1)  # Line buffered
        
        spinner = show_spinner("Processing query")
        stdout_data = []
        stderr_data = []
        
        # Process output in chunks
        while True:
            next(spinner)
            
            # Read output without blocking
            output = process.stdout.readline()
            error = process.stderr.readline()
            
            if output:
                stdout_data.append(output.strip())
            if error:
                stderr_data.append(error.strip())
                
            # Check if process has finished
            if process.poll() is not None:
                break
                
            time.sleep(0.1)
        
        print('\r', end='')  # Clear spinner line
        
        if process.returncode == 0:
            # Process CSV output efficiently
            results = [line for line in stdout_data if line.strip()]
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Write results efficiently
            with open(output_file, 'w', newline='') as f:
                f.write('\n'.join(results))
            
            print(f"{Fore.GREEN}✓ Results saved to: {output_file}{Style.RESET_ALL}")
            logging.info(f"Query executed successfully. Found {len(results)} resources.")
            return True
        else:
            error_msg = '\n'.join(stderr_data)
            print(f"{Fore.RED}✗ Query execution failed: {error_msg}{Style.RESET_ALL}")
            logging.error(f"Query execution failed with error: {error_msg}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Exception occurred while executing query: {str(e)}")
        return False

def create_folder_structure(tenant_name, subscription_name, subscription_id):
    """Create the folder structure for the tenant and subscription."""
    # Use tenant name as the base directory
    base_dir = tenant_name
    os.makedirs(base_dir, exist_ok=True)

    # Create subscription folder
    subscription_folder_name = f"{subscription_name} ({subscription_id})"
    subscription_folder = os.path.join(base_dir, subscription_folder_name)
    os.makedirs(subscription_folder, exist_ok=True)

    resource_types = [
        "VirtualMachines", 
        "StorageAccounts", 
        "AppServices", 
        "NetworkSecurityGroups", 
        "SQLDatabases", 
        "PostgreSQLDatabases", 
        "KeyVaults",
        "MySQLDatabases",
        "CosmosDB"
    ]
    
    resource_folders = {}
    for resource_type in resource_types:
        resource_folder = os.path.join(subscription_folder, resource_type)
        os.makedirs(resource_folder, exist_ok=True)
        resource_folders[resource_type] = resource_folder

    print(f"{Fore.GREEN}✓ Folder structure created in {base_dir}{Style.RESET_ALL}")
    return resource_folders

def write_vuln_overview(vuln_overview, resource_folder, resource_type):
    """Write the vulnerability overview to a CSV file in the resource folder."""
    output_file = os.path.join(resource_folder, f"{resource_type}_vulnerability_overview.csv")
    
    # Special handling for NSGs to combine findings for the same NSG
    if resource_type == "NetworkSecurityGroups":
        consolidated_overview = {}
        for resource, vulns in vuln_overview.items():
            # Extract base NSG name (remove port info if present)
            base_name = resource.split(' (')[0]
            
            if base_name not in consolidated_overview:
                consolidated_overview[base_name] = set()
            
            # Add all vulnerabilities for this NSG
            consolidated_overview[base_name].update(vulns)
        
        # Write consolidated overview
        with open(output_file, 'w') as f:
            f.write("Resource Name,Vulnerabilities Found\n")
            for resource, vulns in consolidated_overview.items():
                # Join vulnerabilities with semicolon for better separation
                f.write(f"{resource},{'; '.join(vulns)}\n")
    else:
        # Original handling for other resource types
        with open(output_file, 'w') as f:
            f.write("Resource Name,Vulnerabilities Found\n")
            for resource, vulns in vuln_overview.items():
                f.write(f"{resource},{'; '.join(vulns)}\n")
                
    print(f"{Fore.GREEN}✓ Vulnerability overview for {resource_type} saved to: {output_file}{Style.RESET_ALL}")

def run_scans(resource_folder, scans, scan_type):
    """Run a list of scans and save results to the resource folder."""
    try:
        total_scans = len(scans)
        successful_scans = 0
        
        for scan_name, query, output_file in scans:
            try:
                print(f"\n{Fore.CYAN}Running {scan_name} scan...{Style.RESET_ALL}")
                output_path = os.path.join(resource_folder, output_file)
                
                if run_steampipe_query(query, output_path):
                    successful_scans += 1
                    print(f"{Fore.GREEN}✓ {scan_name} scan completed successfully{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}✗ {scan_name} scan failed{Style.RESET_ALL}")
                    
            except Exception as e:
                print(f"{Fore.RED}Error in {scan_name} scan: {str(e)}{Style.RESET_ALL}")
                logging.error(f"Error in {scan_name} scan: {str(e)}")
                
        print(f"\n{Fore.CYAN}Scan Summary for {scan_type}:{Style.RESET_ALL}")
        print(f"Total Scans: {total_scans}")
        print(f"Successful: {successful_scans}")
        print(f"Failed: {total_scans - successful_scans}")
        
    except Exception as e:
        print(f"{Fore.RED}Error running scans: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error running scans: {str(e)}")

def run_all_scans(resource_folders):
    """Run all scans for all resource types."""
    try:
        print(f"\n{Fore.CYAN}Running all security scans...{Style.RESET_ALL}")
        
        # Dictionary mapping resource types to their scan functions
        scan_functions = {
            "VirtualMachines": (scan_virtual_machines, scan_virtual_machines.scans),
            "StorageAccounts": (scan_storage_accounts, scan_storage_accounts.scans),
            "AppServices": (scan_app_services, scan_app_services.scans),
            "NetworkSecurityGroups": (scan_network_security_groups, scan_network_security_groups.scans),
            "SQLDatabases": (scan_sql_databases, scan_sql_databases.scans),
            "KeyVaults": (scan_key_vaults, scan_key_vaults.scans),
            "PostgreSQLDatabases": (scan_postgresql_databases, scan_postgresql_databases.scans),
            "MySQLDatabases": (scan_mysql_databases, scan_mysql_databases.scans),
            "CosmosDB": (scan_cosmos_db, scan_cosmos_db.scans)
        }
        
        for resource_type, (_, scans) in scan_functions.items():
            print(f"\n{Fore.CYAN}Running {resource_type} scans...{Style.RESET_ALL}")
            run_scans(resource_folders[resource_type], scans, resource_type)
            
        print(f"\n{Fore.GREEN}✓ All scans completed{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}Error running all scans: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error running all scans: {str(e)}")

def display_scan_submenu(scans, resource_type):
    """Display submenu for selecting specific scans."""
    try:
        print(f"\n{Fore.CYAN}Available {resource_type} Scans:{Style.RESET_ALL}")
        options = ["Run All"] + [scan[0] for scan in scans]
        
        choice = display_menu(f"Select {resource_type} Scan", options, show_back=True)
        if choice is None or choice == 0:  # User cancelled or selected back
            return None
            
        if choice == 1:  # Run All selected
            return scans
        elif 1 < choice <= len(options):
            # Return only the selected scan
            return [scans[choice - 2]]  # -2 because we added "Run All" at the beginning
        else:
            print(f"{Fore.RED}Invalid selection{Style.RESET_ALL}")
            return None
            
    except Exception as e:
        print(f"{Fore.RED}Error displaying scan submenu: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error displaying scan submenu: {str(e)}")
        return None

def run_selected_scans(resource_folder, selected_scans, scan_type):
    """Run only the selected scans for a resource type."""
    if not selected_scans:
        return
        
    try:
        print(f"\n{Fore.CYAN}Running selected {scan_type} scans...{Style.RESET_ALL}")
        run_scans(resource_folder, selected_scans, scan_type)
        
    except Exception as e:
        print(f"{Fore.RED}Error running selected scans: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error running selected scans: {str(e)}")

def scan_resource_group(resource_folder, scans, resource_type):
    """Handle scanning for a specific resource group with a loop."""
    while True:
        selected_scans = display_scan_submenu(scans, resource_type)
        if selected_scans is None:  # User selected back
            return
            
        run_selected_scans(resource_folder, selected_scans, resource_type)
        print(f"\n{Fore.CYAN}Completed {resource_type} scan(s).{Style.RESET_ALL}")
        input(f"{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
        clear_screen()
        print_banner()

def scan_virtual_machines(resource_folder):
    """Run Steampipe scans for virtual machines."""
    if hasattr(scan_virtual_machines, 'scans'):
        scan_resource_group(resource_folder, scan_virtual_machines.scans, "VirtualMachines")

scan_virtual_machines.scans = [
    ("Unmanaged Disks", "SELECT vm.name FROM azure_compute_virtual_machine AS vm, azure_subscription AS sub WHERE sub.subscription_id = vm.subscription_id AND managed_disk_id IS NULL", "unmanaged_disks.csv"),
    ("Unencrypted Disks", "SELECT disk.name FROM azure_compute_disk AS disk, azure_subscription AS sub WHERE disk_state != 'Attached' AND sub.subscription_id = disk.subscription_id AND encryption_type != 'EncryptionAtRestWithCustomerKey'", "unencrypted_disks.csv")
]

def scan_storage_accounts(resource_folder):
    """Run Steampipe scans for storage accounts."""
    if hasattr(scan_storage_accounts, 'scans'):
        scan_resource_group(resource_folder, scan_storage_accounts.scans, "StorageAccounts")

scan_storage_accounts.scans = [
    ("Public Blob Access Enabled", "SELECT name FROM azure_storage_account WHERE allow_blob_public_access = true", "public_blob_access.csv"),
    ("Soft Delete Disabled", "SELECT name FROM azure_storage_account WHERE blob_soft_delete_enabled = false", "soft_delete_disabled.csv"),
    ("Network Default Allow", "SELECT name FROM azure_storage_account WHERE network_rule_default_action = 'Allow'", "network_default_allow.csv"),
    ("Infrastructure Encryption Disabled", "SELECT name FROM azure_storage_account WHERE require_infrastructure_encryption IS NOT TRUE", "infrastructure_encryption.csv"),
    ("HTTPS Traffic Only Disabled", "SELECT name FROM azure_storage_account WHERE enable_https_traffic_only = 'False'", "https_traffic_only.csv"),
    ("Insecure TLS Version", "SELECT name FROM azure_storage_account WHERE minimum_tls_version IN ('TLS1_0', 'TLS1_1')", "tls_version.csv"),
    ("Blob Versioning Disabled", "SELECT name FROM azure_storage_account WHERE blob_versioning_enabled IS NOT TRUE", "blob_versioning.csv")
]

def scan_app_services(resource_folder):
    """Run Steampipe scans for App Services."""
    if hasattr(scan_app_services, 'scans'):
        scan_resource_group(resource_folder, scan_app_services.scans, "AppServices")

scan_app_services.scans = [
    ("Web App Auth Settings", "SELECT name FROM azure_app_service_web_app AS app", "web_app_auth_settings.csv"),
    ("Function App Auth Settings", "SELECT name FROM azure_app_service_function_app", "function_app_auth_settings.csv"),
    ("Web Apps for HTTPS Only", "SELECT name FROM azure_app_service_web_app WHERE NOT https_only", "web_app_https_only.csv"),
    ("Function Apps for Client Certs", "SELECT app.name FROM azure_app_service_function_app AS app WHERE NOT app.client_cert_enabled", "function_app_client_cert.csv"),
    ("Web Apps for Managed Identity", "SELECT app.name FROM azure_app_service_web_app AS app WHERE app.identity = '{}'", "web_app_managed_identity.csv"),
    ("Web Apps for HTTP/2 Enabled", "SELECT name FROM azure_app_service_web_app WHERE (configuration -> 'properties' ->> 'http20Enabled')::boolean = false OR (configuration -> 'properties' ->> 'http20Enabled') IS NULL", "web_app_http2.csv"),
    ("Web Apps for FTPS State", "SELECT name FROM azure_app_service_web_app WHERE configuration -> 'properties' ->> 'ftpsState' = 'AllAllowed'", "web_app_ftps_state.csv"),
    ("Web Apps with No Client Cert", "SELECT app.name AS resource FROM azure_app_service_web_app AS app, azure_subscription AS sub WHERE NOT client_cert_enabled AND sub.subscription_id = app.subscription_id", "app_names_no_client_cert.csv"),
    ("Web Apps for TLS Version < 1.2", "SELECT app.name AS resource FROM azure_app_service_web_app AS app, azure_subscription AS sub WHERE (configuration -> 'properties' ->> 'minTlsVersion') < '1.2' AND sub.subscription_id = app.subscription_id", "app_names_tls_v1_2.csv"),
    ("Function Apps for TLS Version < 1.2", "SELECT app.name AS resource FROM azure_app_service_function_app AS app, azure_subscription AS sub WHERE (configuration -> 'properties' ->> 'minTlsVersion') < '1.2' AND sub.subscription_id = app.subscription_id", "function_app_names_tls_v1_2.csv"),
    ("API Apps for TLS Version Check", "WITH all_api_app AS (SELECT id, name FROM azure_app_service_web_app WHERE EXISTS (SELECT 1 FROM unnest(regexp_split_to_array(kind, ',')) elem WHERE elem LIKE '%api')) SELECT a.name AS app_name FROM azure_app_service_web_app AS a LEFT JOIN all_api_app AS b ON a.id = b.id WHERE b.id IS NOT NULL AND (configuration -> 'properties' ->> 'minTlsVersion') < '1.2'", "api_app_tls_check.csv")
]

def scan_network_security_groups(resource_folder):
    """Run Steampipe scans for Network Security Groups."""
    if hasattr(scan_network_security_groups, 'scans'):
        scan_resource_group(resource_folder, scan_network_security_groups.scans, "NetworkSecurityGroups")

scan_network_security_groups.scans = [
    ("Unrestricted Inbound/Outbound Rules", "WITH unrestricted_inbound AS (SELECT DISTINCT name AS sg_name FROM azure_network_security_group nsg, jsonb_array_elements(security_rules || default_security_rules) sg, jsonb_array_elements_text(CASE WHEN jsonb_array_length(sg -> 'properties' -> 'destinationPortRanges') > 0 THEN (sg -> 'properties' -> 'destinationPortRanges') ELSE jsonb_build_array(sg -> 'properties' -> 'destinationPortRange') END) AS dport, jsonb_array_elements_text(CASE WHEN jsonb_array_length(sg -> 'properties' -> 'sourceAddressPrefixes') > 0 THEN (sg -> 'properties' -> 'sourceAddressPrefixes') ELSE jsonb_build_array(sg -> 'properties' -> 'sourceAddressPrefix') END) AS sip WHERE sg -> 'properties' ->> 'access' = 'Allow' AND sg -> 'properties' ->> 'direction' = 'Inbound' AND sip IN ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0') AND dport = '*'), unrestricted_outbound AS (SELECT DISTINCT name AS sg_name FROM azure_network_security_group nsg, jsonb_array_elements(security_rules || default_security_rules) sg, jsonb_array_elements_text(CASE WHEN jsonb_array_length(sg -> 'properties' -> 'destinationPortRanges') > 0 THEN (sg -> 'properties' -> 'destinationPortRanges') ELSE jsonb_build_array(sg -> 'properties' -> 'destinationPortRange') END) AS dport, jsonb_array_elements_text(CASE WHEN jsonb_array_length(sg -> 'properties' -> 'sourceAddressPrefixes') > 0 THEN (sg -> 'properties' -> 'sourceAddressPrefixes') ELSE jsonb_build_array(sg -> 'properties' -> 'sourceAddressPrefix') END) AS sip WHERE sg -> 'properties' ->> 'access' = 'Allow' AND sg -> 'properties' ->> 'direction' = 'Outbound' AND sip IN ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0') AND dport = '*') SELECT sg_name FROM unrestricted_inbound UNION SELECT sg_name FROM unrestricted_outbound", "unrestricted_rules.csv"),
    ("Clear Text Protocols", """
        WITH clear_text_protocols AS (
            SELECT DISTINCT 
                name AS sg_name,
                dport,
                CASE dport
                    WHEN '20' THEN 'FTP-Data'
                    WHEN '21' THEN 'FTP'
                    WHEN '23' THEN 'Telnet'
                    WHEN '25' THEN 'SMTP'
                    WHEN '69' THEN 'TFTP'
                    WHEN '80' THEN 'HTTP'
                    WHEN '110' THEN 'POP3'
                    WHEN '119' THEN 'NNTP'
                    WHEN '143' THEN 'IMAP'
                    WHEN '161' THEN 'SNMP'
                    WHEN '162' THEN 'SNMP-Trap'
                    WHEN '389' THEN 'LDAP'
                    WHEN '513' THEN 'rlogin'
                    WHEN '514' THEN 'syslog'
                END AS service_name
            FROM azure_network_security_group nsg,
            jsonb_array_elements(security_rules || default_security_rules) sg,
            jsonb_array_elements_text(CASE 
                WHEN jsonb_array_length(sg -> 'properties' -> 'destinationPortRanges') > 0 
                THEN (sg -> 'properties' -> 'destinationPortRanges') 
                ELSE jsonb_build_array(sg -> 'properties' -> 'destinationPortRange') 
            END) AS dport
            WHERE sg -> 'properties' ->> 'access' = 'Allow'
            AND dport IN ('20', '21', '23', '25', '69', '80', '110', '119', '143', '161', '162', '389', '513', '514')
        )
        SELECT 
            sg_name || ',' || dport || ',' || service_name as nsg_port_service 
        FROM clear_text_protocols
        ORDER BY sg_name, dport""", 
        "clear_text_protocols.csv"),
    ("Sensitive Management Ports", """
        WITH sensitive_management_ports AS (
            SELECT DISTINCT 
                name AS sg_name,
                dport,
                CASE dport
                    WHEN '22' THEN 'SSH'
                    WHEN '23' THEN 'Telnet'
                    WHEN '80' THEN 'HTTP'
                    WHEN '443' THEN 'HTTPS'
                    WHEN '3389' THEN 'RDP'
                    WHEN '5900' THEN 'VNC'
                    WHEN '21' THEN 'FTP'
                    WHEN '69' THEN 'TFTP'
                    WHEN '389' THEN 'LDAP'
                    WHEN '514' THEN 'syslog'
                    WHEN '137' THEN 'NetBIOS'
                    WHEN '138' THEN 'NetBIOS'
                    WHEN '139' THEN 'NetBIOS'
                    WHEN '445' THEN 'SMB'
                    WHEN '88' THEN 'Kerberos'
                    WHEN '3306' THEN 'MySQL'
                    WHEN '1433' THEN 'MSSQL'
                    WHEN '5432' THEN 'PostgreSQL'
                    WHEN '1521' THEN 'Oracle'
                    WHEN '6379' THEN 'Redis'
                    WHEN '25' THEN 'SMTP'
                    WHEN '465' THEN 'SMTPS'
                    WHEN '110' THEN 'POP3'
                END AS service_name
            FROM azure_network_security_group nsg,
            jsonb_array_elements(security_rules || default_security_rules) sg,
            jsonb_array_elements_text(CASE 
                WHEN jsonb_array_length(sg -> 'properties' -> 'destinationPortRanges') > 0 
                THEN (sg -> 'properties' -> 'destinationPortRanges') 
                ELSE jsonb_build_array(sg -> 'properties' -> 'destinationPortRange') 
            END) AS dport,
            jsonb_array_elements_text(CASE 
                WHEN jsonb_array_length(sg -> 'properties' -> 'sourceAddressPrefixes') > 0 
                THEN (sg -> 'properties' -> 'sourceAddressPrefixes') 
                ELSE jsonb_build_array(sg -> 'properties' -> 'sourceAddressPrefix') 
            END) AS sip
            WHERE sg -> 'properties' ->> 'access' = 'Allow'
            AND sip IN ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0')
            AND dport IN ('22', '23', '80', '443', '3389', '5900', '21', '69', '389', '514', 
                         '137', '138', '139', '445', '88', '3306', '1433', '5432', '1521', 
                         '6379', '25', '465', '110')
        )
        SELECT 
            sg_name || ',' || dport || ',' || service_name as nsg_port_service
        FROM sensitive_management_ports
        ORDER BY sg_name, dport""",
        "sensitive_management_ports.csv")
]

def scan_sql_databases(resource_folder):
    """Run Steampipe scans for SQL Databases."""
    if hasattr(scan_sql_databases, 'scans'):
        scan_resource_group(resource_folder, scan_sql_databases.scans, "SQLDatabases")

scan_sql_databases.scans = [
    ("Disabled Server Audit Policies", "SELECT s.name AS resource FROM azure_sql_server s, jsonb_array_elements(s.server_audit_policy) AS audit WHERE audit -> 'properties' ->> 'state' = 'Disabled';", "sql_server_audit_disabled.csv"),
    ("Audit Retention Less Than 90 Days", "SELECT s.name AS resource FROM azure_sql_server s, jsonb_array_elements(s.server_audit_policy) AS audit WHERE (audit -> 'properties' ->> 'retentionDays')::integer < 90;", "sql_server_audit_retention_less_than_90.csv"),
    ("Firewall Rules Allowing 0.0.0.0/0", "SELECT s.name AS resource FROM azure_sql_server s WHERE firewall_rules @> '[{\"properties\":{\"endIpAddress\":\"0.0.0.0\",\"startIpAddress\":\"0.0.0.0\"}}]' OR firewall_rules @> '[{\"properties\":{\"endIpAddress\":\"255.255.255.255\",\"startIpAddress\":\"0.0.0.0\"}}]';", "sql_server_firewall_ingress_0_0_0_0.csv"),
    ("Public Network Access Enabled", "SELECT s.name AS resource FROM azure_sql_server s WHERE public_network_access = 'Enabled';", "sql_server_public_network_access_enabled.csv"),
    ("Azure AD Authentication Not Enabled", "WITH sever_with_ad_admin AS (SELECT DISTINCT a.id FROM azure_sql_server AS a, jsonb_array_elements(server_azure_ad_administrator) AS ad_admin WHERE ad_admin ->> 'type' = 'Microsoft.Sql/servers/administrators') SELECT a.name AS resource FROM azure_sql_server AS a LEFT JOIN sever_with_ad_admin AS s ON a.id = s.id WHERE s.id IS NULL;", "sql_server_azure_ad_auth_not_enabled.csv"),
    ("TDE Protector Not Using Customer-Managed Key", "SELECT s.name AS resource FROM azure_sql_server s, jsonb_array_elements(encryption_protector) encryption, azure_subscription sub WHERE sub.subscription_id = s.subscription_id AND encryption ->> 'kind' = 'servicemanaged';", "tde_protector_not_cmk.csv")
]

def scan_key_vaults(resource_folder):
    """Run Steampipe scans for Key Vault misconfigurations."""
    if hasattr(scan_key_vaults, 'scans'):
        scan_resource_group(resource_folder, scan_key_vaults.scans, "KeyVaults")

scan_key_vaults.scans = [
    ("Network ACLs Configuration", "SELECT a.name AS resource FROM azure_key_vault a, azure_subscription sub WHERE (network_acls IS NULL OR network_acls ->> 'defaultAction' != 'Deny') AND sub.subscription_id = a.subscription_id", "public_network_enabled_key_vaults.csv"),
    ("Soft Delete Disabled", "SELECT name FROM azure_key_vault WHERE soft_delete_enabled IS NOT TRUE", "soft_delete_disabled.csv"),
    ("Purge Protection Status", "SELECT name FROM azure_key_vault WHERE purge_protection_enabled IS NOT TRUE", "purge_protection_disabled.csv"),
    ("Diagnostic Settings", "SELECT name FROM azure_key_vault WHERE diagnostic_settings IS NULL", "missing_diagnostics.csv")
]

def scan_postgresql_databases(resource_folder):
    """Run Steampipe scans for PostgreSQL Databases."""
    if hasattr(scan_postgresql_databases, 'scans'):
        scan_resource_group(resource_folder, scan_postgresql_databases.scans, "PostgreSQLDatabases")

scan_postgresql_databases.scans = [
    ("Log Checkpoints Configuration", "WITH log_checkpoints_on AS (SELECT id FROM azure_postgresql_flexible_server, jsonb_array_elements(flexible_server_configurations) AS config WHERE config ->> 'Name' = 'log_checkpoints' AND config ->> 'Value' = 'on') SELECT id FROM log_checkpoints_on;", "log_checkpoints_configuration.csv"),
    ("Connection Throttling Configuration", "WITH connection_throttling_off AS (SELECT id FROM azure_postgresql_flexible_server, jsonb_array_elements(flexible_server_configurations) AS config WHERE config ->> 'Name' = 'connection_throttling' AND config ->> 'Value' = 'off') SELECT id FROM connection_throttling_off;", "connection_throttling_configuration.csv"),
    ("Log Files Retention Days", "SELECT s.id AS resource FROM azure_postgresql_flexible_server s, jsonb_array_elements(flexible_server_configurations) AS config, azure_subscription sub WHERE config ->> 'Name' = 'logfiles.retention_days' AND (config -> 'ConfigurationProperties' ->> 'value')::integer <= 3 AND sub.subscription_id = s.subscription_id;", "logfiles_retention_alarm.csv")
]

def scan_mysql_databases(resource_folder):
    """Run Steampipe scans for MySQL Databases."""
    if hasattr(scan_mysql_databases, 'scans'):
        scan_resource_group(resource_folder, scan_mysql_databases.scans, "MySQLDatabases")

scan_mysql_databases.scans = [
    ("Non-compliant TLS Versions", "WITH tls_version AS (SELECT id FROM azure_mysql_flexible_server, jsonb_array_elements(flexible_server_configurations) AS config WHERE config ->> 'Name' = 'tls_version' AND config ->> 'Value' NOT IN ('TLS1_2', 'TLS1_3')) SELECT id FROM tls_version;", "tls_noncompliant_servers.csv")
]

def scan_cosmos_db(resource_folder):
    """Run Steampipe scans for Cosmos DB."""
    if hasattr(scan_cosmos_db, 'scans'):
        scan_resource_group(resource_folder, scan_cosmos_db.scans, "CosmosDB")

scan_cosmos_db.scans = [
    ("No Firewall", "SELECT name FROM azure_cosmosdb_account WHERE is_virtual_network_filter_enabled = false", "cosmosdb_no_firewall.csv")
]

def get_finding_details(finding_type: str) -> Dict:
    """Get details for a specific finding type from configuration."""
    try:
        # First check for a local finding_details.json
        config_path = Path(__file__).parent / 'finding_details.json'
        if config_path.exists():
            with open(config_path, 'r') as f:
                all_findings = json.load(f)
                return all_findings.get(finding_type, {
                    'description': f'Security finding related to {finding_type}',
                    'impact': 'This finding may impact the security of your Azure resources',
                    'recommendation': 'Review the affected resources and implement security best practices',
                    'references': [
                        {'text': 'Azure Security Best Practices', 'url': 'https://docs.microsoft.com/azure/security/fundamentals/best-practices-concepts'},
                        {'text': 'Azure Security Documentation', 'url': 'https://docs.microsoft.com/azure/security/'}
                    ]
                })
    except Exception as e:
        logging.warning(f"Could not load finding details: {e}")
    
    # Return default details if file doesn't exist or has an error
    return {
        'description': f'Security finding related to {finding_type}',
        'impact': 'This finding may impact the security of your Azure resources',
        'recommendation': 'Review the affected resources and implement security best practices',
        'references': [
            {'text': 'Azure Security Best Practices', 'url': 'https://docs.microsoft.com/azure/security/fundamentals/best-practices-concepts'},
            {'text': 'Azure Security Documentation', 'url': 'https://docs.microsoft.com/azure/security/'}
        ]
    }

def main_menu(resource_folders):
    """Interactive menu for running scans."""
    # Get tenant name directly from the first resource folder path
    first_folder = next(iter(resource_folders.values()))
    # Convert string path to Path object if it's a string
    if isinstance(first_folder, str):
        tenant_name = Path(first_folder).parts[0]  # Get the first part of the path
    else:
        tenant_name = first_folder.parent.parent.name
    
    scan_functions = {
        "Run All Scans": (run_all_scans, "All"),
        "Virtual Machines": (scan_virtual_machines, "VirtualMachines"),
        "Storage Accounts": (scan_storage_accounts, "StorageAccounts"),
        "App Services": (scan_app_services, "AppServices"),
        "Network Security Groups": (scan_network_security_groups, "NetworkSecurityGroups"),
        "SQL Databases": (scan_sql_databases, "SQLDatabases"),
        "Key Vaults": (scan_key_vaults, "KeyVaults"),
        "PostgreSQL Databases": (scan_postgresql_databases, "PostgreSQLDatabases"),
        "MySQL Databases": (scan_mysql_databases, "MySQLDatabases"),
        "Cosmos DB": (scan_cosmos_db, "CosmosDB"),
        "Generate HTML Report": (lambda: generate_html_report(tenant_name), None),
        "Help": (display_help, None),
        "Exit": (None, None)
    }
    
    while True:
        try:
            clear_screen()
            print_banner()
            choice = display_menu("Azure Security Scanner", list(scan_functions.keys()))
            
            if choice is None:  # User cancelled
                continue
                
            if 1 <= choice <= len(scan_functions):
                selected_option = list(scan_functions.items())[choice - 1]
                func, resource_type = selected_option[1]
                
                if func:
                    try:
                        if resource_type == "All":
                            func(resource_folders)
                        elif resource_type:
                            func(resource_folders[resource_type])
                        else:
                            func()
                        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                    except Exception as e:
                        handle_error(e, f"executing {selected_option[0]}")
                        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}Exiting the script. Thank you for using our service.{Style.RESET_ALL}")
                    break
            else:
                print(f"{Fore.RED}Invalid selection. Please try again.{Style.RESET_ALL}")
                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Operation cancelled by user. Returning to main menu...{Style.RESET_ALL}")
            continue
        except Exception as e:
            handle_error(e, "main menu")
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

def check_azure_login():
    """Check if already logged into Azure."""
    try:
        subprocess.run(["az", "account", "show", "--output", "none"], check=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        logging.error(f"Error checking Azure login: {str(e)}")
        return False

def clear_account_credentials():
    """Clear Azure cached account credentials."""
    print(f"{Fore.CYAN}Clearing Azure cached credentials...{Style.RESET_ALL}")
    os.system("az account clear")

def get_tenant_name():
    """Retrieve the tenant ID using Azure CLI."""
    try:
        # First check if user is logged in
        if not check_azure_login():
            print(f"{Fore.YELLOW}Please login to Azure first{Style.RESET_ALL}")
            # Try to login
            subprocess.run(["az", "login", "--output", "none"], check=True)
            
        # Now try to get tenant ID
        result = subprocess.run(
            ["az", "account", "show", "--query", "tenantId", "-o", "tsv"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        tenant_id = result.stdout.strip()
        if tenant_id:
            logging.info(f"Successfully retrieved tenant ID: {tenant_id}")
            return tenant_id
            
        raise ValueError("Empty tenant ID returned")

    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Failed to retrieve tenant ID. Please ensure you're logged in to Azure CLI.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Error details: {e.stderr.strip() if e.stderr else str(e)}{Style.RESET_ALL}")
        logging.error(f"Failed to retrieve tenant ID: {str(e)}")
        return None
    except Exception as e:
        print(f"{Fore.RED}Unexpected error retrieving tenant ID: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Unexpected error retrieving tenant ID: {str(e)}")
        return None

def initial_menu(update_needed=False, latest_version=None):
    """Initial setup menu for Azure operations."""
    resource_folders = None
    logging_configured = False
    
    while True:
        try:
            # Clear screen and print banner only once per loop
            clear_screen()
            print_banner(update_needed, latest_version)
            
            watermark = f"{Fore.LIGHTBLACK_EX}Azure Security Scanner - Confidential{Style.RESET_ALL}"
            print(f"{watermark.center(shutil.get_terminal_size().columns)}\n")

            # Show logging status
            if logging_configured:
                print(f"{Fore.GREEN}✓ Logging is configured{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}! Logging not yet configured{Style.RESET_ALL}")

            choice = display_menu("Azure Setup Menu", [
                "Clear Cached Credentials",
                "Login to Azure",
                "Choose Subscription",
                "Start Testing",
                "Exit"
            ])

            if choice == 1:  # Clear Cached Credentials
                clear_screen()
                print_banner(update_needed, latest_version)
                print(f"{Fore.CYAN}Clearing Azure cached credentials...{Style.RESET_ALL}")
                os.system("az account clear")
                print(f"{Fore.GREEN}Credentials cleared.{Style.RESET_ALL}")
                if logging_configured:
                    logging.info("Azure credentials cleared")
                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

            elif choice == 2:  # Login to Azure
                clear_screen()
                print_banner(update_needed, latest_version)
                print(f"{Fore.CYAN}Logging into Azure...{Style.RESET_ALL}")
                subprocess.run(["az", "login", "--output", "none"], check=True)
                print(f"{Fore.GREEN}Login completed.{Style.RESET_ALL}")
                if logging_configured:
                    logging.info("Azure login completed")
                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

            elif choice == 3:  # Choose Subscription
                clear_screen()
                print_banner(update_needed, latest_version)
                print(f"{Fore.CYAN}Listing Azure subscriptions...{Style.RESET_ALL}")
                
                try:
                    # First ensure we're logged in
                    if not check_azure_login():
                        print(f"{Fore.YELLOW}You need to login first. Initiating login...{Style.RESET_ALL}")
                        subprocess.run(["az", "login", "--output", "none"], check=True)
                        print(f"{Fore.GREEN}Login successful{Style.RESET_ALL}")

                    # Get the tenant name
                    tenant_name = get_tenant_name()
                    if not tenant_name:
                        print(f"{Fore.RED}Unable to retrieve tenant ID. Please ensure you're logged in correctly.{Style.RESET_ALL}")
                        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                        continue

                    # Get subscriptions
                    result = subprocess.run(
                        ["az", "account", "list", "--query", "[].{id:id, name:name}", "-o", "json"],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    
                    subscriptions = json.loads(result.stdout)
                    
                    if not subscriptions:
                        print(f"{Fore.RED}No subscriptions found. Please check your Azure permissions.{Style.RESET_ALL}")
                        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                        continue
                    
                    print(f"\n{Fore.CYAN}Available subscriptions:{Style.RESET_ALL}")
                    sub_options = [f"{sub['name']} ({sub['id']})" for sub in subscriptions]
                    sub_choice = display_menu("Select a subscription", sub_options, show_back=True)
                    
                    if sub_choice == 0:  # Back option
                        continue
                        
                    if 1 <= sub_choice <= len(subscriptions):
                        subscription = subscriptions[sub_choice - 1]
                        subscription_id = subscription["id"]
                        subscription_name = subscription["name"]
                        
                        # Set subscription
                        subprocess.run(["az", "account", "set", "--subscription", subscription_id], check=True)
                        print(f"{Fore.GREEN}Subscription set to: {subscription_name} ({subscription_id}){Style.RESET_ALL}")
                        
                        # Configure logging
                        logging_configured = configure_logging(subscription_name)
                        if logging_configured:
                            logging.info(f"Selected subscription: {subscription_name} ({subscription_id})")
                            logging.info(f"Tenant name: {tenant_name}")
                        
                        # Create folder structure using tenant name
                        resource_folders = create_folder_structure(tenant_name, subscription_name, subscription_id)
                        
                        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
                except Exception as e:
                    handle_error(e, "choosing subscription")
                    input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

            elif choice == 4:  # Start Testing
                if not check_azure_login():
                    print(f"{Fore.RED}Please login first (Option 2){Style.RESET_ALL}")
                    input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                    continue
                if resource_folders is None:
                    print(f"{Fore.RED}Please select a subscription first (Option 3){Style.RESET_ALL}")
                    input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                    continue
                if not logging_configured:
                    print(f"{Fore.RED}Logging not configured. Please select a subscription first.{Style.RESET_ALL}")
                    input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                    continue
                main_menu(resource_folders)
                
            elif choice == 5:  # Exit
                if logging_configured:
                    logging.info("Exiting script")
                print(f"{Fore.CYAN}Exiting script. Thank you for using our service.{Style.RESET_ALL}")
                sys.exit(0)
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Operation cancelled by user. Returning to main menu...{Style.RESET_ALL}")
            continue
        except Exception as e:
            handle_error(e, "initial menu")
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

def check_for_updates():
    """Check if there is a newer version of the script available on GitHub."""
    try:
        # URL to the raw version file on GitHub
        version_url = "https://raw.githubusercontent.com/D4rkm4g1c/AzureSecuritySuite/main/version.txt"
        
        # Fetch the latest version from GitHub
        response = requests.get(version_url)
        response.raise_for_status()
        
        # Extract version number from response
        latest_version_line = response.text.strip()
        if latest_version_line.startswith('__version__'):
            # Extract the version number from the line
            latest_version = latest_version_line.split('=')[1].strip().strip('"\'')
        else:
            raise ValueError("Unexpected version format in version.txt")
        
        # Convert versions to tuples for proper comparison
        current_ver = tuple(map(int, __version__.split('.')))
        latest_ver = tuple(map(int, latest_version.split('.')))
        
        if latest_ver > current_ver:
            print(f"{Fore.YELLOW}A new version ({latest_version}) is available!{Style.RESET_ALL}")
            print(f"Run the script with --update to download the latest version.")
            return (True, latest_version)
        else:
            print(f"{Fore.GREEN}You are using the latest version ({__version__}).{Style.RESET_ALL}")
            return (False, latest_version)
            
    except requests.RequestException as e:
        print(f"{Fore.RED}Failed to check for updates: {str(e)}{Style.RESET_ALL}")
        return (False, None)
    except ValueError as e:
        print(f"{Fore.RED}Error parsing version: {str(e)}{Style.RESET_ALL}")
        return (False, None)

def update_script():
    """Download the latest version of the script from GitHub."""
    try:
        # First get the latest version number
        version_url = "https://raw.githubusercontent.com/D4rkm4g1c/AzureSecuritySuite/main/version.txt"
        version_response = requests.get(version_url)
        version_response.raise_for_status()
        latest_version = version_response.text.strip().split('=')[1].strip().strip('"\'')
        
        # URL to the raw script file on GitHub
        script_url = "https://raw.githubusercontent.com/D4rkm4g1c/AzureSecuritySuite/main/AzureSecuritySuite.py"
        
        # Get the directory of the current script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_name = os.path.basename(__file__)
        
        # Create paths for temporary and backup files
        temp_file = os.path.join(script_dir, f"{script_name}.tmp")
        backup_file = os.path.join(script_dir, f"{script_name}.backup")
        
        print(f"{Fore.CYAN}Downloading latest version...{Style.RESET_ALL}")
        
        # Fetch the latest script from GitHub with proper encoding
        response = requests.get(script_url)
        response.raise_for_status()
        content = response.content.decode('utf-8')
        
        # Update the version number in the content
        content = content.replace('__version__ = "0.0.1"', f'__version__ = "{latest_version}"')
        
        # Backup existing file first
        print(f"{Fore.CYAN}Creating backup...{Style.RESET_ALL}")
        shutil.copy2(__file__, backup_file)
        
        # Write new content to temporary file
        print(f"{Fore.CYAN}Writing new version...{Style.RESET_ALL}")
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write(content)
            
        # Replace the old file with the new version
        print(f"{Fore.CYAN}Installing update...{Style.RESET_ALL}")
        os.replace(temp_file, __file__)
        
        print(f"{Fore.GREEN}✓ Script updated successfully to version {latest_version}!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✓ Backup created at: {backup_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please restart the script to use the new version.{Style.RESET_ALL}")
        sys.exit(0)
        
    except requests.RequestException as e:
        print(f"{Fore.RED}Failed to download update: {str(e)}{Style.RESET_ALL}")
        if os.path.exists(temp_file):
            os.remove(temp_file)
    except Exception as e:
        print(f"{Fore.RED}Error during update: {str(e)}{Style.RESET_ALL}")
        if os.path.exists(temp_file):
            os.remove(temp_file)
        print(f"{Fore.YELLOW}Your backup file is available at: {backup_file}{Style.RESET_ALL}")

def display_help():
    """Display help information for menu options."""
    help_info = f"""
{Fore.CYAN}Azure Security Scanner Help{Style.RESET_ALL}

{Fore.GREEN}Available Scan Options:{Style.RESET_ALL}
• Run All Scans - Execute all security scans in sequence
• Virtual Machines - Check VM security configurations and vulnerabilities
• Storage Accounts - Analyze storage account security settings
• App Services - Review web and function app security settings
• Network Security Groups - Examine NSG rules and configurations
• SQL Databases - Check SQL database security settings
• Key Vaults - Analyze Key Vault access and security configurations
• PostgreSQL Databases - Review PostgreSQL security settings
• MySQL Databases - Check MySQL database security configurations
• Cosmos DB - Examine Cosmos DB security settings

{Fore.GREEN}Setup Options:{Style.RESET_ALL}
• Clear Cached Credentials - Remove stored Azure credentials
• Login to Azure - Authenticate with Azure CLI
• Choose Subscription - Select an Azure subscription to scan

{Fore.GREEN}Navigation:{Style.RESET_ALL}
• Use numbers to select menu options
• Press Ctrl+C to cancel operations
 Select 'Exit' to quit the program

{Fore.GREEN}For more information:{Style.RESET_ALL}
• Check the logs in the 'azuresecuritysuitelogs' directory
• Visit the GitHub repository for updates and documentation
• Report issues on the GitHub issue tracker
"""
    print(help_info)
    logging.info("Help information displayed")
    input(f"\n{Fore.CYAN}Press Enter to return to the menu...{Style.RESET_ALL}")

def main():
    """Main function to start the script."""
    try:
        update_needed, latest_version = check_for_updates()
        
        # Even if an update is available, we should still allow the script to run
        if update_needed:
            print(f"{Fore.YELLOW}Note: A new version ({latest_version}) is available. You can update using --update flag.{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}You are running the latest version ({__version__}).{Style.RESET_ALL}")
        
        # Continue with script execution regardless of update status
        logging.info("Starting Azure Security Scanner.")
        initial_menu(update_needed, latest_version)
        
    except Exception as e:
        print(f"{Fore.RED}Error starting the script: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error starting the script: {str(e)}")

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description='Azure Security Scanner')
    parser.add_argument('--update', action='store_true', help='Update the script to the latest version')
    args = parser.parse_args()

    if args.update:
        update_script()
    else:
        main()  # Call the main function to start the script
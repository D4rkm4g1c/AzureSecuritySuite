# -*- coding: utf-8 -*-
"""
AzureSecuritySuite - Azure Security Scanner
Copyright (c) 2025 D4rkm4g1c. All Rights Reserved.

PROPRIETARY SOFTWARE - PERSONAL INTELLECTUAL PROPERTY
This software was developed independently during personal time.
No employer or company has any rights to this software.

For licensing inquiries, contact the copyright holder.
"""
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
from typing import Dict, List, Tuple, Optional
from report_generator import generate_html_report
import yaml
import traceback

# Set up logging at the start of your script
logging.basicConfig(
    filename='azure_security_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Initialize colorama for cross-platform color support
init(autoreset=True) 

# Create logs directory if it doesn't exist
log_dir = 'azuresecuritysuitelogs'
os.makedirs(log_dir, exist_ok=True)

def download_version_file():
    """Download version.txt from GitHub repository."""
    try:
        # GitHub raw content URL for version.txt
        version_url = "https://raw.githubusercontent.com/D4rkm4g1c/AzureSecuritySuite/main/version.txt"
        
        print(f"{Fore.CYAN}Downloading version.txt from repository...{Style.RESET_ALL}")
        response = requests.get(version_url)
        response.raise_for_status()  # Raise exception for bad status codes
        
        # Save to the same directory as the script
        version_file = os.path.join(os.path.dirname(__file__), 'version.txt')
        with open(version_file, 'w') as f:
            f.write(response.text)
            
        print(f"{Fore.GREEN}✓ Successfully downloaded version.txt{Style.RESET_ALL}")
        return True
        
    except requests.RequestException as e:
        logging.error(f"Failed to download version.txt: {str(e)}")
        return False

def get_version():
    """Load version and date from version.txt or return defaults."""
    try:
        # Try multiple possible locations for version.txt
        possible_paths = [
            os.path.join(os.path.dirname(__file__), 'version.txt'),  # Same directory as script
            'version.txt',  # Current working directory
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'version.txt'),  # Absolute path
        ]
        
        for version_file in possible_paths:
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    version = None
                    date = None
                    for line in f:
                        if line.startswith('__version__'):
                            version = line.split('=')[1].strip().strip('"\'')
                        elif line.startswith('# v') and not date:  # Get date from first version entry
                            try:
                                date = line.split('(')[1].split(')')[0].strip()
                            except IndexError:
                                continue
                        if version and date:
                            logging.info(f"Version {version} ({date}) loaded from {version_file}")
                            return version, date
        
        # If version.txt doesn't exist or is invalid, create it with default values
        default_version = "1.0.1"
        default_date = datetime.now().strftime("%d-%m-%Y")
        version_file = possible_paths[0]  # Use the first path (same directory as script)
        try:
            with open(version_file, 'w') as f:
                f.write(f'__version__ = "{default_version}"\n\n')
                f.write("# Changelog\n")
                f.write("# ---------\n")
                f.write(f"# v{default_version} ({default_date})\n")
                f.write("# - Added dark mode toggle with color scheme (#444444, #bcd03e, #ffffff)\n")
                f.write("# - Removed severity indicators (pending implementation)\n")
                f.write("# - Enhanced report styling with new green theme (#b0d351)\n")
                f.write("# - Simplified header design\n")
                f.write("# - Improved executive summary layout\n")
                f.write("# - Added consistent styling across all report sections\n")
            logging.info(f"Created new version.txt with version {default_version} ({default_date})")
            return default_version, default_date
        except Exception as write_error:
            logging.error(f"Failed to create version.txt: {write_error}")
            return default_version, default_date
            
    except Exception as e:
        logging.warning(f"Could not load version from file: {e}")
        return "1.0.1", datetime.now().strftime("%d-%m-%Y")

# Load version and date at module level
__version__, __version_date__ = get_version()

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
║{Style.BRIGHT + Fore.GREEN + f' Version {__version__} ({__version_date__})'.center(terminal_width-2)}║"""

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

    # Wait for user input before continuing
    input(f"\n{Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

def display_menu(title, options, prompt="Select an option: ", show_back=False):
    """Display a menu with a title and options."""
    logging.info(f"Displaying menu: {title}")
    
    # Add version and date to title
    title_with_version = f"{title} (v{__version__} - {__version_date__})"
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{title_with_version}:{Style.RESET_ALL}")
    
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
            "csv"
        ]
        logging.info(f"Executing Steampipe command: {' '.join(steampipe_cmd)}")
        print(f"\n{Fore.CYAN}Executing query...{Style.RESET_ALL}")
        
        # Execute the command and capture output
        process = subprocess.run(steampipe_cmd, 
                             capture_output=True,
                             text=True,
                             check=True)
        
        # Split output into lines and remove empty lines
        output_lines = [line.strip() for line in process.stdout.splitlines() if line.strip()]
        
        if output_lines:
            # Skip header row and keep all other lines
            results = output_lines[1:]  # Skip header, keep everything else
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Write results
            with open(output_file, 'w', newline='') as f:
                f.write('\n'.join(results))
            
            print(f"{Fore.GREEN}✓ Results saved to: {output_file} ({len(results)} resources found){Style.RESET_ALL}")
            logging.info(f"Query executed successfully. Found {len(results)} resources.")
            return True
        else:
            print(f"{Fore.YELLOW}! No results found for query{Style.RESET_ALL}")
            logging.info("Query executed successfully but returned no results")
            return True
            
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}✗ Query execution failed: {e.stderr}{Style.RESET_ALL}")
        logging.error(f"Query execution failed with error: {e.stderr}")
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

def write_vuln_overview(vuln_overview: Dict[str, set], resource_folder: str, scan_type: str) -> None:
    """Write vulnerability overview file in a table format with all vulnerabilities listed per resource."""
    try:
        # Create the overview file in the resource type directory
        overview_file = os.path.join(resource_folder, f"{scan_type}_vulnerability_overview.csv")
        
        logging.info(f"Writing overview to: {overview_file}")
        print(f"{Fore.CYAN}Writing overview to: {overview_file}{Style.RESET_ALL}")
        
        # Write the overview file with headers matching the desired format
        with open(overview_file, 'w', newline='') as f:
            writer = csv.writer(f)
            # Write headers
            writer.writerow(["Resource", "Vulnerabilities"])
            
            # Write each resource and its vulnerabilities
            for resource, vulns in vuln_overview.items():
                # Sort vulnerabilities and join with semicolons
                vuln_list = ";".join(sorted(vulns))
                writer.writerow([resource, vuln_list])
                
                logging.info(f"Added resource to overview: {resource} with {len(vulns)} findings")
        
        print(f"{Fore.GREEN}✓ Overview file written: {overview_file}{Style.RESET_ALL}")
        logging.info(f"Completed writing vulnerability overview to {overview_file}")
        
    except Exception as e:
        print(f"{Fore.RED}Error writing overview file: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Failed to write vulnerability overview: {str(e)}")

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
        
        # Map folder names to their corresponding YAML files - exact filename matches
        resource_types = {
            "VirtualMachines": "virtual_machines",
            "StorageAccounts": "storage_accounts",
            "AppServices": "app_services",
            "NetworkSecurityGroups": "network_security_groups",
            "SQLDatabases": "sql_databases",
            "KeyVaults": "key_vaults",
            "PostgreSQLDatabases": "postgresql_databases",
            "MySQLDatabases": "mysql_databases",
            "CosmosDB": "cosmos_databases"
        }
        
        total_scans = 0
        successful_scans = 0
        
        for folder_name, yaml_name in resource_types.items():
            if folder_name in resource_folders:
                print(f"\n{Fore.CYAN}Running {folder_name} scans...{Style.RESET_ALL}")
                try:
                    scans = load_scan_definitions(yaml_name)
                    if scans and isinstance(scans, dict):  # Ensure scans is a dictionary
                        total_scans += len(scans.get('scans', []))
                        if 'scans' in scans:
                            for scan in scans['scans']:
                                try:
                                    # Access dictionary values using keys
                                    name = scan.get('name', 'Unnamed scan')
                                    query = scan.get('query', '')
                                    output_file = scan.get('output_file', '')
                                    
                                    if query and output_file:
                                        output_path = os.path.join(resource_folders[folder_name], output_file)
                                        if run_steampipe_query(query, output_path):
                                            successful_scans += 1
                                            print(f"{Fore.GREEN}✓ {name} completed successfully{Style.RESET_ALL}")
                                        else:
                                            print(f"{Fore.RED}✗ {name} failed{Style.RESET_ALL}")
                                except Exception as e:
                                    print(f"{Fore.RED}Error in scan {name}: {str(e)}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}No scans found for {folder_name} in {yaml_name}.yaml{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error running {folder_name} scans: {str(e)}{Style.RESET_ALL}")
                    
        print(f"\n{Fore.CYAN}Scan Summary:{Style.RESET_ALL}")
        print(f"Total Scans: {total_scans}")
        print(f"Successful: {successful_scans}")
        print(f"Failed: {total_scans - successful_scans}")
        
        if successful_scans == total_scans:
            print(f"\n{Fore.GREEN}✓ All scans completed successfully{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}! Some scans failed. Check the output above for details{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}Error running all scans: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error running all scans: {str(e)}")

def display_scan_submenu(scans, resource_type):
    """Display submenu for selecting specific scans."""
    try:
        logging.info(f"Displaying scan submenu for {resource_type}")
        print(f"\n{Fore.CYAN}Available {resource_type} Scans:{Style.RESET_ALL}")
        
        options = ["Run All Scans"]
        
        # Log scan data structure
        logging.info(f"Scan data structure: {json.dumps(scans, indent=2)}")
        
        # Add Steampipe scans
        if 'scans' in scans:
            for scan in scans['scans']:
                scan_name = scan.get('name', 'Unknown scan')
                options.append(f"Steampipe: {scan_name}")
                logging.info(f"Added Steampipe scan option: {scan_name}")
                
        # Add CLI scans
        if 'cli_scans' in scans:
            for scan in scans['cli_scans']:
                scan_name = scan.get('name', 'Unknown scan')
                options.append(f"CLI: {scan_name}")
                logging.info(f"Added CLI scan option: {scan_name}")
        
        logging.info(f"Total menu options: {len(options)}")
        
        choice = display_menu(f"Select {resource_type} Scan", options, show_back=True)
        logging.info(f"User selected option: {choice}")
        
        if choice is None or choice == 0:
            return None
            
        if choice == 1:
            return scans
        elif 1 < choice <= len(options):
            selected_index = choice - 2
            steampipe_count = len(scans.get('scans', []))
            
            if selected_index < steampipe_count:
                return {'scans': [scans['scans'][selected_index]], 'cli_scans': []}
            else:
                cli_index = selected_index - steampipe_count
                return {'scans': [], 'cli_scans': [scans['cli_scans'][cli_index]]}
        else:
            logging.error(f"Invalid selection: {choice}")
            return None
            
    except Exception as e:
        logging.error(f"Error in display_scan_submenu: {str(e)}")
        logging.error(traceback.format_exc())
        return None

def scan_resource_group(resource_folder: str, scan_type: str) -> None:
    """Run scans for a resource group using both Steampipe and Azure CLI."""
    try:
        print(f"\n{Fore.CYAN}Scanning resource folder: {resource_folder}{Style.RESET_ALL}")
        
        # Load scan definitions
        all_scans = load_scan_definitions(scan_type)
        
        if not all_scans:
            print(f"{Fore.RED}No scan definitions loaded{Style.RESET_ALL}")
            return

        # Create menu options
        options = ["Run All Scans"]
        scan_mapping = []  # Keep track of scan type and index
        
        # Add Steampipe scans
        for scan in all_scans.get('scans', []):
            options.append(f"Steampipe: {scan['name']}")
            scan_mapping.append(('steampipe', len(scan_mapping)))
            
        # Add CLI scans
        for scan in all_scans.get('cli_scans', []):
            options.append(f"CLI: {scan['name']}")
            scan_mapping.append(('cli', len(scan_mapping)))
        
        print(f"\n{Fore.MAGENTA}DEBUG: Menu Options:{Style.RESET_ALL}")
        for i, option in enumerate(options):
            print(f"{i+1}. {option}")
            
        print(f"\n{Fore.MAGENTA}DEBUG: Scan Mapping:{Style.RESET_ALL}")
        print(json.dumps(scan_mapping, indent=2))

        # Display menu
        choice = display_menu(f"Select {scan_type} Scan", options, show_back=True)
        
        if choice is None or choice == 0:  # User cancelled or selected back
            return
            
        if choice == 1:  # Run All selected
            print(f"\n{Fore.MAGENTA}DEBUG: Running all scans{Style.RESET_ALL}")
            # Run all Steampipe scans
            for scan in all_scans.get('scans', []):
                output_file = os.path.join(resource_folder, scan['output_file'])
                print(f"\nRunning Steampipe scan: {scan['name']}")
                run_steampipe_query(scan['query'], output_file)
                
            # Run all CLI scans
            for scan in all_scans.get('cli_scans', []):
                output_file = os.path.join(resource_folder, scan['output_file'])
                print(f"\nRunning CLI scan: {scan['name']}")
                run_cli_query(scan['query'], output_file)
        else:
            # Get selected scan
            selected_index = choice - 2  # -2 because we added "Run All" at the beginning
            if selected_index < len(scan_mapping):
                scan_type, scan_index = scan_mapping[selected_index]
                
                if scan_type == 'steampipe':
                    scan = all_scans['scans'][scan_index]
                    output_file = os.path.join(resource_folder, scan['output_file'])
                    print(f"\nRunning Steampipe scan: {scan['name']}")
                    run_steampipe_query(scan['query'], output_file)
                else:  # CLI scan
                    scan = all_scans['cli_scans'][scan_index]
                    output_file = os.path.join(resource_folder, scan['output_file'])
                    print(f"\nRunning CLI scan: {scan['name']}")
                    run_cli_query(scan['query'], output_file)

    except Exception as e:
        print(f"{Fore.RED}Error in scan_resource_group: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error in scan_resource_group: {str(e)}")
        traceback.print_exc()  # Print full stack trace

def _process_scan_results(output_file, scan_name, vuln_overview):
    """Process scan results and add them to the vulnerability overview."""
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            # Skip the header line and get non-empty lines
            lines = [line.strip() for line in f.readlines()[1:] if line.strip()]
            if lines:
                print(f"{Fore.GREEN}Found resources: {lines}{Style.RESET_ALL}")
                for resource in lines:
                    if resource not in vuln_overview:
                        vuln_overview[resource] = set()
                    vuln_overview[resource].add(scan_name)
                print(f"{Fore.RED}! Found {len(lines)} vulnerable resources{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}No vulnerable resources found in {output_file}{Style.RESET_ALL}")

def load_scan_definitions(resource_type):
    """Load scan definitions from YAML file."""
    try:
        # Construct path to the YAML file
        yaml_file = os.path.join('scans', f'{resource_type}.yaml')
        
        if not os.path.exists(yaml_file):
            print(f"{Fore.YELLOW}No scan definitions found at {yaml_file}{Style.RESET_ALL}")
            return None
            
        with open(yaml_file, 'r') as f:
            scan_data = yaml.safe_load(f)
            
        if not scan_data or not isinstance(scan_data, dict):
            print(f"{Fore.YELLOW}Invalid YAML format in {yaml_file}{Style.RESET_ALL}")
            return None
            
        # Validate the structure
        if 'scans' not in scan_data:
            print(f"{Fore.YELLOW}No 'scans' key found in {yaml_file}{Style.RESET_ALL}")
            return None
            
        # Return the entire scan_data dictionary
        return scan_data
        
    except yaml.YAMLError as e:
        print(f"{Fore.RED}Error parsing YAML file {yaml_file}: {str(e)}{Style.RESET_ALL}")
        return None
    except Exception as e:
        print(f"{Fore.RED}Error loading scan definitions: {str(e)}{Style.RESET_ALL}")
        return None

def run_cli_query(query, output_file):
    """Run an Azure CLI query and save the output to a file."""
    try:
        print(f"\n{Fore.CYAN}Executing CLI query...{Style.RESET_ALL}")
        
        # Check if this is a shell script
        if query.strip().startswith('#!/bin/bash'):
            # Create a temporary shell script
            temp_script = 'temp_script.sh'
            
            try:
                # Write the script
                with open(temp_script, 'w') as f:
                    f.write(query)
                
                # Make it executable
                os.chmod(temp_script, 0o755)
                
                # Execute the script
                print(f"{Fore.CYAN}Executing shell script...{Style.RESET_ALL}")
                process = subprocess.run(
                    f'./{temp_script}',
                    shell=True,
                    capture_output=True,
                    text=True
                )
                
                if process.returncode != 0:
                    print(f"{Fore.RED}Script execution failed: {process.stderr}{Style.RESET_ALL}")
                    return False
                
            finally:
                # Clean up temporary script
                if os.path.exists(temp_script):
                    os.remove(temp_script)
        else:
            # Regular Azure CLI command
            process = subprocess.run(
                query,
                shell=True,
                capture_output=True,
                text=True
            )
            
            if process.returncode != 0:
                print(f"{Fore.RED}Command execution failed: {process.stderr}{Style.RESET_ALL}")
                return False
        
        # Process output
        if process.stdout:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Write results
            with open(output_file, 'w', newline='') as f:
                f.write(process.stdout)
            
            print(f"{Fore.GREEN}✓ Results saved to: {output_file}{Style.RESET_ALL}")
            logging.info(f"CLI query executed successfully")
            return True
        else:
            print(f"{Fore.YELLOW}! No results found{Style.RESET_ALL}")
            return True
            
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Exception in CLI query: {str(e)}")
        return False

def scan_virtual_machines(resource_folder):
    """Run Steampipe scans for virtual machines."""
    scan_resource_group(resource_folder, 'virtual_machines')

def scan_storage_accounts(resource_folder):
    """Run Steampipe scans for storage accounts."""
    scan_resource_group(resource_folder, 'storage_accounts')

def scan_network_security_groups(resource_folder):
    """Run Steampipe scans for network security groups."""
    scan_resource_group(resource_folder, 'network_security_groups')

def scan_sql_databases(resource_folder):
    """Run Steampipe scans for SQL databases."""
    scan_resource_group(resource_folder, 'sql_databases')

def scan_key_vaults(resource_folder):
    """Run Steampipe scans for key vaults."""
    scan_resource_group(resource_folder, 'key_vaults')

def scan_postgresql_databases(resource_folder):
    """Run Steampipe scans for PostgreSQL databases."""
    scan_resource_group(resource_folder, 'postgresql_databases')

def scan_mysql_databases(resource_folder):
    """Run Steampipe scans for MySQL databases."""
    scan_resource_group(resource_folder, 'mysql_databases')

def scan_app_services(resource_folder):
    """Run Steampipe scans for app services."""
    scan_resource_group(resource_folder, 'app_services')

def scan_cosmos_db(resource_folder):
    """Run Steampipe scans for Cosmos DB."""
    scan_resource_group(resource_folder, 'cosmos_databases')

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
            
            watermark = f"{Fore.LIGHTBLACK_EX}Azure Security Scanner v{__version__} ({__version_date__}) - Confidential{Style.RESET_ALL}"
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
        # Download and check the latest version file
        version_url = "https://raw.githubusercontent.com/D4rkm4g1c/AzureSecuritySuite/main/version.txt"
        response = requests.get(version_url)
        response.raise_for_status()
        
        # Parse the latest version from GitHub
        latest_version = None
        for line in response.text.splitlines():
            if line.startswith('__version__'):
                latest_version = line.split('=')[1].strip().strip('"\'')
                break
                
        if not latest_version:
            raise ValueError("Could not find version in remote version.txt")
            
        print(f"{Fore.CYAN}Current version: {__version__}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Latest version: {latest_version}{Style.RESET_ALL}")
            
        # Convert versions to tuples for proper comparison
        current_ver = tuple(map(int, __version__.split('.')))
        latest_ver = tuple(map(int, latest_version.split('.')))
        
        if latest_ver > current_ver:
            print(f"{Fore.YELLOW}A new version ({latest_version}) is available!{Style.RESET_ALL}")
            print(f"Run the script with --update to download the latest version.")
            return (True, latest_version)
        elif latest_ver < current_ver:
            print(f"{Fore.YELLOW}Warning: Local version ({__version__}) is ahead of repository version ({latest_version}){Style.RESET_ALL}")
            return (False, latest_version)
        else:
            print(f"{Fore.GREEN}You are using the latest version ({__version__}).{Style.RESET_ALL}")
            return (False, latest_version)
            
    except Exception as e:
        print(f"{Fore.RED}Failed to check for updates: {str(e)}{Style.RESET_ALL}")
        return (False, None)

def update_script():
    """Download the latest version of the script and associated files from GitHub."""
    try:
        base_url = "https://raw.githubusercontent.com/D4rkm4g1c/AzureSecuritySuite/main"
        files_to_update = {
            'version.txt': 'version.txt',
            'AzureSecuritySuite.py': os.path.basename(__file__),
            'report_generator.py': 'report_generator.py'
        }
        
        # Add YAML scan definition files
        yaml_files = [
            'scans/virtual_machines.yaml',
            'scans/storage_accounts.yaml',
            'scans/app_services.yaml',
            'scans/network_security_groups.yaml',
            'scans/sql_databases.yaml',
            'scans/key_vaults.yaml',
            'scans/postgresql_databases.yaml',
            'scans/mysql_databases.yaml',
            'scans/cosmos_databases.yaml'
        ]
        
        # Add YAML files to the update list
        for yaml_file in yaml_files:
            files_to_update[yaml_file] = yaml_file

        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        print(f"{Fore.CYAN}Starting update process...{Style.RESET_ALL}")
        
        # Create backups directory
        backup_dir = os.path.join(script_dir, 'backups', datetime.now().strftime('%Y%m%d_%H%M%S'))
        os.makedirs(backup_dir, exist_ok=True)
        
        # Download and update each file
        for filename, local_name in files_to_update.items():
            try:
                file_url = f"{base_url}/{filename}"
                response = requests.get(file_url)
                response.raise_for_status()
                
                local_path = os.path.join(script_dir, local_name)
                temp_path = local_path + '.tmp'
                backup_path = os.path.join(backup_dir, local_name)
                
                # Create directory structure if needed (for YAML files in subdirectories)
                os.makedirs(os.path.dirname(local_path), exist_ok=True)
                os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                
                # Create backup if file exists
                if os.path.exists(local_path):
                    print(f"{Fore.CYAN}Backing up {local_name}...{Style.RESET_ALL}")
                    shutil.copy2(local_path, backup_path)
                
                # Write new content
                print(f"{Fore.CYAN}Updating {local_name}...{Style.RESET_ALL}")
                with open(temp_path, 'wb') as f:
                    f.write(response.content)
                
                # Replace old file with new version
                os.replace(temp_path, local_path)
                
            except Exception as e:
                print(f"{Fore.RED}Failed to update {filename}: {str(e)}{Style.RESET_ALL}")
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                continue
        
        print(f"{Fore.GREEN}✓ Update completed successfully!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✓ Backups created in: {backup_dir}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please restart the script to use the new version.{Style.RESET_ALL}")
        sys.exit(0)
        
    except Exception as e:
        print(f"{Fore.RED}Error during update: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Your backups are available in: {backup_dir}{Style.RESET_ALL}")

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
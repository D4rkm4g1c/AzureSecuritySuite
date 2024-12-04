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
        print(f"\n{Fore.CYAN}Setting up logging...{Style.RESET_ALL}")
        print(f"Log file will be created at: {log_filepath}")
        
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

def print_banner():
    """Display a professional and colorful banner with ASCII art."""
    clear_screen()
    terminal_width = shutil.get_terminal_size().columns
    ascii_art = r"""
     ___                           ___                                                              
    (   )                         (   )                                                             
  .-.| |       ,--.    ___ .-.     | |   ___    ___ .-. .-.        ,--.     .--.    .--.    .--.    
 /   \ |      /   |   (   )   \    | |  (   )  (   )   '   \      /   |    /    \  (_  |   /    \   
|  .-. |     / .' |    | ' .-. ;   | |  ' /     |  .-.  .-. ;    / .' |   ;  ,-. '   | |  |  .-. ;  
| |  | |    / / | |    |  / (___)  | |,' /      | |  | |  | |   / / | |   | |  | |   | |  |  |(___) 
| |  | |   / /  | |    | |         | .  '.      | |  | |  | |  / /  | |   | |  | |   | |  |  |      
| |  | |  /  `--' |-.  | |         | | `. \     | |  | |  | | /  `--' |-. | |  | |   | |  |  | ___  
| '  | |  `-----| |-'  | |         | |   \ \    | |  | |  | | `-----| |-' | '  | |   | |  |  '(   ) 
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
║{Style.BRIGHT + Fore.GREEN + f' Version 1.0 - 2024-12-03'.center(terminal_width-2)}║
║{' ' * (terminal_width-2)}║
╚{'═' * (terminal_width-2)}╝{Style.RESET_ALL}
"""
    print(banner)

def display_menu(title, options, prompt="Select an option: ", show_back=False):
    """Display a menu with a title and options."""
    clear_screen()
    print_banner()
    logging.info(f"Displaying menu: {title}")
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{title}:{Style.RESET_ALL}")
    for idx, option in enumerate(options, 1):
        print(f"{Fore.GREEN}{idx}.{Style.RESET_ALL} {option}")
    if show_back:
        print(f"{Fore.RED}0.{Style.RESET_ALL} Back to Previous Menu")
    
    while True:
        choice = input(f"{Fore.YELLOW}{prompt}{Style.RESET_ALL}")
        if choice.isdigit():
            return int(choice)
        else:
            print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")

def show_spinner(text):
    """Show a spinner while processing."""
    spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
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
        spinner = show_spinner("Processing query")
        
        # Show spinner while query is running
        process = subprocess.Popen(steampipe_cmd, 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE, 
                                   text=True)
        
        try:
            while process.poll() is None:
                next(spinner)
                time.sleep(0.1)
        except KeyboardInterrupt:
            process.terminate()
            raise
        
        stdout, stderr = process.communicate()
        print('\r', end='')  # Clear spinner line
        
        if process.returncode == 0:
            resources = [r.strip().rstrip('%') for r in stdout.splitlines() if r.strip()]
            formatted_output = ", ".join(resources)
            
            with open(output_file, 'w') as f:
                f.write(formatted_output)
            
            print(f"{Fore.GREEN}✓ Results saved to: {output_file}{Style.RESET_ALL}")
            logging.info(f"Query executed successfully. Found {len(resources)} resources.")
            logging.info(f"Results saved to: {output_file}")
            return True
        else:
            print(f"{Fore.RED}✗ Query execution failed: {stderr}{Style.RESET_ALL}")
            logging.error(f"Query execution failed with error: {stderr}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Exception occurred while executing query: {str(e)}")
        return False

def create_folder_structure(tenant_name, subscription_name, subscription_id):
    """Create the folder structure for the tenant and subscription."""
    tenant_folder = os.path.join(".", tenant_name)
    os.makedirs(tenant_folder, exist_ok=True)

    subscription_folder_name = f"{subscription_name} ({subscription_id})"
    subscription_folder = os.path.join(tenant_folder, subscription_folder_name)
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

    print(f"{Fore.GREEN}Folder structure created successfully.{Style.RESET_ALL}")
    return resource_folders

def write_vuln_overview(vuln_overview, resource_folder, resource_type):
    """Write the vulnerability overview to a CSV file in the resource folder."""
    output_file = os.path.join(resource_folder, f"{resource_type}_vulnerability_overview.csv")
    with open(output_file, 'w') as f:
        f.write("Resource Name,Vulnerabilities Found\n")
        for resource, vulns in vuln_overview.items():
            f.write(f"{resource},{', '.join(vulns)}\n")
    print(f"{Fore.GREEN}✓ Vulnerability overview for {resource_type} saved to: {output_file}{Style.RESET_ALL}")

def run_scans(resource_folder, scans, scan_type):
    """Execute all scans for a given resource type."""
    print(f"\n{Fore.CYAN}Running {scan_type} scans...{Style.RESET_ALL}")
    logging.info(f"Starting scans for {scan_type}")
    logging.info("=" * 50)  # Add visual separator in logs
    vuln_overview = {}  # Dictionary to store vulnerabilities for this resource type
    
    for scan_name, query, output_file in scans:
        try:
            print(f"\nExecuting: {scan_name}")
            logging.info(f"\nExecuting Scan: {scan_name}")
            logging.info(f"SQL Query: {query}")
            full_output_path = os.path.join(resource_folder, output_file)
            
            # Run the query and get results
            process = subprocess.Popen(
                ["steampipe", "query", query, "--output", "csv", "--header=false"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                # Process the results
                resources = [r.strip() for r in stdout.splitlines() if r.strip()]
                
                # Write to individual scan file
                with open(full_output_path, 'w') as f:
                    f.write(", ".join(resources))
                
                # Update vulnerability overview
                for resource in resources:
                    if resource not in vuln_overview:
                        vuln_overview[resource] = []
                    vuln_overview[resource].append(scan_name)
                
                print(f"{Fore.GREEN}✓ Results saved to: {output_file}{Style.RESET_ALL}")
                logging.info(f"Scan completed successfully")
                logging.info(f"Found {len(resources)} vulnerable resources")
                logging.info(f"Results saved to: {full_output_path}")
            else:
                print(f"{Fore.RED}✗ Query execution failed: {stderr}{Style.RESET_ALL}")
                logging.error(f"Query execution failed: {stderr}")
                
        except Exception as e:
            print(f"{Fore.RED}Error in {scan_name}: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Error in {scan_name}: {str(e)}")
        
        logging.info("-" * 30)  # Add separator between scans
    
    # Write vulnerability overview for this resource type
    if vuln_overview:
        write_vuln_overview(vuln_overview, resource_folder, scan_type)
        logging.info(f"Vulnerability overview written for {scan_type}")
        logging.info(f"Total resources with vulnerabilities: {len(vuln_overview)}")
    
    print(f"{Fore.GREEN}✓ {scan_type} scans completed{Style.RESET_ALL}")
    logging.info(f"All {scan_type} scans completed")
    logging.info("=" * 50)  # Add visual separator in logs

def scan_virtual_machines(resource_folder):
    """Run Steampipe scans for virtual machines."""
    scans = [
        ("Unmanaged Disks", "SELECT vm.name FROM azure_compute_virtual_machine AS vm, azure_subscription AS sub WHERE sub.subscription_id = vm.subscription_id AND managed_disk_id IS NULL", "unmanaged_disks.csv"),
        ("Unencrypted Disks", "SELECT disk.name FROM azure_compute_disk AS disk, azure_subscription AS sub WHERE disk_state != 'Attached' AND sub.subscription_id = disk.subscription_id AND encryption_type != 'EncryptionAtRestWithCustomerKey'", "unencrypted_disks.csv")
    ]
    run_scans(resource_folder, scans, "VirtualMachines")

def scan_storage_accounts(resource_folder):
    """Run Steampipe scans for storage accounts."""
    scans = [
        ("Public Blob Access Enabled", "SELECT name FROM azure_storage_account WHERE allow_blob_public_access = true", "public_blob_access.csv"),
        ("Soft Delete Disabled", "SELECT name FROM azure_storage_account WHERE blob_soft_delete_enabled = false", "soft_delete_disabled.csv"),
        ("Network Default Allow", "SELECT name FROM azure_storage_account WHERE network_rule_default_action = 'Allow'", "network_default_allow.csv"),
        ("Infrastructure Encryption Disabled", "SELECT name FROM azure_storage_account WHERE require_infrastructure_encryption IS NOT TRUE", "infrastructure_encryption.csv"),
        ("HTTPS Traffic Only Disabled", "SELECT name FROM azure_storage_account WHERE enable_https_traffic_only = 'False'", "https_traffic_only.csv"),
        ("Insecure TLS Version", "SELECT name FROM azure_storage_account WHERE minimum_tls_version IN ('TLS1_0', 'TLS1_1')", "tls_version.csv"),
        ("Blob Versioning Disabled", "SELECT name FROM azure_storage_account WHERE blob_versioning_enabled IS NOT TRUE", "blob_versioning.csv")
    ]
    run_scans(resource_folder, scans, "StorageAccounts")

def scan_app_services(resource_folder):
    """Run Steampipe scans for App Services."""
    scans = [
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
    run_scans(resource_folder, scans, "AppServices")

def scan_network_security_groups(resource_folder):
    """Run Steampipe scans for Network Security Groups."""
    scans = [
        ("Unrestricted Inbound/Outbound Rules", "WITH unrestricted_inbound AS (SELECT DISTINCT name AS sg_name FROM azure_network_security_group nsg, jsonb_array_elements(security_rules || default_security_rules) sg, jsonb_array_elements_text(CASE WHEN jsonb_array_length(sg -> 'properties' -> 'destinationPortRanges') > 0 THEN (sg -> 'properties' -> 'destinationPortRanges') ELSE jsonb_build_array(sg -> 'properties' -> 'destinationPortRange') END) AS dport, jsonb_array_elements_text(CASE WHEN jsonb_array_length(sg -> 'properties' -> 'sourceAddressPrefixes') > 0 THEN (sg -> 'properties' -> 'sourceAddressPrefixes') ELSE jsonb_build_array(sg -> 'properties' -> 'sourceAddressPrefix') END) AS sip WHERE sg -> 'properties' ->> 'access' = 'Allow' AND sg -> 'properties' ->> 'direction' = 'Inbound' AND sip IN ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0') AND dport = '*'), unrestricted_outbound AS (SELECT DISTINCT name AS sg_name FROM azure_network_security_group nsg, jsonb_array_elements(security_rules || default_security_rules) sg, jsonb_array_elements_text(CASE WHEN jsonb_array_length(sg -> 'properties' -> 'destinationPortRanges') > 0 THEN (sg -> 'properties' -> 'destinationPortRanges') ELSE jsonb_build_array(sg -> 'properties' -> 'destinationPortRange') END) AS dport, jsonb_array_elements_text(CASE WHEN jsonb_array_length(sg -> 'properties' -> 'sourceAddressPrefixes') > 0 THEN (sg -> 'properties' -> 'sourceAddressPrefixes') ELSE jsonb_build_array(sg -> 'properties' -> 'sourceAddressPrefix') END) AS sip WHERE sg -> 'properties' ->> 'access' = 'Allow' AND sg -> 'properties' ->> 'direction' = 'Outbound' AND sip IN ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0') AND dport = '*') SELECT sg_name FROM unrestricted_inbound UNION SELECT sg_name FROM unrestricted_outbound", "unrestricted_rules.csv"),
        ("Clear Text Protocols", "WITH clear_text_protocols AS (SELECT DISTINCT name AS sg_name, dport FROM azure_network_security_group nsg, jsonb_array_elements(security_rules || default_security_rules) sg, jsonb_array_elements_text(CASE WHEN jsonb_array_length(sg -> 'properties' -> 'destinationPortRanges') > 0 THEN (sg -> 'properties' -> 'destinationPortRanges') ELSE jsonb_build_array(sg -> 'properties' -> 'destinationPortRange') END) AS dport WHERE sg -> 'properties' ->> 'access' = 'Allow' AND dport IN ('20', '21', '23', '25', '69', '80', '110', '119', '143', '161', '162', '389', '513', '514')) SELECT sg_name || ' (' || dport || ')' as nsg_port FROM clear_text_protocols", "clear_text_protocols.csv"),
        ("Sensitive Management Ports", "WITH sensitive_management_ports AS (SELECT DISTINCT name AS sg_name, dport FROM azure_network_security_group nsg, jsonb_array_elements(security_rules || default_security_rules) sg, jsonb_array_elements_text(CASE WHEN jsonb_array_length(sg -> 'properties' -> 'destinationPortRanges') > 0 THEN (sg -> 'properties' -> 'destinationPortRanges') ELSE jsonb_build_array(sg -> 'properties' -> 'destinationPortRange') END) AS dport, jsonb_array_elements_text(CASE WHEN jsonb_array_length(sg -> 'properties' -> 'sourceAddressPrefixes') > 0 THEN (sg -> 'properties' -> 'sourceAddressPrefixes') ELSE jsonb_build_array(sg -> 'properties' -> 'sourceAddressPrefix') END) AS sip WHERE sg -> 'properties' ->> 'access' = 'Allow' AND sip IN ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0') AND dport IN ('22', '23', '80', '443', '3389', '5900', '21', '69', '389', '514', '137', '138', '139', '445', '88', '3306', '1433', '5432', '1521', '6379', '25', '465', '110')) SELECT sg_name || ' (' || dport || ')' as nsg_port FROM sensitive_management_ports", "sensitive_management_ports.csv")
    ]
    run_scans(resource_folder, scans, "NetworkSecurityGroups")

def scan_sql_databases(resource_folder):
    """Run Steampipe scans for SQL Databases."""
    scans = [
        ("Disabled Server Audit Policies", "SELECT s.name AS resource FROM azure_sql_server s, jsonb_array_elements(s.server_audit_policy) AS audit WHERE audit -> 'properties' ->> 'state' = 'Disabled';", "sql_server_audit_disabled.csv"),
        ("Audit Retention Less Than 90 Days", "SELECT s.name AS resource FROM azure_sql_server s, jsonb_array_elements(s.server_audit_policy) AS audit WHERE (audit -> 'properties' ->> 'retentionDays')::integer < 90;", "sql_server_audit_retention_less_than_90.csv"),
        ("Firewall Rules Allowing 0.0.0.0/0", "SELECT s.name AS resource FROM azure_sql_server s WHERE firewall_rules @> '[{\"properties\":{\"endIpAddress\":\"0.0.0.0\",\"startIpAddress\":\"0.0.0.0\"}}]' OR firewall_rules @> '[{\"properties\":{\"endIpAddress\":\"255.255.255.255\",\"startIpAddress\":\"0.0.0.0\"}}]';", "sql_server_firewall_ingress_0_0_0_0.csv"),
        ("Public Network Access Enabled", "SELECT s.name AS resource FROM azure_sql_server s WHERE public_network_access = 'Enabled';", "sql_server_public_network_access_enabled.csv"),
        ("Azure AD Authentication Not Enabled", "WITH sever_with_ad_admin AS (SELECT DISTINCT a.id FROM azure_sql_server AS a, jsonb_array_elements(server_azure_ad_administrator) AS ad_admin WHERE ad_admin ->> 'type' = 'Microsoft.Sql/servers/administrators') SELECT a.name AS resource FROM azure_sql_server AS a LEFT JOIN sever_with_ad_admin AS s ON a.id = s.id WHERE s.id IS NULL;", "sql_server_azure_ad_auth_not_enabled.csv"),
        ("TDE Protector Not Using Customer-Managed Key", "SELECT s.name AS resource FROM azure_sql_server s, jsonb_array_elements(encryption_protector) encryption, azure_subscription sub WHERE sub.subscription_id = s.subscription_id AND encryption ->> 'kind' = 'servicemanaged';", "tde_protector_not_cmk.csv")
    ]
    run_scans(resource_folder, scans, "SQLDatabases")

def scan_key_vaults(resource_folder):
    """Run Steampipe scans for Key Vault misconfigurations."""
    scans = [
        ("Network ACLs Configuration", "SELECT a.name AS resource FROM azure_key_vault a, azure_subscription sub WHERE (network_acls IS NULL OR network_acls ->> 'defaultAction' != 'Deny') AND sub.subscription_id = a.subscription_id", "public_network_enabled_key_vaults.csv"),
        ("Soft Delete Disabled", "SELECT name FROM azure_key_vault WHERE soft_delete_enabled IS NOT TRUE", "soft_delete_disabled.csv"),
        ("Purge Protection Status", "SELECT name FROM azure_key_vault WHERE purge_protection_enabled IS NOT TRUE", "purge_protection_disabled.csv"),
        ("Diagnostic Settings", "SELECT name FROM azure_key_vault WHERE diagnostic_settings IS NULL", "missing_diagnostics.csv"),
    ]
    run_scans(resource_folder, scans, "KeyVaults")

def scan_postgresql_databases(resource_folder):
    """Run Steampipe scans for PostgreSQL Databases."""
    scans = [
        ("Log Checkpoints Configuration", "WITH log_checkpoints_on AS (SELECT id FROM azure_postgresql_flexible_server, jsonb_array_elements(flexible_server_configurations) AS config WHERE config ->> 'Name' = 'log_checkpoints' AND config ->> 'Value' = 'on') SELECT id FROM log_checkpoints_on;", "log_checkpoints_configuration.csv"),
        ("Connection Throttling Configuration", "WITH connection_throttling_off AS (SELECT id FROM azure_postgresql_flexible_server, jsonb_array_elements(flexible_server_configurations) AS config WHERE config ->> 'Name' = 'connection_throttling' AND config ->> 'Value' = 'off') SELECT id FROM connection_throttling_off;", "connection_throttling_configuration.csv"),
        ("Log Files Retention Days", "SELECT s.id AS resource FROM azure_postgresql_flexible_server s, jsonb_array_elements(flexible_server_configurations) AS config, azure_subscription sub WHERE config ->> 'Name' = 'logfiles.retention_days' AND (config -> 'ConfigurationProperties' ->> 'value')::integer <= 3 AND sub.subscription_id = s.subscription_id;", "logfiles_retention_alarm.csv")
    ]
    run_scans(resource_folder, scans, "PostgreSQLDatabases")

def scan_mysql_databases(resource_folder):
    """Run Steampipe scans for MySQL Databases."""
    scans = [
        ("Non-compliant TLS Versions", "WITH tls_version AS (SELECT id FROM azure_mysql_flexible_server, jsonb_array_elements(flexible_server_configurations) AS config WHERE config ->> 'Name' = 'tls_version' AND config ->> 'Value' NOT IN ('TLS1_2', 'TLS1_3')) SELECT id FROM tls_version;", "tls_noncompliant_servers.csv")
    ]
    run_scans(resource_folder, scans, "MySQLDatabases")

def scan_cosmos_db(resource_folder):
    """Run Steampipe scans for Cosmos DB."""
    scans = [
        ("No Firewall", "SELECT name FROM azure_cosmosdb_account WHERE is_virtual_network_filter_enabled = false", "cosmosdb_no_firewall.csv")
    ]
    run_scans(resource_folder, scans, "CosmosDB")

def run_all_scans(resource_folders):
    """Run all Steampipe scans for all resource types automatically."""
    print(f"\n{Fore.CYAN}Starting comprehensive security scan...{Style.RESET_ALL}")
    
    scan_functions = [
        (scan_virtual_machines, "VirtualMachines"),
        (scan_storage_accounts, "StorageAccounts"),
        (scan_app_services, "AppServices"),
        (scan_network_security_groups, "NetworkSecurityGroups"),
        (scan_sql_databases, "SQLDatabases"),
        (scan_key_vaults, "KeyVaults"),
        (scan_postgresql_databases, "PostgreSQLDatabases"),
        (scan_mysql_databases, "MySQLDatabases"),
        (scan_cosmos_db, "CosmosDB")
    ]
    
    for scan_func, resource_type in scan_functions:
        try:
            print(f"\n{Fore.YELLOW}Running {resource_type} scans...{Style.RESET_ALL}")
            scan_func(resource_folders[resource_type])
            print(f"{Fore.GREEN}✓ {resource_type} scans completed{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}✗ Error in {resource_type} scan: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Error in {resource_type} scan: {str(e)}")
    
    print(f"\n{Fore.GREEN}Comprehensive scan completed.{Style.RESET_ALL}")

def main_menu(resource_folders):
    """Interactive menu for running scans."""
    scan_functions = {
        "Run All Scans": (run_all_scans, None),
        "Virtual Machines": (scan_virtual_machines, "VirtualMachines"),
        "Storage Accounts": (scan_storage_accounts, "StorageAccounts"),
        "App Services": (scan_app_services, "AppServices"),
        "Network Security Groups": (scan_network_security_groups, "NetworkSecurityGroups"),
        "SQL Databases": (scan_sql_databases, "SQLDatabases"),
        "Key Vaults": (scan_key_vaults, "KeyVaults"),
        "PostgreSQL Databases": (scan_postgresql_databases, "PostgreSQLDatabases"),
        "MySQL Databases": (scan_mysql_databases, "MySQLDatabases"),
        "Cosmos DB": (scan_cosmos_db, "CosmosDB"),
        "Exit": (None, None)
    }

    while True:
        choice = display_menu("Azure Security Scanner", list(scan_functions.keys()))
        
        if 1 <= choice <= len(scan_functions):
            selected_option = list(scan_functions.items())[choice - 1]
            func, resource_type = selected_option[1]
            
            if func:
                try:
                    if resource_type:
                        func(resource_folders[resource_type])
                    else:
                        # This is for "Run All Scans" option
                        print(f"\n{Fore.CYAN}Starting comprehensive security scan...{Style.RESET_ALL}")
                        for scan_name, (scan_func, res_type) in scan_functions.items():
                            if scan_func and res_type:  # Skip "Run All Scans" and "Exit" options
                                try:
                                    scan_func(resource_folders[res_type])
                                except Exception as e:
                                    print(f"{Fore.RED}Error in {scan_name}: {str(e)}{Style.RESET_ALL}")
                                    logging.error(f"Error in {scan_name}: {str(e)}")
                        print(f"\n{Fore.GREEN}Comprehensive scan completed.{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}Error executing scan: {str(e)}{Style.RESET_ALL}")
                    logging.error(f"Error executing scan: {str(e)}")
            else:
                print(f"{Fore.CYAN}Exiting the script. Thank you for using our service.{Style.RESET_ALL}")
                break
        else:
            print(f"{Fore.RED}Invalid selection. Please try again.{Style.RESET_ALL}")

def check_azure_login():
    """Check if already logged into Azure."""
    try:
        subprocess.run(["az", "account", "show", "--output", "none"], check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def clear_account_credentials():
    """Clear Azure cached account credentials."""
    print(f"{Fore.CYAN}Clearing Azure cached credentials...{Style.RESET_ALL}")
    os.system("az account clear")

def initial_menu():
    """Initial setup menu for Azure operations."""
    resource_folders = None
    logging_configured = False
    
    while True:
        clear_screen()
        print_banner()
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

        if choice == 1:
            print(f"{Fore.CYAN}Clearing Azure cached credentials...{Style.RESET_ALL}")
            os.system("az account clear")
            print(f"{Fore.GREEN}Credentials cleared.{Style.RESET_ALL}")
            if logging_configured:
                logging.info("Azure credentials cleared")
                
        elif choice == 2:
            print(f"{Fore.CYAN}Logging into Azure...{Style.RESET_ALL}")
            subprocess.run(["az", "login", "--output", "none"], check=True)
            print(f"{Fore.GREEN}Login completed.{Style.RESET_ALL}")
            if logging_configured:
                logging.info("Azure login completed")
                
        elif choice == 3:
            print(f"{Fore.CYAN}Listing Azure subscriptions...{Style.RESET_ALL}")
            subscriptions = json.loads(subprocess.run(["az", "account", "list", "--query", "[].{id:id, name:name}", "-o", "json"], capture_output=True, text=True, check=True).stdout)
            
            print(f"\n{Fore.CYAN}Available subscriptions:{Style.RESET_ALL}")
            for idx, sub in enumerate(subscriptions):
                print(f"{Fore.GREEN}{idx + 1}.{Style.RESET_ALL} {sub['name']} ({sub['id']})")

            sub_choice = display_menu("Select a subscription by number", [f"{sub['name']} ({sub['id']})" for sub in subscriptions])
            if 1 <= sub_choice <= len(subscriptions):
                subscription_id = subscriptions[sub_choice - 1]["id"]
                subscription_name = subscriptions[sub_choice - 1]["name"]
                
                # Set subscription
                subprocess.run(["az", "account", "set", "--subscription", subscription_id], check=True)
                print(f"{Fore.GREEN}Subscription set to: {subscription_name} ({subscription_id}){Style.RESET_ALL}")
                
                # Configure logging
                logging_configured = configure_logging(subscription_name)
                if logging_configured:
                    logging.info(f"Selected subscription: {subscription_name} ({subscription_id})")
                
                # Get tenant details and create folder structure
                tenant_details = json.loads(subprocess.run(["az", "account", "show"], capture_output=True, text=True, check=True).stdout)
                tenant_name = tenant_details['tenantId']
                resource_folders = create_folder_structure(tenant_name, subscription_name, subscription_id)
                
            else:
                print(f"{Fore.RED}Invalid selection.{Style.RESET_ALL}")
                
        elif choice == 4:
            if not check_azure_login():
                print(f"{Fore.RED}Please login first (Option 2){Style.RESET_ALL}")
                continue
            if resource_folders is None:
                print(f"{Fore.RED}Please select a subscription first (Option 3){Style.RESET_ALL}")
                continue
            if not logging_configured:
                print(f"{Fore.RED}Logging not configured. Please select a subscription first.{Style.RESET_ALL}")
                continue
            main_menu(resource_folders)
            
        elif choice == 5:
            if logging_configured:
                logging.info("Exiting script")
            print(f"{Fore.CYAN}Exiting script. Thank you for using our service.{Style.RESET_ALL}")
            sys.exit(0)
            
        else:
            print(f"{Fore.RED}Invalid selection. Please try again.{Style.RESET_ALL}")

def check_for_updates():
    """Check if there is a newer version of the script available on GitHub."""
    try:
        # URL to the raw version file on GitHub
        version_url = "https://raw.githubusercontent.com/D4rkm4g1c/AzureSecuritySuite/refs/heads/main/version.txt"
        
        # Fetch the latest version from GitHub
        response = requests.get(version_url)
        response.raise_for_status()
        
        latest_version = response.text.strip()
        
        if latest_version > __version__:
            print(f"{Fore.YELLOW}A new version ({latest_version}) is available!{Style.RESET_ALL}")
            print(f"Run the script with --update to download the latest version.")
        else:
            print(f"{Fore.GREEN}You are using the latest version ({__version__}).{Style.RESET_ALL}")
            
    except requests.RequestException as e:
        print(f"{Fore.RED}Failed to check for updates: {str(e)}{Style.RESET_ALL}")

def update_script():
    """Download the latest version of the script from GitHub."""
    try:
        # URL to the raw script file on GitHub
        script_url = "https://raw.githubusercontent.com/D4rkm4g1c/AzureSecuritySuite/refs/heads/main/AzureSecuritySuite.py"
        
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
        
        print(f"{Fore.GREEN}✓ Script updated successfully!{Style.RESET_ALL}")
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

def main():
    """Main function to start the script."""
    logging.info("Starting Azure Security Scanner.")
    initial_menu()

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description='Azure Security Scanner')
    parser.add_argument('--update', action='store_true', help='Update the script to the latest version')
    args = parser.parse_args()

    if args.update:
        update_script()
    else:
        check_for_updates()
        # Continue with the rest of your script
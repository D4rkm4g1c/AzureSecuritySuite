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

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Configure logging
logging.basicConfig(
    filename='azure_scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

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
    

.______    _______ .__   __. .___________. _______     _______.___________.   .______    _______   ______   .______    __       _______ 
|   _  \  |   ____||  \ |  | |           ||   ____|   /       |           |   |   _  \  |   ____| /  __  \  |   _  \  |  |     |   ____|
|  |_)  | |  |__   |   \|  | `---|  |----`|  |__     |   (----`---|  |----`   |  |_)  | |  |__   |  |  |  | |  |_)  | |  |     |  |__   
|   ___/  |   __|  |  . `  |     |  |     |   __|     \   \       |  |        |   ___/  |   __|  |  |  |  | |   ___/  |  |     |   __|  
|  |      |  |____ |  |\   |     |  |     |  |____.----)   |      |  |        |  |      |  |____ |  `--'  | |  |      |  `----.|  |____ 
| _|      |_______||__| \__|     |__|     |_______|_______/       |__|        | _|      |_______| \______/  | _|      |_______||_______|
                                                                                                                                            
    """.strip().splitlines()

    # Calculate the width of the ASCII art
    ascii_width = max(len(line) for line in ascii_art)
    border_width = max(ascii_width, terminal_width)

    # Create the top border
    top_border = f"{Fore.CYAN}╔{'═' * (border_width - 2)}╗{Style.RESET_ALL}"
    bottom_border = f"{Fore.CYAN}╚{'═' * (border_width - 2)}╝{Style.RESET_ALL}"

    # Center each line of the ASCII art
    centered_ascii_art = "\n".join(line.center(border_width) for line in ascii_art)

    # Print the banner
    banner = f"""
{top_border}
{centered_ascii_art}
{bottom_border}
{Fore.CYAN}╔{'═' * (terminal_width-2)}╗
║{' ' * (terminal_width-2)}║
║{Style.BRIGHT + Fore.MAGENTA + ' Welcome to '.center(terminal_width-2)}║
║{Style.BRIGHT + Fore.YELLOW + ' Pentest People '.center(terminal_width-2)}║
║{Style.BRIGHT + Fore.YELLOW + ' Azure Security Scanner (AzureSecuritySuite) '.center(terminal_width-2)}║
║{' ' * (terminal_width-2)}║
║{Style.BRIGHT + Fore.GREEN + 'Created by James Round (Consultant)'.center(terminal_width-2)}║
║{' ' * (terminal_width-2)}║
║{Style.BRIGHT + Fore.GREEN + f' Version 1.0 - {time.strftime("%Y-%m-%d")}'.center(terminal_width-2)}║
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
    choice = input(f"{Fore.YELLOW}{prompt}{Style.RESET_ALL}")
    logging.info(f"User selected option: {choice}")
    return choice

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
        logging.info(f"Executing query: {query}")
        print(f"\n{Fore.CYAN}Executing query...{Style.RESET_ALL}")
        spinner = show_spinner("Processing query")
        
        steampipe_cmd = [
            "steampipe",
            "query",
            query,
            "--output",
            "csv",
            "--header=false"
        ]
        
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
            log_query_execution(query, output_file, True)
            return True
        else:
            print(f"{Fore.RED}✗ Query execution failed: {stderr}{Style.RESET_ALL}")
            log_query_execution(query, output_file, False)
            return False
            
    except Exception as e:
        print(f"{Fore.RED}✗ Error: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Exception occurred while executing query: {query} - Error: {str(e)}")
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
        "MySQLDatabases"
    ]
    
    resource_folders = {}
    for resource_type in resource_types:
        resource_folder = os.path.join(subscription_folder, resource_type)
        os.makedirs(resource_folder, exist_ok=True)
        resource_folders[resource_type] = resource_folder

    print(f"{Fore.GREEN}Folder structure created successfully.{Style.RESET_ALL}")
    return resource_folders

def scan_menu(resource_folder, scans, title):
    """Generic function to handle scanning menus."""
    while True:
        choice = display_menu(title, [scan[0] for scan in scans] + ["Run All Scans", "Return to Main Menu"], show_back=True)
        if choice.isdigit():
            choice = int(choice)
            if 1 <= choice <= len(scans):
                query, output_file = scans[choice - 1][1], f"{resource_folder}/{scans[choice - 1][2]}"
                run_steampipe_query(query, output_file)
                time.sleep(5)  # Wait for 5 seconds before clearing the screen
            elif choice == len(scans) + 1:
                print(f"\n{Fore.CYAN}Running all {title} scans...{Style.RESET_ALL}")
                for scan in scans:
                    query, output_file = scan[1], f"{resource_folder}/{scan[2]}"
                    run_steampipe_query(query, output_file)
                print(f"{Fore.GREEN}All {title} scans completed.{Style.RESET_ALL}")
                time.sleep(5)  # Wait for 5 seconds before clearing the screen
            elif choice == 0:
                break
        else:
            print(f"{Fore.RED}Invalid selection. Please try again.{Style.RESET_ALL}")

def scan_storage_accounts(resource_folder):
    """Run Steampipe scans for storage accounts."""
    scans = [
        ("Scan for Public Blob Access", "SELECT name FROM azure_storage_account WHERE allow_blob_public_access = true", "public_blob_access.csv"),
        ("Scan for Soft Delete Disabled", "SELECT name FROM azure_storage_account WHERE blob_soft_delete_enabled = false", "soft_delete_disabled.csv"),
        ("Scan for Network Default Allow", "SELECT name FROM azure_storage_account WHERE network_rule_default_action = 'Allow'", "network_default_allow.csv"),
        ("Scan for Infrastructure Encryption", "SELECT name FROM azure_storage_account WHERE require_infrastructure_encryption IS NOT TRUE", "infrastructure_encryption.csv"),
        ("Scan for HTTPS Traffic Only", "SELECT name FROM azure_storage_account WHERE enable_https_traffic_only = 'False'", "https_traffic_only.csv"),
        ("Scan for TLS Version", "SELECT name FROM azure_storage_account WHERE minimum_tls_version IN ('TLS1_0', 'TLS1_1')", "tls_version.csv"),
        ("Scan for Blob Versioning", "SELECT name FROM azure_storage_account WHERE blob_versioning_enabled IS NOT TRUE", "blob_versioning.csv")
    ]
    scan_menu(resource_folder, scans, "Storage Account Scanning Menu")

def scan_virtual_machines(resource_folder):
    """Run Steampipe scans for virtual machines."""
    scans = [
        ("Scan for Unmanaged Disks", "SELECT vm.name FROM azure_compute_virtual_machine AS vm, azure_subscription AS sub WHERE sub.subscription_id = vm.subscription_id AND managed_disk_id IS NULL", "unmanaged_disks.csv"),
        ("Scan for Unencrypted Disks", "SELECT disk.name FROM azure_compute_disk AS disk, azure_subscription AS sub WHERE disk_state != 'Attached' AND sub.subscription_id = disk.subscription_id AND encryption_type != 'EncryptionAtRestWithCustomerKey'", "unencrypted_disks.csv")
    ]
    scan_menu(resource_folder, scans, "Virtual Machine Scanning Menu")

def scan_key_vaults(resource_folder):
    """Run Steampipe scans for Key Vault misconfigurations."""
    scans = [
        ("Scan Network ACLs Configuration", "SELECT name, network_acls FROM azure_key_vault WHERE network_acls IS NOT NULL", "network_acls.csv"),
        ("Scan Soft Delete Status", "SELECT name FROM azure_key_vault WHERE soft_delete_enabled IS NOT TRUE", "soft_delete_disabled.csv"),
        ("Scan Purge Protection Status", "SELECT name FROM azure_key_vault WHERE purge_protection_enabled IS NOT TRUE", "purge_protection_disabled.csv"),
        ("Scan Diagnostic Settings", "SELECT name FROM azure_key_vault WHERE diagnostic_settings IS NULL", "missing_diagnostics.csv")
    ]
    scan_menu(resource_folder, scans, "Key Vault Scanning Menu")

def scan_app_services(resource_folder):
    """Run Steampipe scans for App Services."""
    scans = [
        ("Scan Web App Auth Settings", "SELECT name, auth_settings FROM azure_app_service_web_app AS app", "web_app_auth_settings.csv"),
        ("Scan Function App Auth Settings", "SELECT name, auth_settings FROM azure_app_service_function_app", "function_app_auth_settings.csv"),
        ("Scan Web Apps for HTTPS Only", "SELECT name FROM azure_app_service_web_app WHERE NOT https_only", "web_app_https_only.csv"),
        ("Scan Function Apps for Client Certs", "SELECT app.name FROM azure_app_service_function_app AS app WHERE NOT app.client_cert_enabled", "function_app_client_cert.csv"),
        ("Scan Web Apps for Managed Identity", "SELECT app.name FROM azure_app_service_web_app AS app WHERE app.identity = '{}'", "web_app_managed_identity.csv"),
        ("Scan Web Apps for HTTP/2 Enabled", """
        SELECT name FROM azure_app_service_web_app
        WHERE (configuration -> 'properties' ->> 'http20Enabled')::boolean = false
        OR (configuration -> 'properties' ->> 'http20Enabled') IS NULL
        """, "web_app_http2.csv"),
        ("Scan Web Apps for FTPS State", "SELECT name FROM azure_app_service_web_app WHERE configuration -> 'properties' ->> 'ftpsState' = 'AllAllowed'", "web_app_ftps_state.csv")
    ]
    scan_menu(resource_folder, scans, "App Services Scanning Menu")

def scan_network_security_groups(resource_folder):
    """Run Steampipe scans for Network Security Groups."""
    scans = [
        ("Scan for Unrestricted Inbound/Outbound Rules", """
        WITH unrestricted_inbound AS (
          SELECT DISTINCT
            name AS sg_name
          FROM
            azure_network_security_group nsg,
            jsonb_array_elements(security_rules || default_security_rules) sg,
            jsonb_array_elements_text(
              CASE
                WHEN jsonb_array_length(sg -> 'properties' -> 'destinationPortRanges') > 0 THEN (sg -> 'properties' -> 'destinationPortRanges')
                ELSE jsonb_build_array(sg -> 'properties' -> 'destinationPortRange')
              END
            ) AS dport,
            jsonb_array_elements_text(
              CASE
                WHEN jsonb_array_length(sg -> 'properties' -> 'sourceAddressPrefixes') > 0 THEN (sg -> 'properties' -> 'sourceAddressPrefixes')
                ELSE jsonb_build_array(sg -> 'properties' -> 'sourceAddressPrefix')
              END
            ) AS sip
          WHERE
            sg -> 'properties' ->> 'access' = 'Allow'
            AND sg -> 'properties' ->> 'direction' = 'Inbound'
            AND sip IN ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0')
            AND dport = '*'
        ),
        unrestricted_outbound AS (
          SELECT DISTINCT
            name AS sg_name
          FROM
            azure_network_security_group nsg,
            jsonb_array_elements(security_rules || default_security_rules) sg,
            jsonb_array_elements_text(
              CASE
                WHEN jsonb_array_length(sg -> 'properties' -> 'destinationPortRanges') > 0 THEN (sg -> 'properties' -> 'destinationPortRanges')
                ELSE jsonb_build_array(sg -> 'properties' -> 'destinationPortRange')
              END
            ) AS dport,
            jsonb_array_elements_text(
              CASE
                WHEN jsonb_array_length(sg -> 'properties' -> 'sourceAddressPrefixes') > 0 THEN (sg -> 'properties' -> 'sourceAddressPrefixes')
                ELSE jsonb_build_array(sg -> 'properties' -> 'sourceAddressPrefix')
              END
            ) AS sip
          WHERE
            sg -> 'properties' ->> 'access' = 'Allow'
            AND sg -> 'properties' ->> 'direction' = 'Outbound'
            AND sip IN ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0')
            AND dport = '*'
        )
        SELECT
          sg_name
        FROM
          unrestricted_inbound
        UNION
        SELECT
          sg_name
        FROM
          unrestricted_outbound
        """, "unrestricted_rules.csv")
    ]
    scan_menu(resource_folder, scans, "Network Security Groups Scanning Menu")

def scan_sql_databases(resource_folder):
    """Run Steampipe scans for SQL Databases."""
    scans = [
        ("Scan for Disabled Server Audit Policies", """
        SELECT s.name AS resource
        FROM azure_sql_server s,
        jsonb_array_elements(s.server_audit_policy) AS audit
        WHERE audit -> 'properties' ->> 'state' = 'Disabled';
        """, "sql_server_audit_disabled.csv"),
        ("Scan for Audit Retention Less Than 90 Days", """
        SELECT s.name AS resource
        FROM azure_sql_server s,
        jsonb_array_elements(s.server_audit_policy) AS audit
        WHERE (audit -> 'properties' ->> 'retentionDays')::integer < 90;
        """, "sql_server_audit_retention_less_than_90.csv"),
        ("Scan for Firewall Rules Allowing 0.0.0.0/0", """
        SELECT s.name AS resource
        FROM azure_sql_server s
        WHERE firewall_rules @> '[{"properties":{"endIpAddress":"0.0.0.0","startIpAddress":"0.0.0.0"}}]'
        OR firewall_rules @> '[{"properties":{"endIpAddress":"255.255.255.255","startIpAddress":"0.0.0.0"}}]';
        """, "sql_server_firewall_ingress_0_0_0_0.csv"),
        ("Scan for Public Network Access Enabled", """
        SELECT s.name AS resource
        FROM azure_sql_server s
        WHERE public_network_access = 'Enabled';
        """, "sql_server_public_network_access_enabled.csv"),
        ("Scan for Azure AD Authentication Enabled", """
        WITH sever_with_ad_admin AS (
          SELECT DISTINCT a.id
          FROM azure_sql_server AS a,
          jsonb_array_elements(server_azure_ad_administrator) AS ad_admin
          WHERE ad_admin ->> 'type' = 'Microsoft.Sql/servers/administrators'
        )
        SELECT a.name AS resource
        FROM azure_sql_server AS a
        LEFT JOIN sever_with_ad_admin AS s ON a.id = s.id
        WHERE s.id IS NOT NULL;
        """, "sql_server_azure_ad_auth_enabled.csv"),
        ("Scan for TDE Protector Not Using Customer-Managed Key", """
        SELECT s.name AS resource
        FROM azure_sql_server s,
        jsonb_array_elements(encryption_protector) encryption,
        azure_subscription sub
        WHERE sub.subscription_id = s.subscription_id
        AND encryption ->> 'kind' = 'servicemanaged';
        """, "tde_protector_not_cmk.csv")
    ]
    scan_menu(resource_folder, scans, "SQL Databases Scanning Menu")

def scan_postgresql_databases(resource_folder):
    """Run Steampipe scans for PostgreSQL Databases."""
    scans = [
        ("Check Log Checkpoints Configuration", """
        WITH log_checkpoints_on AS (
            SELECT id
            FROM azure_postgresql_flexible_server,
            jsonb_array_elements(flexible_server_configurations) AS config
            WHERE config ->> 'Name' = 'log_checkpoints'
            AND config ->> 'Value' = 'on'
        )
        SELECT id FROM log_checkpoints_on;
        """, "log_checkpoints_configuration.csv"),
        ("Check Connection Throttling Configuration", """
        WITH connection_throttling_off AS (
            SELECT id
            FROM azure_postgresql_flexible_server,
            jsonb_array_elements(flexible_server_configurations) AS config
            WHERE config ->> 'Name' = 'connection_throttling'
            AND config ->> 'Value' = 'off'
        )
        SELECT id FROM connection_throttling_off;
        """, "connection_throttling_configuration.csv"),
        ("Check Log Files Retention Days", """
        SELECT s.id AS resource
        FROM azure_postgresql_flexible_server s,
        jsonb_array_elements(flexible_server_configurations) AS config,
        azure_subscription sub
        WHERE config ->> 'Name' = 'logfiles.retention_days'
        AND (config -> 'ConfigurationProperties' ->> 'value')::integer <= 3
        AND sub.subscription_id = s.subscription_id;
        """, "logfiles_retention_alarm.csv")
    ]
    scan_menu(resource_folder, scans, "PostgreSQL Databases Scanning Menu")

def scan_mysql_databases(resource_folder):
    """Run Steampipe scans for MySQL Databases."""
    scans = [
        ("Placeholder for MySQL Scan 1", "SELECT 'Placeholder for MySQL Scan 1';", "mysql_scan_1.csv"),
        ("Placeholder for MySQL Scan 2", "SELECT 'Placeholder for MySQL Scan 2';", "mysql_scan_2.csv")
    ]
    scan_menu(resource_folder, scans, "MySQL Databases Scanning Menu")

def run_all_scans(resource_folders):
    """Run all Steampipe scans for all resource types automatically."""
    print(f"\n{Fore.CYAN}Initiating comprehensive scan for all resource types...{Style.RESET_ALL}")

    resource_types = [
        ("Virtual Machines", scan_virtual_machines, "VirtualMachines"),
        ("Storage Accounts", scan_storage_accounts, "StorageAccounts"),
        ("App Services", scan_app_services, "AppServices"),
        ("Network Security Groups", scan_network_security_groups, "NetworkSecurityGroups"),
        ("SQL Databases", scan_sql_databases, "SQLDatabases"),
        ("Key Vaults", scan_key_vaults, "KeyVaults"),
        ("PostgreSQL Databases", scan_postgresql_databases, "PostgreSQLDatabases"),
        ("MySQL Databases", scan_mysql_databases, "MySQLDatabases")
    ]

    for idx, (name, scan_func, folder_key) in enumerate(resource_types, 1):
        print(f"\n{Fore.CYAN}Scanning {name}...{Style.RESET_ALL}")
        scan_func(resource_folders[folder_key])
        print(f"{Fore.GREEN}✓ {name} scan completed.{Style.RESET_ALL}")
        # Simple progress bar
        progress = f"[{'#' * idx}{'.' * (len(resource_types) - idx)}] {idx}/{len(resource_types)}"
        print(f"{Fore.YELLOW}{progress}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}Comprehensive scan completed.{Style.RESET_ALL}")
    time.sleep(5)  # Wait for 5 seconds before clearing the screen

def main_menu(resource_folders):
    """Interactive menu for running scans."""
    options = [
        ("Scan Virtual Machines", scan_virtual_machines, "VirtualMachines"),
        ("Scan Storage Accounts", scan_storage_accounts, "StorageAccounts"),
        ("Scan App Services", scan_app_services, "AppServices"),
        ("Scan Network Security Groups", scan_network_security_groups, "NetworkSecurityGroups"),
        ("Scan SQL Databases", scan_sql_databases, "SQLDatabases"),
        ("Scan Key Vaults", scan_key_vaults, "KeyVaults"),
        ("Scan PostgreSQL Databases", scan_postgresql_databases, "PostgreSQLDatabases"),
        ("Scan MySQL Databases", scan_mysql_databases, "MySQLDatabases"),
        ("Run All Scans", run_all_scans, None),
        ("Exit", None, None)
    ]

    while True:
        choice = display_menu("Resource Type Scanning Menu", [opt[0] for opt in options])
        if choice.isdigit():
            choice = int(choice)
            if 1 <= choice <= len(options):
                if options[choice - 1][1]:
                    if options[choice - 1][2]:
                        options[choice - 1][1](resource_folders[options[choice - 1][2]])
                    else:
                        options[choice - 1][1](resource_folders)
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
    
    while True:
        clear_screen()
        print_banner()
        watermark = f"{Fore.LIGHTBLACK_EX}Azure Security Scanner - Confidential{Style.RESET_ALL}"
        print(f"{watermark.center(shutil.get_terminal_size().columns)}\n")

        choice = display_menu("Azure Setup Menu", [
            "Clear Cached Credentials",
            "Login to Azure",
            "Choose Subscription",
            "Start Testing",
            "Exit"
        ])

        if choice == "1":
            logging.info("Clearing Azure cached credentials.")
            os.system("az account clear")
            print(f"{Fore.GREEN}Credentials cleared.{Style.RESET_ALL}")
        elif choice == "2":
            logging.info("Logging into Azure.")
            subprocess.run(["az", "login", "--output", "none"], check=True)
            print(f"{Fore.GREEN}Login completed.{Style.RESET_ALL}")
        elif choice == "3":
            logging.info("Listing Azure subscriptions.")
            subscriptions = json.loads(subprocess.run(["az", "account", "list", "--query", "[].{id:id, name:name}", "-o", "json"], capture_output=True, text=True, check=True).stdout)
            print(f"\n{Fore.CYAN}Available subscriptions:{Style.RESET_ALL}")
            for idx, sub in enumerate(subscriptions):
                print(f"{Fore.GREEN}{idx + 1}.{Style.RESET_ALL} {sub['name']} ({sub['id']})")

            sub_choice = int(input(f"{Fore.YELLOW}Select a subscription by number: {Style.RESET_ALL}")) - 1
            logging.info(f"User selected subscription: {sub_choice}")
            if 0 <= sub_choice < len(subscriptions):
                subscription_id = subscriptions[sub_choice]["id"]
                subscription_name = subscriptions[sub_choice]["name"]
                subprocess.run(["az", "account", "set", "--subscription", subscription_id], check=True)
                print(f"{Fore.GREEN}Subscription set to: {subscription_name} ({subscription_id}){Style.RESET_ALL}")
                
                tenant_details = json.loads(subprocess.run(["az", "account", "show"], capture_output=True, text=True, check=True).stdout)
                tenant_name = tenant_details['tenantId']
                resource_folders = create_folder_structure(tenant_name, subscription_name, subscription_id)
            else:
                print(f"{Fore.RED}Invalid selection.{Style.RESET_ALL}")
        elif choice == "4":
            if not check_azure_login():
                print(f"{Fore.RED}Please login first (Option 2){Style.RESET_ALL}")
                continue
            if resource_folders is None:
                print(f"{Fore.RED}Please select a subscription first (Option 3){Style.RESET_ALL}")
                continue
            main_menu(resource_folders)
        elif choice == "5":
            logging.info("Exiting script.")
            print(f"{Fore.CYAN}Exiting script. Thank you for using our service.{Style.RESET_ALL}")
            sys.exit(0)
        else:
            print(f"{Fore.RED}Invalid selection. Please try again.{Style.RESET_ALL}")

def main():
    """Main function to start the script."""
    logging.info("Starting Azure Security Scanner.")
    initial_menu()

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description='Azure Security Scanner')
    args = parser.parse_args()

    main()
# Azure Security Scanner (AzureSecuritySuite)

## Overview

AzureSecuritySuite is a comprehensive security assessment tool designed to identify potential security misconfigurations and vulnerabilities in your Azure environment. The tool automates the process of checking for common security issues such as unencrypted disks, public access settings, weak TLS configurations, and more across your Azure resources.

## What Does It Check?

The tool performs various security checks across different Azure resources:

### Virtual Machines
- Unmanaged disks detection
- Unencrypted disk identification
- Network security configuration review

### Storage Accounts
- Public blob access settings
- Soft delete configuration
- Network access rules
- Infrastructure encryption status
- HTTPS traffic settings
- TLS version verification
- Blob versioning status

### App Services
- Authentication settings review
- HTTPS-only status
- Client certificate requirements
- Managed identity configuration
- HTTP/2 protocol status
- FTPS state verification
- TLS version compliance

### Network Security Groups
- Unrestricted inbound/outbound rules
- Clear text protocols allowed
- Sensitive port exposure

### SQL Databases
- Server audit policy status
- Audit retention periods
- Firewall rules configuration
- Public network access settings
- Azure AD authentication status
- TDE protector configuration

### Key Vaults
- Network ACLs configuration
- Soft delete status
- Purge protection settings
- Diagnostic settings verification

### PostgreSQL/MySQL Databases
- Security configuration checks
- Log retention settings
- TLS compliance verification

### Cosmos DB
- Firewall configuration review

## Quick Demo

Here's how to use the tool:

1. **Initial Setup**:
   ```bash
   python AzureSecuritySuite.py
   ```

2. **Login Process**:
   - Select "Login to Azure"
   - Authenticate via browser prompt
   - Choose your subscription

3. **Running Scans**:
   - Option 1: Select "Run All Scans" for a comprehensive assessment
   - Option 2: Choose specific resource types (e.g., "Virtual Machines")
     - Select individual checks or "Run All" for that resource
     - Review results
     - Run additional checks as needed

4. **Viewing Results**:
   - Results are saved in CSV format
   - Files are organized by tenant and subscription
   - Each resource type has its own folder
   - Each check produces a separate CSV file

## Prerequisites

- Python 3.6 or higher
- Azure CLI
- Steampipe
- Colorama Python package

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/D4rkm4g1c/AzureSecuritySuite.git
   cd azure-security-scanner
   ```

2. **Install Required Packages:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Azure CLI and Steampipe:**
   Follow the official installation instructions for [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) and [Steampipe](https://steampipe.io/downloads).

## Troubleshooting

- Ensure Azure CLI is logged in (`az login`)
- Verify Steampipe installation (`steampipe --version`)
- Check `azure_scanner.log` for detailed error messages
- Ensure you have appropriate permissions in your Azure subscription

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, please contact me via LinkedIn.

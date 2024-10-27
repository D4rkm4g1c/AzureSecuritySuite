# Azure Security Scanner (AzureSecuritySuite)

## Overview

AzureSecuritySuite is a comprehensive security assessment tool designed to identify potential security misconfigurations and vulnerabilities in your Azure environment. The tool automates the process of checking for common security issues such as unencrypted disks, public access settings, weak TLS configurations, and more across your Azure resources.

## Features

### Automated Security Scanning
- Comprehensive security checks across multiple Azure services
- Parallel processing for improved performance
- Real-time progress tracking
- Detailed logging system
- Automatic version management and updates
- YAML-based scan definitions for easy maintenance

### Interactive HTML Reports
- Clean, modern interface
- Dark/Light mode toggle
- Interactive filtering and search capabilities
- Two viewing modes:
  - View by Vulnerability
  - View by Resource
- Executive summary with key metrics
- Responsive design for all devices

## Project Structure
```
AzureSecuritySuite/
├── AzureSecuritySuite.py     # Main script
├── report_generator.py       # Report generation module
├── version.txt              # Version tracking
├── requirements.txt         # Dependencies
└── scans/                   # YAML scan definitions
    ├── virtual_machines.yaml
    ├── storage_accounts.yaml
    ├── app_services.yaml
    └── ...
```

## Development Setup

1. **Clone Repository**:
   ```bash
   git clone https://github.com/D4rkm4g1c/AzureSecuritySuite.git
   cd AzureSecuritySuite
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
2. **Run the tool**:
   ```bash
   python AzureSecuritySuite.py
   ```
   
## Scan Definitions
Security checks are defined in YAML files for easy maintenance:

```yaml
scans:
  - name: "Unencrypted Disks"
    description: "Identifies VMs with unencrypted disks"
    query: |
      SELECT name, resource_group
      FROM azure_compute_disk
      WHERE encryption_type IS NULL
```

## Common Issues

1. **Authentication Failures**
   - Ensure Azure CLI is logged in
   - Verify permissions
   - Check MFA requirements

2. **Report Generation**
   - Ensure write permissions 
   - Check disk space
   - Verify browser compatibility

## Roadmap

### Upcoming Features
- [ ] Compliance Reporting (CIS, NIST, PCI)
- [ ] Multi-tenant Support
- [ ] Resource Tagging Analysis
- [ ] Automated Remediation Options

## Support

For issues and feature requests, please use GitHub Issues.

## Security Checks

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

## Quick Start Guide

1. **Initial Setup**:
   ```bash
   python AzureSecuritySuite.py
   ```
   - Optional: Use `--update` flag to get the latest version
   ```bash
   python AzureSecuritySuite.py --update
   ```

2. **Authentication**:
   - Select "Login to Azure"
   - Authenticate via browser prompt
   - Choose your subscription

3. **Running Scans**:
   - Option 1: "Run All Scans" for comprehensive assessment
   - Option 2: Choose specific resource types
   - Review real-time progress
   - Generate HTML report when complete

4. **Viewing Reports**:
   - Open generated HTML report
   - Use search functionality to find specific issues
   - Toggle between vulnerability and resource views
   - Switch between light/dark modes for comfortable viewing
   - Review executive summary for quick insights

## Version Management

- Automatic version checking on startup
- Easy updates via `--update` flag
- Version history tracking in version.txt
- Automatic backup creation during updates
- Changelog tracking for all versions

## Prerequisites

- Python 3.6 or higher
- Azure CLI
- Steampipe
- Required Python packages:
  - colorama
  - pathlib
  - datetime
  - logging
  - requests
  - pyyaml

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
- For report issues, check browser console for any JavaScript errors

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, please contact me or raise an issue :)

## Intellectual Property Notice

This software was developed independently by D4rkm4g1c during personal time and is not affiliated with any employer. All rights reserved to the original author.

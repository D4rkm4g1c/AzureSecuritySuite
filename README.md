# Azure Security Scanner (AzureSecuritySuite)

## Overview

AzureSecuritySuite is a comprehensive tool designed to enhance the security posture of your Azure environment. This suite provides automated scanning capabilities across various Azure resources, including Virtual Machines, Storage Accounts, App Services, Network Security Groups, SQL Databases, Key Vaults, PostgreSQL Databases, and MySQL Databases.

## Features

- Scans various Azure resources including Virtual Machines, Storage Accounts, App Services, Network Security Groups, SQL Databases, Key Vaults, PostgreSQL Databases, and MySQL Databases.
- Provides a comprehensive scan option to run all available scans.
- Generates detailed reports in CSV format.
- Includes a user-friendly command-line interface with color-coded output.
- Logs all actions and results for traceability.

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



## Usage

1. **Run the Script:**

   ```bash
   python Azure.py
   ```

   - Loging using the menu as well as selecting the correct subscriptions for review. 

2. **Navigate the Menu:**

   - Use the menu to select the type of scan you want to perform.
   - Follow the prompts to execute scans and view results.

3. **View Reports:**

   - Reports are saved in CSV format in the specified output directory.
   - Review the logs in `azure_scanner.log` for detailed execution information.

## Troubleshooting

- Ensure you are logged into Azure CLI before running the script.
- Verify that Steampipe is installed and configured correctly.
- Check the `azure_scanner.log` file for error messages and troubleshooting information.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, please contact me via Linkedin.

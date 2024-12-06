from datetime import datetime
from pathlib import Path
import logging
from html import escape
from colorama import Fore, Style

def generate_html_report(tenant_name):
    """Generate a simplified HTML report for all scan results"""
    try:
        print(f"\n{Fore.CYAN}Generating HTML report...{Style.RESET_ALL}")
        
        scan_dir = Path(tenant_name)
        
        # Process each subscription
        for subscription_dir in scan_dir.iterdir():
            if not subscription_dir.is_dir():
                continue
                
            subscription_name = subscription_dir.name
            findings_by_type = {}
            
            # Process each resource type directory
            for resource_type_dir in subscription_dir.iterdir():
                if not resource_type_dir.is_dir():
                    continue
                    
                resource_type = resource_type_dir.name
                findings = {}
                
                # Process each vulnerability file (skip overview)
                for csv_file in resource_type_dir.glob('*.csv'):
                    if '_vulnerability_overview' not in csv_file.stem:
                        finding_name = csv_file.stem
                        with open(csv_file, 'r') as f:
                            # Get non-empty lines
                            resources = [line.strip() for line in f if line.strip()]
                            # Add to findings even if empty (to show "no resources vulnerable")
                            findings[finding_name] = resources
                
                if findings:
                    findings_by_type[resource_type] = findings

            if findings_by_type:
                _create_html_report(subscription_dir, subscription_name, findings_by_type)
            else:
                print(f"{Fore.YELLOW}No findings for {subscription_name}{Style.RESET_ALL}")

        return True
        
    except Exception as e:
        print(f"{Fore.RED}Error generating HTML report: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error generating HTML report: {str(e)}")
        return False

def _create_html_report(subscription_dir, subscription_name, findings_by_type):
    """Create the HTML report for a subscription"""
    try:
        # Calculate statistics
        total_findings = sum(len(resources) for findings in findings_by_type.values() 
                           for resources in findings.values())
        high_severity = medium_severity = low_severity = 0
        
        for findings in findings_by_type.values():
            for finding_type, resources in findings.items():
                if any(kw in finding_type.lower() for kw in ['critical', 'high', 'severe', 'unrestricted', 'public']):
                    high_severity += len(resources)
                elif any(kw in finding_type.lower() for kw in ['warning', 'medium', 'sensitive']):
                    medium_severity += len(resources)
                else:
                    low_severity += len(resources)

        # Generate HTML
        html_parts = [
            _get_html_header(subscription_name),
            _get_executive_summary(total_findings, high_severity, medium_severity, low_severity, 
                                len(findings_by_type))
        ]
        
        # Add both views
        for resource_type, findings in findings_by_type.items():
            # Add vulnerability-based view
            html_parts.append(_get_resource_section(resource_type, findings))
            
            # Add resource-based view
            overview_file = Path(subscription_dir) / resource_type / f'{resource_type}_vulnerability_overview.csv'
            html_parts.append(_get_resource_overview_section(resource_type, overview_file))
        
        # Add closing tags and JavaScript
        html_parts.extend([
            """
                </div>
            </body>
            """,
            _get_javascript(),
            "</html>"
        ])
        
        # Write report to file
        report_path = subscription_dir / 'security_report.html'
        report_path.write_text('\n'.join(html_parts), encoding='utf-8')
        print(f"{Fore.GREEN}✓ Report generated for {subscription_name}: {report_path}{Style.RESET_ALL}")
        
    except Exception as e:
        logging.error(f"Failed to create report for {subscription_name}: {e}")
        raise

def _get_resource_section(resource_type, findings):
    """Return the HTML for a resource type section"""
    html_parts = [f"""
        <div class="resource-type vulnerability-view">
            <h2>{escape(resource_type)}</h2>
    """]
    
    # Process each finding
    for finding_name, resources in findings.items():
        # Convert finding name to display name
        display_name = (finding_name
            .replace('sql_server_', 'SQL Server ')
            .replace('key_vault_', 'Key Vault ')
            .replace('app_service_', 'App Service ')
            .replace('network_security_group_', 'Network Security Group ')
            .replace('storage_account_', 'Storage Account ')
            .replace('cosmos_db_', 'Cosmos DB ')
            .replace('mysql_server_', 'MySQL Server ')
            .replace('postgresql_server_', 'PostgreSQL Server ')
            .replace('_', ' ')
            .title())
        
        # Determine severity
        severity = "high" if any(kw in finding_name.lower() for kw in ['public', 'unrestricted']) else \
                  "medium" if any(kw in finding_name.lower() for kw in ['sensitive']) else "low"
        
        html_parts.append(f"""
            <div class="finding">
                <span class="severity-badge {escape(severity)}">{escape(severity.upper())}</span>
                {escape(display_name)}
                <div class="affected-resources">
        """)
        
        if resources:
            html_parts.append(f"""
                    Affected resources ({len(resources)}):
                    <ul>
            """)
            # Add each affected resource
            for resource in sorted(set(resources)):
                html_parts.append(f"<li>{escape(resource)}</li>")
            html_parts.append("</ul>")
        else:
            html_parts.append("<p>No resources vulnerable</p>")
        
        html_parts.append("</div></div>")
    
    html_parts.append("</div>")
    return '\n'.join(html_parts)

def _get_html_header(subscription_name):
    """Return the HTML header section"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Assessment Report</title>
        {_get_css_styles()}
    </head>
    <body>
        <div class="container">
            <h1>Security Assessment Report</h1>
            <div class="subtitle">{escape(subscription_name)}</div>
            <div class="subtitle">Generated: {escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</div>
            
            <div class="view-toggle">
                <button id="vulnView" class="toggle-btn active">View by Vulnerability</button>
                <button id="resourceView" class="toggle-btn">View by Resource</button>
            </div>
            
            <input type="text" class="search-input" 
                   placeholder="Search findings (e.g., 'high severity', 'NSG', 'encryption')...">
    """

def _get_css_styles():
    """Return the CSS styles"""
    return """
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 2rem;
                background: #f5f6fa;
                color: #2d3436;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                padding: 2rem;
                border-radius: 12px;
                box-shadow: 0 2px 12px rgba(0,0,0,0.05);
            }
            h1 {
                font-size: 2.5rem;
                font-weight: 600;
                margin: 0 0 0.5rem 0;
                color: #2d3436;
            }
            .subtitle {
                color: #636e72;
                font-size: 0.95rem;
                margin-bottom: 0.5rem;
            }
            .view-toggle {
                margin: 2rem 0;
                display: flex;
                gap: 0.5rem;
            }
            .toggle-btn {
                padding: 0.6rem 1.2rem;
                font-size: 0.95rem;
                font-weight: 500;
                border: 1px solid #dfe6e9;
                border-radius: 6px;
                background: white;
                color: #636e72;
                cursor: pointer;
                transition: all 0.2s ease;
            }
            .toggle-btn:hover {
                background: #f5f6fa;
            }
            .toggle-btn.active {
                background: #0984e3;
                color: white;
                border-color: #0984e3;
            }
            .search-input {
                width: 100%;
                padding: 0.8rem 1rem;
                font-size: 0.95rem;
                border: 1px solid #dfe6e9;
                border-radius: 6px;
                margin: 1rem 0;
                transition: all 0.2s ease;
            }
            .search-input:focus {
                outline: none;
                border-color: #0984e3;
                box-shadow: 0 0 0 3px rgba(9,132,227,0.1);
            }
            .executive-summary {
                margin: 2rem 0;
                padding: 1.5rem;
                background: white;
                border-radius: 8px;
                border: 1px solid #dfe6e9;
            }
            .summary-grid {
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 1rem;
                margin-top: 1rem;
            }
            .summary-item {
                padding: 1.2rem;
                text-align: center;
                background: #f5f6fa;
                border-radius: 8px;
                transition: transform 0.2s ease;
            }
            .summary-item:hover {
                transform: translateY(-2px);
            }
            .summary-item h3 {
                font-size: 0.85rem;
                color: #636e72;
                margin: 0;
                font-weight: 500;
            }
            .summary-item .number {
                font-size: 2rem;
                font-weight: 600;
                margin: 0.5rem 0;
            }
            .high { color: #e74c3c; }
            .medium { color: #f1c40f; }
            .low { color: #27ae60; }
            
            /* Resource View Styles */
            .resource-block {
                background: white;
                padding: 1.5rem;
                margin: 1rem 0;
                border: 1px solid #dfe6e9;
                border-radius: 8px;
                transition: box-shadow 0.2s ease;
            }
            .resource-block:hover {
                box-shadow: 0 4px 12px rgba(0,0,0,0.05);
            }
            .resource-block h3 {
                font-size: 1.1rem;
                color: #2d3436;
                margin: 0 0 1rem 0;
                font-weight: 600;
            }
            .vulnerabilities h4 {
                font-size: 0.9rem;
                color: #636e72;
                margin: 0.5rem 0;
            }
            .vulnerabilities ul {
                list-style: none;
                padding: 0;
                margin: 0.5rem 0;
            }
            .vulnerabilities li {
                padding: 0.8rem 1rem;
                margin: 0.5rem 0;
                background: #f5f6fa;
                border-radius: 6px;
                display: flex;
                align-items: center;
                gap: 0.8rem;
                transition: background-color 0.2s ease;
            }
            .vulnerabilities li:hover {
                background: #edf0f7;
            }
            .severity-badge {
                display: inline-block;
                padding: 0.3rem 0.8rem;
                border-radius: 4px;
                font-size: 0.8rem;
                font-weight: 500;
                text-transform: uppercase;
                min-width: 60px;
                text-align: center;
            }
            .severity-badge.high {
                background: #ff7675;
                color: white;
            }
            .severity-badge.medium {
                background: #ffeaa7;
                color: #2d3436;
            }
            .severity-badge.low {
                background: #55efc4;
                color: #2d3436;
            }
            
            /* Responsive Design */
            @media (max-width: 768px) {
                .summary-grid {
                    grid-template-columns: repeat(2, 1fr);
                }
                .container {
                    padding: 1rem;
                }
                h1 {
                    font-size: 2rem;
                }
            }
        </style>
    """

def _get_executive_summary(total_findings, high_severity, medium_severity, low_severity, resource_types):
    """Return the executive summary section"""
    return f"""
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>Total Findings</h3>
                    <div class="number">{total_findings}</div>
                </div>
                <div class="summary-item">
                    <h3>High Severity</h3>
                    <div class="number high">{high_severity}</div>
                </div>
                <div class="summary-item">
                    <h3>Medium Severity</h3>
                    <div class="number medium">{medium_severity}</div>
                </div>
                <div class="summary-item">
                    <h3>Low Severity</h3>
                    <div class="number low">{low_severity}</div>
                </div>
                <div class="summary-item">
                    <h3>Resource Types Affected</h3>
                    <div class="number">{resource_types}</div>
                </div>
            </div>
        </div>
    """

def _get_resource_overview_section(resource_type, overview_file):
    """Return the HTML for a resource overview section"""
    html_parts = [f"""
        <div class="resource-type resource-view">
            <h2>{escape(resource_type)}</h2>
    """]
    
    resources_dict = {}
    
    # Read the overview file
    if overview_file.exists():
        with open(overview_file, 'r') as f:
            # Skip header if present
            header = f.readline()
            for line in f:
                if line.strip():
                    # Split on comma and handle potential semicolon-separated vulnerabilities
                    parts = line.strip().split(',', 1)  # Split only on first comma
                    if len(parts) >= 2:
                        resource = parts[0].strip()
                        vulns = [v.strip() for v in parts[1].split(';') if v.strip()]
                        if vulns:  # Only add if there are vulnerabilities
                            resources_dict[resource] = vulns
    
    # Generate HTML for each resource
    for resource, vulns in sorted(resources_dict.items()):
        html_parts.append(f"""
            <div class="resource-block">
                <h3>{escape(resource)}</h3>
                <div class="vulnerabilities">
                    <h4>Vulnerabilities Found ({len(vulns)}):</h4>
                    <ul>
        """)
        
        # Sort vulnerabilities by severity and name
        sorted_vulns = sorted(vulns, key=lambda x: (
            0 if any(kw in x.lower() for kw in ['critical', 'high', 'severe', 'unrestricted', 'public']) else
            1 if any(kw in x.lower() for kw in ['warning', 'medium', 'sensitive']) else 2,
            x.lower()
        ))
        
        for vuln in sorted_vulns:
            # Determine severity for each vulnerability
            severity = "high" if any(kw in vuln.lower() for kw in [
                'critical', 'high', 'severe', 'unrestricted', 'public'
            ]) else "medium" if any(kw in vuln.lower() for kw in [
                'warning', 'medium', 'sensitive'
            ]) else "low"
            
            html_parts.append(f"""
                <li>
                    <span class="severity-badge {escape(severity)}">{escape(severity.upper())}</span>
                    {escape(vuln)}
                </li>
            """)
        
        html_parts.append("""
                    </ul>
                </div>
            </div>
        """)
    
    html_parts.append("</div>")
    return '\n'.join(html_parts)

def _get_javascript():
    return """
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const vulnView = document.getElementById('vulnView');
                const resourceView = document.getElementById('resourceView');
                const vulnSections = document.querySelectorAll('.vulnerability-view');
                const resourceSections = document.querySelectorAll('.resource-view');
                
                function showVulnView() {
                    vulnView.classList.add('active');
                    resourceView.classList.remove('active');
                    vulnSections.forEach(section => {
                        section.style.display = 'block';
                        section.style.opacity = '1';
                    });
                    resourceSections.forEach(section => {
                        section.style.opacity = '0';
                        section.style.display = 'none';
                    });
                }
                
                function showResourceView() {
                    resourceView.classList.add('active');
                    vulnView.classList.remove('active');
                    vulnSections.forEach(section => {
                        section.style.opacity = '0';
                        section.style.display = 'none';
                    });
                    resourceSections.forEach(section => {
                        section.style.display = 'block';
                        section.style.opacity = '1';
                    });
                }
                
                // Set initial view
                showVulnView();
                
                // Add click handlers
                vulnView.addEventListener('click', showVulnView);
                resourceView.addEventListener('click', showResourceView);
                
                // Add search functionality
                const searchInput = document.querySelector('.search-input');
                searchInput.addEventListener('input', function(e) {
                    const searchTerm = e.target.value.toLowerCase();
                    const currentView = vulnView.classList.contains('active') ? 'vulnerability' : 'resource';
                    const sections = currentView === 'vulnerability' ? 
                        document.querySelectorAll('.finding') : 
                        document.querySelectorAll('.resource-block');
                    
                    sections.forEach(section => {
                        const text = section.textContent.toLowerCase();
                        section.style.display = text.includes(searchTerm) ? 'block' : 'none';
                    });
                });
            });
        </script>
    """
# -*- coding: utf-8 -*-
"""
Report Generator for AzureSecuritySuite
Copyright (c) 2025 D4rkm4g1c. All Rights Reserved.

PROPRIETARY SOFTWARE - PERSONAL INTELLECTUAL PROPERTY
This software was developed independently during personal time.
No employer or company has any rights to this software.

For licensing inquiries, contact the copyright holder.
"""
import logging
from pathlib import Path
from html import escape
from datetime import datetime
from colorama import Fore, Style

def generate_html_report(tenant_name):
    """Generate a simplified HTML report for all scan results"""
    try:
        print(f"\n{Fore.CYAN}Generating HTML report...{Style.RESET_ALL}")
        
        scan_dir = Path(tenant_name)
        if not scan_dir.exists():
            print(f"{Fore.RED}Tenant directory not found: {scan_dir}{Style.RESET_ALL}")
            return False
            
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
                        # Get vulnerability name from file name
                        finding_name = csv_file.stem.replace('_', ' ').title()
                        
                        # Read affected resources from the CSV file
                        with open(csv_file, 'r') as f:
                            resources = [line.strip() for line in f if line.strip()]
                            # Always add the finding, even if no resources are affected
                            findings[finding_name] = resources
                
                if findings:  # If we found any vulnerability files
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

def _get_html_header(subscription_name):
    """Return the HTML header with styling"""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Assessment Report</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        
        <style>
            /* Base Styles */
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 2rem;
                background: #f7f9fc;
                color: #2c3e50;
            }}
            
            /* Container */
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background: #ffffff;
                padding: 2.5rem;
                border-radius: 8px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            }}
            
            /* Header */
            .report-header {{
                margin-bottom: 2rem;
                text-align: center;
                border-bottom: 2px solid #3498db;
                padding-bottom: 2rem;
            }}
            
            h1, h2, h3, h4 {{
                color: #2c3e50;
                letter-spacing: -0.5px;
            }}
            
            h1 {{ font-size: 2.8rem; font-weight: 700; margin: 0 0 1.5rem 0; color: #1e5180; }}
            h2 {{ font-size: 1.8rem; font-weight: 600; margin: 2rem 0 1rem; color: #1e5180; }}
            h3 {{ font-size: 1.4rem; font-weight: 600; margin: 1.5rem 0 0.75rem; }}
            
            /* Navigation */
            .navigation-tabs {{
                display: flex;
                justify-content: center;
                gap: 1rem;
                margin: 2rem 0;
            }}
            
            .tab-btn {{
                padding: 1rem 2rem;
                font-size: 1.1rem;
                font-weight: 500;
                border: none;
                border-radius: 6px;
                background: #f1f5f9;
                color: #2c3e50;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                gap: 0.75rem;
            }}
            
            .tab-btn:hover {{
                background: #e1eaf1;
                transform: translateY(-2px);
            }}
            
            .tab-btn.active {{
                background: #3498db;
                color: #ffffff;
                box-shadow: 0 4px 12px rgba(52, 152, 219, 0.2);
            }}
            
            /* Search */
            .search-container {{
                position: relative;
                margin: 2rem auto;
                max-width: 800px;
            }}
            
            .search-input {{
                width: 100%;
                padding: 1.2rem 1.2rem 1.2rem 3.5rem;
                font-size: 1.1rem;
                border: 1px solid #dfe6e9;
                border-radius: 6px;
                background: #ffffff;
                color: #2c3e50;
                transition: all 0.3s ease;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            }}
            
            .search-input:focus {{
                border-color: #3498db;
                outline: none;
                box-shadow: 0 1px 3px rgba(52, 152, 219, 0.2);
            }}
            
            /* Findings */
            .finding {{
                border: 1px solid #e1eaf1;
                margin: 1rem 0;
                padding: 1.5rem;
                border-radius: 6px;
                background: #ffffff;
                transition: all 0.3s ease;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            }}
            
            .finding:hover {{
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
                border-color: #3498db;
            }}
            
            .finding-name {{
                font-size: 1.1rem;
                font-weight: 600;
                color: #3498db;
                margin-bottom: 1rem;
            }}
            
            /* Resource View */
            .resource-type-header {{
                display: flex;
                align-items: center;
                gap: 1rem;
                margin-bottom: 2rem;
            }}
            
            .resource-type-header i {{
                color: #3498db;
            }}
            
            .resource-card {{
                background: #ffffff;
                border: 1px solid #e1eaf1;
                border-radius: 6px;
                padding: 1.5rem;
                margin-bottom: 1.5rem;
                transition: all 0.3s ease;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            }}
            
            .resource-card:hover {{
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
                border-color: #3498db;
            }}
            
            .resource-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 1rem;
                padding-bottom: 0.5rem;
                border-bottom: 1px solid rgba(52, 152, 219, 0.2);
            }}
            
            .finding-count {{
                font-size: 0.9rem;
                color: #ffffff;
                background: #3498db;
                padding: 0.3rem 0.8rem;
                border-radius: 20px;
            }}
            
            /* Dark Mode */
            body.dark-mode {{
                background: #1e2a3a;
                color: #f1f5f9;
            }}
            
            .dark-mode .container,
            .dark-mode .resource-card,
            .dark-mode .finding {{
                background: #2c3e50;
                border-color: #3498db;
            }}
            
            .dark-mode h1, 
            .dark-mode h2, 
            .dark-mode h3, 
            .dark-mode h4 {{
                color: #f1f5f9;
            }}
            
            .dark-mode h1,
            .dark-mode h2 {{
                color: #3498db;
            }}
            
            .dark-mode .finding-name {{
                color: #3498db;
            }}
            
            .dark-mode .search-input {{
                background: #2c3e50;
                color: #f1f5f9;
                border-color: #4b6584;
            }}
            
            .dark-mode .tab-btn {{
                background: #34495e;
                color: #f1f5f9;
            }}
            
            .dark-mode .tab-btn.active {{
                background: #3498db;
                color: #ffffff;
            }}
            
            /* Theme Toggle */
            .theme-toggle {{
                position: fixed;
                top: 1rem;
                right: 1rem;
            }}
            
            .theme-btn {{
                background: none;
                border: none;
                color: #2c3e50;
                font-size: 1.5rem;
                cursor: pointer;
                padding: 0.5rem;
                border-radius: 50%;
                transition: all 0.3s ease;
            }}
            
            .dark-mode .theme-btn {{
                color: #f1f5f9;
            }}
            
            /* Responsive Design */
            @media (max-width: 768px) {{
                .container {{
                    padding: 1rem;
                }}
                
                h1 {{
                    font-size: 2rem;
                }}
            }}
            
            /* Executive Summary */
            .executive-summary {{
                background: #f8fafc;
                padding: 2.5rem;
                border-radius: 8px;
                margin: 3rem 0;
                border: 1px solid #e1eaf1;
            }}
            
            .summary-grid {{
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 1.5rem;
                margin-top: 2rem;
            }}
            
            .summary-item {{
                background: #ffffff;
                padding: 1.5rem;
                border-radius: 8px;
                text-align: center;
                box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
                transition: transform 0.3s ease;
                border: 1px solid #e1eaf1;
            }}
            
            .summary-item:hover {{
                transform: translateY(-4px);
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
                border-color: #3498db;
            }}
            
            .summary-item .number {{
                font-size: 2rem;
                font-weight: 700;
                color: #3498db;
                margin-top: 0.5rem;
            }}
            
            .dark-mode .executive-summary,
            .dark-mode .summary-item {{
                background: #34495e;
                border-color: #3498db;
            }}
            
            .dark-mode .summary-item .number {{
                color: #3498db;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="theme-toggle">
                <button id="themeToggle" class="theme-btn">
                    <i class="fas fa-moon"></i>
                </button>
            </div>
            <div class="report-header">
                <div class="header-content">
                    <h1>Security Assessment Report</h1>
                    <div class="subtitle">{escape(subscription_name)}</div>
                    <div class="subtitle">
                        <i class="far fa-calendar-alt"></i> 
                        Generated: {current_time}
                    </div>
                </div>
            </div>
            
            <div class="navigation-tabs">
                <button id="vulnView" class="tab-btn active">
                    <i class="fas fa-shield-alt"></i> View by Vulnerability
                </button>
                <button id="resourceView" class="tab-btn">
                    <i class="fas fa-server"></i> View by Resource
                </button>
            </div>
            
            <div class="search-container">
                <i class="fas fa-search search-icon"></i>
                <input type="text" class="search-input" 
                       placeholder="Search findings (e.g., 'NSG', 'encryption')...">
            </div>
    """

def _get_executive_summary(total_findings, affected_resource_types, affected_resources):
    """Return the executive summary HTML"""
    return f"""
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <h3>Total Findings</h3>
                    <div class="number">{total_findings}</div>
                </div>
                <div class="summary-item">
                    <h3>Resource Types Affected</h3>
                    <div class="number">{affected_resource_types}</div>
                </div>
                <div class="summary-item">
                    <h3>Resources Affected</h3>
                    <div class="number">{affected_resources}</div>
                </div>
            </div>
        </div>
    """

def _get_javascript():
    """Return the JavaScript code"""
    return """
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                // View toggle functionality
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
                
                // Search functionality
                const searchInput = document.querySelector('.search-input');
                searchInput.addEventListener('input', function(e) {
                    const searchTerm = e.target.value.toLowerCase();
                    const currentView = vulnView.classList.contains('active') ? 'vulnerability' : 'resource';
                    const sections = currentView === 'vulnerability' ? 
                        document.querySelectorAll('.finding') : 
                        document.querySelectorAll('.resource-card');
                    
                    sections.forEach(section => {
                        const text = section.textContent.toLowerCase();
                        section.style.display = text.includes(searchTerm) ? 'block' : 'none';
                    });
                });
                
                // Dark mode toggle
                const themeToggle = document.getElementById('themeToggle');
                const body = document.body;
                const icon = themeToggle.querySelector('i');
                
                // Check for saved theme preference
                if (localStorage.getItem('darkMode') === 'enabled') {
                    body.classList.add('dark-mode');
                    icon.classList.replace('fa-moon', 'fa-sun');
                }
                
                themeToggle.addEventListener('click', () => {
                    body.classList.toggle('dark-mode');
                    
                    if (body.classList.contains('dark-mode')) {
                        icon.classList.replace('fa-moon', 'fa-sun');
                        localStorage.setItem('darkMode', 'enabled');
                    } else {
                        icon.classList.replace('fa-sun', 'fa-moon');
                        localStorage.removeItem('darkMode');
                    }
                });
            });
        </script>
    """

def _get_resource_icon(resource_type):
    """Return the appropriate Font Awesome icon class for a resource type"""
    icon_map = {
        'AppServices': 'fa-globe',
        'SQLDatabases': 'fa-table',
        'KeyVaults': 'fa-key',
        'NetworkSecurityGroups': 'fa-shield-alt',
        'PostgreSQLDatabases': 'fa-database',
        'MySQLDatabases': 'fa-database',
        'CosmosDB': 'fa-atom'
    }
    return icon_map.get(resource_type, 'fa-cube')

def _create_html_report(subscription_dir, subscription_name, findings_by_type):
    """Create the HTML report for a subscription"""
    try:
        report_file = subscription_dir / 'security_report.html'
        
        # Calculate statistics for executive summary
        total_findings = sum(len(findings) for findings in findings_by_type.values())
        affected_resource_types = len(findings_by_type)
        
        # Calculate affected resources
        affected_resources = set()
        for findings in findings_by_type.values():
            for resources in findings.values():
                if resources:  # Only count resources that are actually affected
                    affected_resources.update(resources)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            # Write HTML header
            f.write(_get_html_header(subscription_name))
            
            # Write executive summary with three statistics
            f.write(_get_executive_summary(
                total_findings,
                affected_resource_types,
                len(affected_resources)
            ))
            
            # Write vulnerability view
            for resource_type, findings in findings_by_type.items():
                icon_class = _get_resource_icon(resource_type)
                f.write(f"""
                    <div class="resource-type vulnerability-view">
                        <div class="resource-type-header">
                            <i class="fas {icon_class} resource-icon"></i>
                            <h2>{escape(resource_type)}</h2>
                        </div>
                """)
                
                for finding_name, resources in findings.items():
                    f.write(f"""
                        <div class="finding">
                            <div class="finding-name">{escape(finding_name)}</div>
                            <div class="affected-resources">
                    """)
                    
                    if resources:
                        f.write("""
                            <div class="resources" onclick="navigator.clipboard.writeText(this.textContent)">
                        """)
                        f.write(escape(", ".join(sorted(resources))))
                        f.write("</div>")
                    else:
                        f.write("<p>No affected resources</p>")
                    
                    f.write("</div></div>")
                
                f.write("</div>")
            
            # Write resource view
            for resource_type, findings in findings_by_type.items():
                icon_class = _get_resource_icon(resource_type)
                f.write(f"""
                    <div class="resource-type resource-view">
                        <div class="resource-type-header">
                            <i class="fas {icon_class} resource-icon"></i>
                            <h2>{escape(resource_type)}</h2>
                        </div>
                """)
                
                # Get all unique resources
                all_resources = set()
                resource_findings = {}
                
                # Collect all resources and their findings
                for finding_name, resources in findings.items():
                    for resource in resources:
                        all_resources.add(resource)
                        if resource not in resource_findings:
                            resource_findings[resource] = []
                        resource_findings[resource].append(finding_name)
                
                if all_resources:
                    for resource_name in sorted(all_resources):
                        vulns = resource_findings.get(resource_name, [])
                        f.write(f"""
                            <div class="resource-card">
                                <div class="resource-header">
                                    <h3>{escape(resource_name)}</h3>
                                    <div class="finding-count">
                                        {len(vulns)} finding{'s' if len(vulns) != 1 else ''}
                                    </div>
                                </div>
                                <div class="findings-container">
                                    <div class="vuln-list">
                        """)
                        
                        if vulns:
                            f.write(", ".join(escape(vuln) for vuln in sorted(vulns)))
                        else:
                            f.write("No findings")
                        
                        f.write("</div></div></div>")
                else:
                    f.write("<p>No resources found</p>")
                
                f.write("</div>")
            
            # Close the container and add JavaScript
            f.write("</div></body>")
            f.write(_get_javascript())
            f.write("</html>")
            
        print(f"{Fore.GREEN}✓ Report generated: {report_file}{Style.RESET_ALL}")
        return True
        
    except Exception as e:
        print(f"{Fore.RED}Error creating HTML report: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error creating HTML report: {str(e)}")
        return False
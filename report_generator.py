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
        
        html_parts.append(f"""
            <div class="finding">
                <div class="finding-name">{escape(display_name)}</div>
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
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        {_get_css_styles()}
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
                        Generated: {escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
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

def _get_css_styles():
    """Return the CSS styles"""
    return """
        <style>
            /* Base Styles */
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 2rem;
                background: #ffffff;
                color: #2d3436;
            }
            
            /* Container */
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: #ffffff;
                padding: 2.5rem;
                border-radius: 16px;
                box-shadow: 0 4px 6px rgba(176, 211, 81, 0.1);
            }
            
            /* Header */
            .report-header {
                margin-bottom: 2rem;
                text-align: center;
                border-bottom: 2px solid #b0d351;
                padding-bottom: 2rem;
            }
            
            h1, h2, h3, h4 {
                color: #2d3436;
                letter-spacing: -0.5px;
            }
            
            h1 { font-size: 2.8rem; font-weight: 700; margin: 0 0 1.5rem 0; }
            h2 { font-size: 1.8rem; font-weight: 600; margin: 2rem 0 1rem; }
            h3 { font-size: 1.4rem; font-weight: 600; margin: 1.5rem 0 0.75rem; }
            
            /* Info Items */
            .subscription-info {
                display: flex;
                justify-content: center;
                gap: 2rem;
                margin: 1rem 0;
                flex-wrap: wrap;
            }
            
            .info-item {
                display: flex;
                align-items: center;
                gap: 0.5rem;
                color: #64748b;
                font-size: 1.1rem;
            }
            
            .info-item i {
                color: #b0d351;
            }
            
            /* Navigation */
            .navigation-tabs {
                display: flex;
                justify-content: center;
                gap: 1rem;
                margin: 2rem 0;
            }
            
            .tab-btn {
                padding: 1rem 2rem;
                font-size: 1.1rem;
                font-weight: 500;
                border: none;
                border-radius: 12px;
                background: #f8f9fa;
                color: #2d3436;
                cursor: pointer;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                gap: 0.75rem;
            }
            
            .tab-btn:hover {
                background: #b0d351;
                color: #ffffff;
                transform: translateY(-2px);
            }
            
            .tab-btn.active {
                background: #b0d351;
                color: #ffffff;
                box-shadow: 0 4px 12px rgba(176, 211, 81, 0.2);
            }
            .search-container {
                position: relative;
                margin: 2rem auto;
                max-width: 800px;
            }
            .search-input {
                width: 100%;
                padding: 1.2rem 1.2rem 1.2rem 3.5rem;
                font-size: 1.1rem;
                border: 2px solid #b0d351;
                border-radius: 12px;
                background: #ffffff;
                color: #2d3436;
                transition: all 0.3s ease;
            }
            .search-input:focus {
                outline: none;
                border-color: #b0d351;
                box-shadow: 0 0 0 4px rgba(176, 211, 81, 0.1);
            }
            .executive-summary {
                background: #ffffff;
                padding: 2.5rem;
                border-radius: 16px;
                margin: 3rem 0;
                border: 2px solid #b0d351;
            }
            .summary-grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 1.5rem;
                margin-top: 2rem;
            }
            .summary-item {
                background: #ffffff;
                padding: 1.5rem;
                border-radius: 12px;
                text-align: center;
                box-shadow: 0 2px 4px rgba(176, 211, 81, 0.15);
                transition: transform 0.3s ease;
                border: 1px solid #b0d351;
            }
            .summary-item:hover {
                transform: translateY(-4px);
                box-shadow: 0 4px 12px rgba(176, 211, 81, 0.2);
            }
            .finding {
                border: 1px solid #b0d351;
                margin: 1rem 0;
                padding: 1.5rem;
                border-radius: 12px;
                background: #ffffff;
                transition: all 0.3s ease;
            }
            .finding:hover {
                box-shadow: 0 4px 12px rgba(176, 211, 81, 0.15);
            }
            .finding-name {
                font-size: 1.1rem;
                font-weight: 600;
                color: #2d3436;
                margin-bottom: 1rem;
            }
            .affected-resources {
                color: #64748b;
            }
            .affected-resources ul {
                margin: 0.5rem 0;
                padding-left: 1.5rem;
            }
            .affected-resources li {
                margin: 0.25rem 0;
            }
            @media (max-width: 768px) {
                .summary-grid {
                    grid-template-columns: 1fr;
                }
            }
            /* Dark mode styles */
            .theme-toggle {
                position: absolute;
                top: 2rem;
                right: 2rem;
            }
            
            .theme-btn {
                background: none;
                border: none;
                font-size: 1.5rem;
                color: #b0d351;
                cursor: pointer;
                padding: 0.5rem;
                border-radius: 50%;
                transition: all 0.3s ease;
            }
            
            .theme-btn:hover {
                transform: scale(1.1);
            }
            
            /* Dark mode classes */
            body.dark-mode {
                background: #444444;
                color: #ffffff;
            }
            
            .dark-mode .container {
                background: #444444;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
            }
            
            .dark-mode h1, 
            .dark-mode h2, 
            .dark-mode h3, 
            .dark-mode h4 {
                color: #ffffff;
            }
            
            .dark-mode .finding {
                background: #444444;
                border-color: #bcd03e;
            }
            
            .dark-mode .finding-name {
                color: #ffffff;
            }
            
            .dark-mode .search-input {
                background: #444444;
                color: #ffffff;
                border-color: #bcd03e;
            }
            
            .dark-mode .tab-btn {
                background: #555555;
                color: #ffffff;
            }
            
            .dark-mode .tab-btn.active {
                background: #bcd03e;
                color: #444444;
            }
            
            .dark-mode .executive-summary {
                background: #444444;
                border-color: #bcd03e;
            }
            
            .dark-mode .summary-item {
                background: #444444;
                border-color: #bcd03e;
                color: #ffffff;
            }
            
            .dark-mode .info-item {
                color: #ffffff;
            }
            
            .dark-mode .info-item i {
                color: #bcd03e;
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
                
                // Dark mode toggle
                const themeToggle = document.getElementById('themeToggle');
                const body = document.body;
                const icon = themeToggle.querySelector('i');
                
                // Check for saved theme preference
                const darkMode = localStorage.getItem('darkMode');
                if (darkMode === 'enabled') {
                    body.classList.add('dark-mode');
                    icon.classList.remove('fa-moon');
                    icon.classList.add('fa-sun');
                }
                
                themeToggle.addEventListener('click', () => {
                    body.classList.toggle('dark-mode');
                    
                    // Update icon
                    if (body.classList.contains('dark-mode')) {
                        icon.classList.remove('fa-moon');
                        icon.classList.add('fa-sun');
                        localStorage.setItem('darkMode', 'enabled');
                    } else {
                        icon.classList.remove('fa-sun');
                        icon.classList.add('fa-moon');
                        localStorage.setItem('darkMode', null);
                    }
                });
            });
        </script>
    """

def _get_additional_css():
    return """
        .report-header {
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #eee;
        }
        .header-content {
            flex: 1;
        }
        .navigation-tabs {
            display: flex;
            gap: 1rem;
            margin: 2rem 0;
        }
        .tab-btn {
            padding: 0.8rem 1.5rem;
            font-size: 1rem;
            border: none;
            border-radius: 6px;
            background: #f5f6fa;
            color: #636e72;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .tab-btn.active {
            background: #0984e3;
            color: white;
        }
        .search-container {
            position: relative;
            margin: 2rem 0;
        }
        .search-icon {
            position: absolute;
            left: 1rem;
            top: 50%;
            transform: translateY(-50%);
            color: #636e72;
        }
        .search-input {
            padding-left: 2.5rem;
        }
        .search-filters {
            display: flex;
            gap: 1rem;
            margin-top: 1rem;
        }
        .filter-btn {
            padding: 0.4rem 1rem;
            border: 1px solid #dfe6e9;
            border-radius: 20px;
            background: white;
            color: #636e72;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .filter-btn:hover {
            background: #f5f6fa;
        }
        .filter-btn.active {
            background: #f5f6fa;
            border-color: #0984e3;
            color: #0984e3;
        }
        .severity-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }
        .severity-dot.high { background: #ff7675; }
        .severity-dot.medium { background: #ffeaa7; }
        .severity-dot.low { background: #55efc4; }
    """
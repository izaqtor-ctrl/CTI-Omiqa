import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests
import json
import hashlib
from typing import Dict, List, Optional
import time

# Configure page
st.set_page_config(
    page_title="SME Threat Intelligence Platform - POC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
.metric-container {
    background-color: #f0f2f6;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #1f77b4;
}
.high-risk { border-left-color: #ff4444; }
.medium-risk { border-left-color: #ff8800; }
.low-risk { border-left-color: #44ff44; }

.threat-card {
    background: white;
    padding: 1rem;
    border-radius: 0.5rem;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin: 0.5rem 0;
}
</style>
""", unsafe_allow_html=True)

class ThreatIntelligencePlatform:
    def __init__(self):
        self.feeds = {
            'abuse_ch_urlhaus': 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/',
            'abuse_ch_malware': 'https://mb-api.abuse.ch/api/v1/',
            'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        }
        self.initialize_session_state()
    
    def initialize_session_state(self):
        if 'threats_data' not in st.session_state:
            st.session_state.threats_data = []
        if 'last_update' not in st.session_state:
            st.session_state.last_update = None
        if 'company_profile' not in st.session_state:
            st.session_state.company_profile = {
                'industry': 'Technology',
                'size': '50-200',
                'tech_stack': ['Microsoft 365', 'Windows', 'Cloud'],
                'geography': 'North America'
            }
    
    def fetch_abuse_ch_data(self) -> List[Dict]:
        """Fetch recent malicious URLs from Abuse.ch URLhaus"""
        try:
            # Use the correct API endpoint for recent URLs
            response = requests.get('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/50/', timeout=15)
            if response.status_code == 200:
                data = response.json()
                threats = []
                
                # Check if we have the expected data structure
                if 'urls' in data and isinstance(data['urls'], list):
                    for url_data in data['urls']:
                        if not url_data or 'url' not in url_data:
                            continue
                            
                        threat = {
                            'id': hashlib.md5(url_data['url'].encode()).hexdigest()[:8],
                            'type': 'malicious_url',
                            'value': url_data['url'],
                            'source': 'Abuse.ch URLhaus',
                            'confidence': 85,
                            'first_seen': url_data.get('date_added', ''),
                            'threat_type': url_data.get('threat', 'malware'),
                            'tags': url_data.get('tags', []) if url_data.get('tags') else [],
                            'status': url_data.get('url_status', 'unknown'),
                            'relevance_score': self.calculate_relevance_score(url_data),
                            'action_recommended': 'Block URL in web filter/firewall'
                        }
                        threats.append(threat)
                else:
                    st.warning("Unexpected data structure from Abuse.ch API")
                    
                return threats[:25]  # Limit for POC performance
        except requests.exceptions.RequestException as e:
            st.error(f"Network error fetching Abuse.ch data: {e}")
        except Exception as e:
            st.error(f"Error processing Abuse.ch data: {e}")
        return []
    
    def fetch_cisa_kev_data(self) -> List[Dict]:
        """Fetch CISA Known Exploited Vulnerabilities"""
        try:
            response = requests.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 
                                   timeout=15)
            if response.status_code == 200:
                data = response.json()
                threats = []
                
                # Get recent vulnerabilities (sort by date added)
                vulns = data.get('vulnerabilities', [])
                # Sort by dateAdded (most recent first)
                vulns_sorted = sorted(vulns, 
                                    key=lambda x: x.get('dateAdded', '1900-01-01'), 
                                    reverse=True)
                
                for vuln in vulns_sorted[:15]:  # Get 15 most recent
                    # Calculate days since added
                    date_added = vuln.get('dateAdded', '')
                    days_old = self.calculate_days_since(date_added)
                    
                    threat = {
                        'id': vuln.get('cveID', 'UNKNOWN'),
                        'type': 'vulnerability',
                        'value': vuln.get('cveID', 'UNKNOWN'),
                        'source': 'CISA KEV',
                        'confidence': 95,
                        'first_seen': date_added,
                        'threat_type': 'critical_vulnerability',
                        'description': vuln.get('shortDescription', '')[:200] + '...' if len(vuln.get('shortDescription', '')) > 200 else vuln.get('shortDescription', ''),
                        'vendor': vuln.get('vendorProject', ''),
                        'product': vuln.get('product', ''),
                        'due_date': vuln.get('dueDate', ''),
                        'days_old': days_old,
                        'relevance_score': self.calculate_vuln_relevance(vuln),
                        'action_recommended': f"Emergency patch required by {vuln.get('dueDate', 'ASAP')}"
                    }
                    threats.append(threat)
                return threats
        except requests.exceptions.RequestException as e:
            st.error(f"Network error fetching CISA KEV data: {e}")
        except Exception as e:
            st.error(f"Error processing CISA KEV data: {e}")
        return []
    
    def fetch_malware_bazaar_data(self) -> List[Dict]:
        """Fetch recent malware samples from Abuse.ch MalwareBazaar"""
        try:
            # Get recent malware samples
            payload = {'query': 'get_recent', 'selector': 'time'}
            response = requests.post('https://mb-api.abuse.ch/api/v1/', 
                                   data=payload, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                threats = []
                
                if 'data' in data and isinstance(data['data'], list):
                    for sample in data['data'][:10]:  # Limit for performance
                        if not sample:
                            continue
                            
                        threat = {
                            'id': sample.get('sha256_hash', 'unknown')[:8],
                            'type': 'malware_sample',
                            'value': sample.get('sha256_hash', 'unknown'),
                            'source': 'Abuse.ch MalwareBazaar',
                            'confidence': 90,
                            'first_seen': sample.get('first_seen', ''),
                            'threat_type': sample.get('signature', 'malware'),
                            'file_name': sample.get('file_name', ''),
                            'file_type': sample.get('file_type', ''),
                            'tags': sample.get('tags', []) if sample.get('tags') else [],
                            'relevance_score': self.calculate_malware_relevance(sample),
                            'action_recommended': f"Block hash {sample.get('sha256_hash', '')[:16]}... in EDR"
                        }
                        threats.append(threat)
                return threats
        except requests.exceptions.RequestException as e:
            st.error(f"Network error fetching MalwareBazaar data: {e}")
        except Exception as e:
            st.error(f"Error processing MalwareBazaar data: {e}")
        return []
    
    def calculate_relevance_score(self, threat_data: Dict) -> int:
        """Calculate relevance score based on company profile"""
        score = 50  # Base score
        
        # Industry-specific scoring
        if st.session_state.company_profile['industry'] == 'Technology':
            score += 20
        
        # Tech stack relevance - check the URL or threat data for keywords
        tech_keywords = ['microsoft', 'office', 'windows', 'cloud', 'login', 'auth']
        threat_text = str(threat_data).lower()
        url_text = threat_data.get('url', '').lower()
        
        for keyword in tech_keywords:
            if keyword in threat_text or keyword in url_text:
                score += 15
                break
        
        # Threat type severity
        threat_type = threat_data.get('threat', '').lower()
        if threat_type in ['malware', 'ransomware', 'phishing']:
            score += 25
        elif threat_type in ['trojan', 'backdoor']:
            score += 20
        
        # URL status - active threats are higher priority
        if threat_data.get('url_status') == 'online':
            score += 15
        
        return min(score, 100)
    
    def calculate_days_since(self, date_string: str) -> int:
        """Calculate days since a given date string"""
        try:
            from datetime import datetime
            # Handle different date formats
            for fmt in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%SZ']:
                try:
                    date_obj = datetime.strptime(date_string, fmt)
                    return (datetime.now() - date_obj).days
                except ValueError:
                    continue
            return 0
        except:
            return 0
    
    def calculate_malware_relevance(self, malware_data: Dict) -> int:
        """Calculate malware sample relevance score"""
        score = 60  # Base score for malware
        
        # Check signature/family relevance
        signature = malware_data.get('signature', '').lower()
        file_type = malware_data.get('file_type', '').lower()
        file_name = malware_data.get('file_name', '').lower()
        
        # Higher score for common business-targeting malware
        high_impact_families = ['emotet', 'trickbot', 'qbot', 'ransomware', 'backdoor', 'stealer', 'banker']
        for family in high_impact_families:
            if family in signature or family in file_name:
                score += 25
                break
        
        # Windows executables are more relevant for most SMEs
        if file_type in ['exe', 'dll', 'bat', 'ps1', 'msi']:
            score += 15
        
        # Office documents with macros
        if file_type in ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'] and 'macro' in signature:
            score += 20
        
        # Recent samples are more relevant
        first_seen = malware_data.get('first_seen', '')
        days_old = self.calculate_days_since(first_seen)
        if days_old < 7:
            score += 15
        elif days_old < 30:
            score += 10
        
        return min(score, 100)
    
    def calculate_vuln_relevance(self, vuln_data: Dict) -> int:
        """Calculate vulnerability relevance score"""
        score = 75  # Higher base score for KEV vulnerabilities (actively exploited)
        
        # Check if affects company's tech stack
        vendor = vuln_data.get('vendorProject', '').lower()
        product = vuln_data.get('product', '').lower()
        description = vuln_data.get('shortDescription', '').lower()
        
        tech_stack = [t.lower() for t in st.session_state.company_profile['tech_stack']]
        
        # Direct tech stack match
        for tech in tech_stack:
            if tech in vendor or tech in product or tech in description:
                score += 20
                break
        
        # Industry-specific vulnerabilities
        industry = st.session_state.company_profile['industry'].lower()
        if industry == 'technology':
            if any(keyword in description for keyword in ['remote', 'code execution', 'authentication']):
                score += 10
        
        # Recent vulnerabilities are higher priority
        date_added = vuln_data.get('dateAdded', '')
        days_old = self.calculate_days_since(date_added)
        if days_old < 30:
            score += 15
        elif days_old < 90:
            score += 10
        
        # Common business-critical products
        critical_products = ['windows', 'office', 'exchange', 'sharepoint', 'outlook', 'chrome', 'firefox']
        for prod in critical_products:
            if prod in product.lower() or prod in vendor.lower():
                score += 15
                break
        
        return min(score, 100)

def main():
    tip = ThreatIntelligencePlatform()
    
    # Sidebar
    st.sidebar.title("🛡️ TIP Control Panel")
    
    # Company Profile Setup
    with st.sidebar.expander("Company Profile", expanded=True):
        industry = st.selectbox(
            "Industry",
            ["Technology", "Healthcare", "Financial", "Manufacturing", "Retail"],
            index=0
        )
        
        company_size = st.selectbox(
            "Company Size",
            ["10-50", "50-200", "200-500", "500+"],
            index=1
        )
        
        tech_stack = st.multiselect(
            "Tech Stack",
            ["Microsoft 365", "Google Workspace", "Windows", "Mac", "Linux", "AWS", "Azure", "GCP"],
            default=["Microsoft 365", "Windows"]
        )
        
        # Update session state
        st.session_state.company_profile.update({
            'industry': industry,
            'size': company_size,
            'tech_stack': tech_stack
        })
    
    # Data refresh controls
    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Refresh Threat Feeds", type="primary"):
        with st.spinner("Fetching real-time threat intelligence..."):
            all_threats = []
            
            # Fetch from multiple real sources
            st.info("Fetching URLhaus malicious URLs...")
            abuse_data = tip.fetch_abuse_ch_data()
            all_threats.extend(abuse_data)
            
            st.info("Fetching CISA Known Exploited Vulnerabilities...")
            cisa_data = tip.fetch_cisa_kev_data()
            all_threats.extend(cisa_data)
            
            st.info("Fetching MalwareBazaar samples...")
            malware_data = tip.fetch_malware_bazaar_data()
            all_threats.extend(malware_data)
            
            # Store results
            st.session_state.threats_data = all_threats
            st.session_state.last_update = datetime.now()
        
        if all_threats:
            st.sidebar.success(f"✅ Loaded {len(all_threats)} real threats!")
            # Show breakdown
            sources = {}
            for threat in all_threats:
                source = threat.get('source', 'Unknown')
                sources[source] = sources.get(source, 0) + 1
            
            for source, count in sources.items():
                st.sidebar.info(f"• {source}: {count} threats")
        else:
            st.sidebar.error("⚠️ No threats loaded - check network connection")
    
    if st.session_state.last_update:
        st.sidebar.info(f"Last update: {st.session_state.last_update.strftime('%H:%M:%S')}")
    
    # Clear data button
    if st.sidebar.button("🔄 Clear & Reload All Data", type="secondary"):
        st.session_state.threats_data = []
        st.session_state.last_update = None
        st.rerun()
    
    # Debug info
    st.sidebar.markdown("---")
    if st.sidebar.checkbox("🔍 Show Debug Info"):
        current_threats = st.session_state.threats_data if st.session_state.threats_data else []
        if current_threats:
            sources_debug = {}
            for threat in current_threats:
                source = threat.get('source', 'Unknown')
                sources_debug[source] = sources_debug.get(source, 0) + 1
            
            st.sidebar.write("**Current Data Sources:**")
            for source, count in sources_debug.items():
                st.sidebar.write(f"• {source}: {count}")
        else:
            st.sidebar.write("**No data loaded**")
    
    # Main content
    st.title("🛡️ SME Threat Intelligence Platform - POC")
    st.markdown("**Enterprise-grade intel without enterprise costs**")
    
    # Load initial data if empty
    if not st.session_state.threats_data:
        with st.spinner("Loading real-time threat intelligence..."):
            # Only load real data - no mock data
            all_threats = []
            
            # Try each real source
            st.write("Connecting to Abuse.ch URLhaus...")
            try:
                abuse_data = tip.fetch_abuse_ch_data()
                if abuse_data:
                    all_threats.extend(abuse_data)
                    st.write(f"✅ Loaded {len(abuse_data)} URLs from URLhaus")
            except Exception as e:
                st.write(f"❌ URLhaus failed: {e}")
                
            st.write("Connecting to CISA KEV...")
            try:
                cisa_data = tip.fetch_cisa_kev_data()
                if cisa_data:
                    all_threats.extend(cisa_data)
                    st.write(f"✅ Loaded {len(cisa_data)} vulnerabilities from CISA")
            except Exception as e:
                st.write(f"❌ CISA KEV failed: {e}")
                
            st.write("Connecting to MalwareBazaar...")
            try:
                malware_data = tip.fetch_malware_bazaar_data()
                if malware_data:
                    all_threats.extend(malware_data)
                    st.write(f"✅ Loaded {len(malware_data)} malware samples")
            except Exception as e:
                st.write(f"❌ MalwareBazaar failed: {e}")
            
            if all_threats:
                st.session_state.threats_data = all_threats
                st.session_state.last_update = datetime.now()
                st.success(f"🎉 Successfully loaded {len(all_threats)} real threats!")
            else:
                st.error("⚠️ Could not load any real threat data. Please check internet connection and try refreshing.")
                st.session_state.threats_data = []

    # Get current threats data
    current_threats = st.session_state.threats_data if st.session_state.threats_data else []
    
    # Show data sources summary for debugging
    if current_threats:
        sources_summary = {}
        for threat in current_threats:
            source = threat.get('source', 'Unknown')
            sources_summary[source] = sources_summary.get(source, 0) + 1
        
        st.info(f"**Data Sources Currently Loaded:** " + 
                ", ".join([f"{source} ({count})" for source, count in sources_summary.items()]))

    # Executive Dashboard
    st.header("📊 Executive Dashboard")

    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    high_risk_threats = [t for t in current_threats if t.get('relevance_score', 0) >= 80]
    medium_risk_threats = [t for t in current_threats if 60 <= t.get('relevance_score', 0) < 80]
    low_risk_threats = [t for t in current_threats if t.get('relevance_score', 0) < 60]
    
    with col1:
        st.metric("🔴 High Risk Threats", len(high_risk_threats))
    
    with col2:
        st.metric("🟡 Medium Risk", len(medium_risk_threats))
    
    with col3:
        st.metric("🟢 Low Risk", len(low_risk_threats))
    
    with col4:
        active_sources = len([s for s in ['URLhaus', 'CISA KEV', 'MalwareBazaar'] if any(
            threat.get('source', '').startswith(s) for threat in current_threats
        )])
        st.metric("📡 Active Feeds", f"{active_sources}/3")
    
    # Risk overview chart
    col1, col2 = st.columns(2)
    
    with col1:
        if current_threats:
            risk_data = pd.DataFrame({
                'Risk Level': ['High (80-100)', 'Medium (60-79)', 'Low (0-59)'],
                'Count': [len(high_risk_threats), len(medium_risk_threats), len(low_risk_threats)],
                'Color': ['#ff4444', '#ff8800', '#44ff44']
            })
            
            fig = px.pie(risk_data, values='Count', names='Risk Level', 
                        color='Risk Level',
                        color_discrete_map={
                            'High (80-100)': '#ff4444',
                            'Medium (60-79)': '#ff8800', 
                            'Low (0-59)': '#44ff44'
                        },
                        title="Threat Risk Distribution")
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        if current_threats:
            source_counts = {}
            for threat in current_threats:
                source = threat.get('source', 'Unknown')
                source_counts[source] = source_counts.get(source, 0) + 1
            
            fig = px.bar(
                x=list(source_counts.keys()),
                y=list(source_counts.values()),
                title="Threats by Source",
                color=list(source_counts.values()),
                color_continuous_scale="Blues"
            )
            fig.update_layout(showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
    
    # Priority Actions
    st.header("🎯 Priority Actions")
    
    if high_risk_threats:
        st.markdown("### Immediate Action Required")
        for threat in high_risk_threats[:5]:  # Top 5
            with st.container():
                col1, col2, col3 = st.columns([3, 1, 2])
                
                with col1:
                    threat_display = threat.get('value', '')
                    if len(threat_display) > 50:
                        threat_display = threat_display[:47] + "..."
                    
                    description = threat.get('description', '')
                    if not description:
                        if threat.get('type') == 'malicious_url':
                            description = f"Malicious URL hosting {threat.get('threat_type', 'malware')}"
                        elif threat.get('type') == 'malware_sample':
                            description = f"Malware sample: {threat.get('threat_type', 'unknown')}"
                        else:
                            description = threat.get('threat_type', 'Security threat')
                    
                    if len(description) > 100:
                        description = description[:97] + "..."
                    
                    st.markdown(f"""
                    <div class="threat-card">
                        <strong>{threat.get('type', '').replace('_', ' ').title()}</strong><br>
                        <code>{threat_display}</code><br>
                        <small>{description}</small><br>
                        <small>Source: {threat.get('source', '')} | Confidence: {threat.get('confidence', 0)}%</small>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    st.markdown(f"**Risk: {threat.get('relevance_score', 0)}**")
                    if threat.get('relevance_score', 0) >= 90:
                        st.error("🔴 CRITICAL")
                    else:
                        st.warning("🟡 HIGH")
                
                with col3:
                    action = threat.get('action_recommended', 'Review and assess')
                    if st.button(f"Take Action", key=f"action_{threat.get('id')}"):
                        st.success(f"✅ Action logged: {action}")
    else:
        st.info("No high-risk threats detected. Great job! 🎉")
    
    # Detailed Threat Feed
    st.header("🔍 Detailed Threat Intelligence")
    
    # Filter controls
    col1, col2, col3 = st.columns(3)
    
    with col1:
        threat_type_filter = st.selectbox(
            "Filter by Type",
            ["All"] + list(set(t.get('type', '') for t in current_threats))
        )
    
    with col2:
        risk_filter = st.selectbox(
            "Risk Level",
            ["All", "High (80+)", "Medium (60-79)", "Low (<60)"]
        )
    
    with col3:
        source_filter = st.selectbox(
            "Source",
            ["All"] + list(set(t.get('source', '') for t in current_threats))
        )
    
    # Apply filters
    filtered_threats = current_threats.copy()
    
    if threat_type_filter != "All":
        filtered_threats = [t for t in filtered_threats if t.get('type') == threat_type_filter]
    
    if risk_filter != "All":
        if risk_filter == "High (80+)":
            filtered_threats = [t for t in filtered_threats if t.get('relevance_score', 0) >= 80]
        elif risk_filter == "Medium (60-79)":
            filtered_threats = [t for t in filtered_threats if 60 <= t.get('relevance_score', 0) < 80]
        else:
            filtered_threats = [t for t in filtered_threats if t.get('relevance_score', 0) < 60]
    
    if source_filter != "All":
        filtered_threats = [t for t in filtered_threats if t.get('source') == source_filter]
    
    # Display threats table
    if filtered_threats:
        threat_df = pd.DataFrame(filtered_threats)
        
        # Select and rename columns for display
        display_columns = ['id', 'type', 'value', 'source', 'relevance_score', 'first_seen']
        available_columns = [col for col in display_columns if col in threat_df.columns]
        
        if available_columns:
            display_df = threat_df[available_columns].copy()
            display_df.columns = ['ID', 'Type', 'Indicator', 'Source', 'Risk Score', 'First Seen']
            
            st.dataframe(
                display_df,
                use_container_width=True,
                hide_index=True
            )
        else:
            st.write("Threat data structure:", filtered_threats[0] if filtered_threats else "No data")
    else:
        st.info("No threats match the selected filters.")
    
    # Footer with POC info
    st.markdown("---")
    st.markdown("""
    **🔴 LIVE DATA**: This POC is now pulling real threat intelligence from:
    - ✅ **Abuse.ch URLhaus**: Live malicious URLs and domains
    - ✅ **CISA KEV**: Known Exploited Vulnerabilities (actively targeted)
    - ✅ **Abuse.ch MalwareBazaar**: Recent malware samples and hashes
    - 🔄 **Business Context**: Smart relevance scoring based on your company profile
    - 📊 **Executive Reporting**: Clean dashboards for non-technical stakeholders
    """)
    
    # Show data freshness
    if st.session_state.last_update:
        minutes_ago = int((datetime.now() - st.session_state.last_update).total_seconds() / 60)
        if minutes_ago < 1:
            st.info("🕐 Data refreshed less than 1 minute ago")
        else:
            st.info(f"🕐 Data refreshed {minutes_ago} minutes ago")

if __name__ == "__main__":
    main()

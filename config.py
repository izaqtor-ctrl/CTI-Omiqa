# Configuration file for SME TIP POC
# Copy this file to config.py and update with your API keys

import os
from datetime import timedelta

class Config:
    # API Keys (for production use)
    OTX_API_KEY = os.environ.get('OTX_API_KEY', '')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    
    # Threat Feed URLs
    THREAT_FEEDS = {
        'abuse_ch_urlhaus': 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
        'abuse_ch_malware': 'https://bazaar-api.abuse.ch/v1/samples/recent/',
        'cisa_kev': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        'otx_indicators': 'https://otx.alienvault.com/api/v1/indicators/recent/',
    }
    
    # Data retention settings
    MAX_THREATS_MEMORY = 1000  # Maximum threats to keep in memory
    DATA_RETENTION_DAYS = 90
    
    # Risk scoring weights
    RISK_SCORING = {
        'industry_relevance': 0.3,
        'tech_stack_match': 0.25,
        'threat_severity': 0.25,
        'source_confidence': 0.2
    }
    
    # Business context templates
    INDUSTRY_PROFILES = {
        'Technology': {
            'high_risk_keywords': ['saas', 'cloud', 'api', 'devops', 'github'],
            'tech_stack_bias': 1.2
        },
        'Healthcare': {
            'high_risk_keywords': ['hipaa', 'phi', 'medical', 'patient'],
            'compliance_weight': 1.5
        },
        'Financial': {
            'high_risk_keywords': ['banking', 'payment', 'pci', 'fintech'],
            'compliance_weight': 1.8
        }
    }
    
    # Integration endpoints (for future phases)
    INTEGRATION_APIS = {
        'microsoft_365': {
            'endpoint': 'https://graph.microsoft.com/v1.0/security',
            'scopes': ['SecurityEvents.ReadWrite.All']
        },
        'google_workspace': {
            'endpoint': 'https://www.googleapis.com/admin/directory/v1',
            'scopes': ['admin.directory.user']
        }
    }
    
    # Streamlit configuration
    STREAMLIT_CONFIG = {
        'theme': 'light',
        'page_title': 'SME Threat Intelligence Platform',
        'page_icon': '🛡️',
        'layout': 'wide'
    }
    
    # Logging configuration
    LOGGING = {
        'level': 'INFO',
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': 'tip_poc.log'
    }

# POC-specific settings
class POCConfig(Config):
    # Use mock data for demonstration
    USE_MOCK_DATA = True
    
    # Simplified risk scoring for POC
    SIMPLE_RISK_THRESHOLD = {
        'high': 80,
        'medium': 60,
        'low': 0
    }
    
    # Demo company profiles
    DEMO_COMPANIES = [
        {
            'name': 'TechCorp SME',
            'industry': 'Technology',
            'size': '50-200',
            'tech_stack': ['Microsoft 365', 'AWS', 'Windows'],
            'geography': 'North America'
        },
        {
            'name': 'HealthCare Plus',
            'industry': 'Healthcare', 
            'size': '100-500',
            'tech_stack': ['Microsoft 365', 'Google Workspace', 'Linux'],
            'geography': 'North America'
        }
    ]

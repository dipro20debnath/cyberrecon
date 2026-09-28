"""
CyberRecon Pro - Configuration Management
"""
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

class Config:
    """Configuration manager for CyberRecon Pro"""
    
    DEFAULT_CONFIG = {
        'api_keys': {
            'virustotal': '',
            'securitytrails': '',
            'shodan': '',
            'censys': '',
            'urlscan': ''
        },
        'wordlists': {
            'subdomains': 'wordlists/subdomains.txt',
            'dns': 'wordlists/dns-names.txt',
            'ports': 'wordlists/top-ports.txt'
        },
        'settings': {
            'timeout': 30,
            'threads': 50,
            'rate_limit': 1.0,
            'max_retries': 3,
            'user_agent': 'CyberRecon-Pro/1.0'
        },
        'output': {
            'default_format': 'json',
            'save_directory': 'reports/',
            'screenshots': False
        }
    }
    
    def __init__(self, config_path: str = 'config.yaml'):
        self.config_path = Path(config_path)
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file or create default"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        
        # Default config তৈরি করো
        self._save_config(self.DEFAULT_CONFIG)
        return self.DEFAULT_CONFIG
    
    def _save_config(self, config: Dict[str, Any]):
        """Save configuration to YAML file"""
        with open(self.config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get config value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set config value using dot notation"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self._save_config(self.config)
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service"""
        key = self.get(f'api_keys.{service}')
        env_key = os.getenv(f'CR_{service.upper()}_API_KEY')
        return env_key or key
    
    @property
    def threads(self) -> int:
        return self.get('settings.threads', 50)
    
    @property
    def timeout(self) -> int:
        return self.get('settings.timeout', 30)
    
    @property
    def output_dir(self) -> Path:
        return Path(self.get('output.save_directory', 'reports/'))

# Global config instance (default)
config = Config()

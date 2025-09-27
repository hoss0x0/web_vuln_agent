"""Burp Suite interface for security testing with proxy integration."""

import json
import logging
from typing import Dict, Optional, Union, Any
from dataclasses import dataclass
from datetime import datetime
import requests
from requests.exceptions import RequestException

from utils.logger import setup_logger

logger = setup_logger(__name__)

@dataclass
class BurpConfig:
    """Configuration for Burp Suite proxy"""
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    ca_cert_path: Optional[str] = None
    timeout: int = 30
    headers: Dict[str, str] = None
    cookies: Dict[str, str] = None
    verify_ssl: bool = False  # Usually False when using Burp proxy

class BurpSender:
    """Enhanced Burp Suite request sender"""
    
    def __init__(self, config: Optional[BurpConfig] = None):
        """Initialize Burp Suite sender with configuration"""
        self.config = config or BurpConfig()
        self._setup_session()
        
    def _setup_session(self) -> None:
        """Setup requests session with Burp proxy"""
        self.session = requests.Session()
        
        # Configure Burp proxy
        self.session.proxies = {
            'http': f'http://{self.config.proxy_host}:{self.config.proxy_port}',
            'https': f'http://{self.config.proxy_host}:{self.config.proxy_port}'
        }
        
        # Configure SSL verification
        if self.config.ca_cert_path:
            self.session.verify = self.config.ca_cert_path
        else:
            self.session.verify = self.config.verify_ssl
            
        # Set default headers if provided
        if self.config.headers:
            self.session.headers.update(self.config.headers)
            
        # Set default cookies if provided
        if self.config.cookies:
            self.session.cookies.update(self.config.cookies)

    def send_request(
        self,
        method: str,
        url: str,
        data: Optional[Union[Dict, str]] = None,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        files: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Send HTTP request through Burp Suite proxy
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            data: Form data or raw body
            params: URL parameters
            headers: Custom headers
            cookies: Custom cookies
            files: Files to upload
            json_data: JSON data to send
            **kwargs: Additional request parameters
            
        Returns:
            Dictionary containing response data and metadata
        """
        start_time = datetime.utcnow()
        
        try:
            # Prepare request
            request_headers = {**(self.config.headers or {}), **(headers or {})}
            request_cookies = {**(self.config.cookies or {}), **(cookies or {})}
            
            # Log request details
            logger.debug(
                f"Sending {method} request through Burp proxy ({self.config.proxy_host}:{self.config.proxy_port})\n"
                f"URL: {url}\n"
                f"Headers: {json.dumps(request_headers, indent=2)}\n"
                f"Params: {json.dumps(params, indent=2) if params else None}\n"
                f"Data: {json.dumps(data, indent=2) if data else None}\n"
                f"JSON: {json.dumps(json_data, indent=2) if json_data else None}"
            )
            
            # Send request through Burp proxy
            response = self.session.request(
                method=method,
                url=url,
                data=data,
                params=params,
                headers=request_headers,
                cookies=request_cookies,
                files=files,
                json=json_data,
                timeout=self.config.timeout,
                **kwargs
            )
            
            # Calculate duration
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Prepare response data
            result = {
                "success": True,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "cookies": dict(response.cookies),
                "content": response.text,
                "url": response.url,
                "duration": round(duration, 3),
                "timestamp": start_time.isoformat(),
                "proxy_info": {
                    "host": self.config.proxy_host,
                    "port": self.config.proxy_port
                },
                "metadata": {
                    "content_type": response.headers.get("content-type"),
                    "content_length": len(response.content),
                    "encoding": response.encoding
                }
            }
            
            # Try to parse JSON response
            try:
                result["json"] = response.json()
            except:
                result["json"] = None
            
            # Log response summary
            logger.info(
                f"[Burp] {method} {url} - {response.status_code} "
                f"({result['duration']}s)"
            )
            
            return result
            
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout for {method} {url}")
            return {
                "success": False,
                "error": "Request timeout",
                "duration": (datetime.utcnow() - start_time).total_seconds(),
                "proxy_info": {
                    "host": self.config.proxy_host,
                    "port": self.config.proxy_port
                }
            }
            
        except requests.exceptions.ProxyError:
            logger.error(
                f"Burp proxy connection failed "
                f"({self.config.proxy_host}:{self.config.proxy_port})"
            )
            return {
                "success": False,
                "error": "Burp proxy connection failed",
                "duration": (datetime.utcnow() - start_time).total_seconds(),
                "proxy_info": {
                    "host": self.config.proxy_host,
                    "port": self.config.proxy_port
                }
            }
            
        except RequestException as e:
            logger.error(f"Request failed for {method} {url}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "duration": (datetime.utcnow() - start_time).total_seconds(),
                "proxy_info": {
                    "host": self.config.proxy_host,
                    "port": self.config.proxy_port
                }
            }
            
        except Exception as e:
            logger.error(f"Unexpected error for {method} {url}: {str(e)}")
            return {
                "success": False,
                "error": f"Unexpected error: {str(e)}",
                "duration": (datetime.utcnow() - start_time).total_seconds(),
                "proxy_info": {
                    "host": self.config.proxy_host,
                    "port": self.config.proxy_port
                }
            }

# Initialize global Burp sender
burp_sender = BurpSender()

def send_request(
    method: str,
    url: str,
    **kwargs
) -> Dict[str, Any]:
    """Send HTTP request through Burp Suite proxy"""
    return burp_sender.send_request(method, url, **kwargs)

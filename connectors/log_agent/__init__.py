"""
Ethio-Cyber-Shield (ECS) — Lightweight Log Agent Collector Package.
Provides log parsers (Nginx, Apache, Syslog, CEF) and continuous file collector.
"""
from connectors.log_agent.parser import (
    parse_log_line,
    parse_nginx_apache_access,
    parse_nginx_apache_error,
    parse_syslog,
    parse_cef
)
from connectors.log_agent.collector import (
    LogAgentCollector,
    CollectorCheckpoint
)

__all__ = [
    'parse_log_line',
    'parse_nginx_apache_access',
    'parse_nginx_apache_error',
    'parse_syslog',
    'parse_cef',
    'LogAgentCollector',
    'CollectorCheckpoint'
]

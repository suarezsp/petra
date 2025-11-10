# PETRA

PETRA (Post-Exploitation Threat Recognition & Analysis) is a command-line interface (CLI) tool designed for cybersecurity analysis of system logs. It focuses on detecting anomalies, insider threats, and potential attacks such as brute-force attempts or ransomware patterns. Built from scratch in Python, it combines basic pattern recognition with simple machine learning models to provide proactive insights for small to medium-sized enterprises (SMEs) and individual administrators.

## What It Solves

In 2025, cybersecurity tools for log analysis are often enterprise-grade, expensive, or overly complex, leaving SMEs and home administrators with limited options for early threat detection. PETRA addresses this gap by offering a lightweight, open-source alternative that:

- Analyzes local log files (e.g., auth.log, syslog) for common threats like brute-force attacks, unusual access times, or file access bursts.
- Uses basic ML (e.g., clustering for outliers) to identify subtle anomalies without requiring expert knowledge or cloud resources.
- Provides real-time monitoring and configurable alerts, emphasizing privacy (offline processing) and ethics (consent-based log handling).
- Helps mitigate insider risks and misconfigurations, which account for a significant portion of breaches according to reports like the Global Cybersecurity Outlook 2025.

PETRA is not a full SIEM system but a focused, extensible tool for defensive cybersecurity, suitable for educational purposes, TFG projects, or portfolio demonstrations.

## Features

- **Log Parsing**: Supports common formats like auth.log (SSH/login events), syslog, and Windows Event logs, with regex-based extraction of key elements (timestamps, IPs, users).
- **Basic Detection**: Threshold-based rules for brute-force, sudo escalations, and unusual activity.
- **ML-Enhanced Detection**: Simple algorithms (e.g., Isolation Forest or KMeans) for outlier detection in patterns like access frequency or timing.
- **Real-Time Watch Mode**: Monitors log files for live alerts, with optional email notifications.
- **Reporting**: Outputs in console (tables, ASCII graphics), JSON, CSV, or HTML, with risk scoring and explanations referencing standards like NIST.
- **Extensibility**: YAML configurations for custom rules, parsers, and plugins.
- **Enrichment**: Offline GeoIP lookup for suspicious IPs.
- **Ethics and Privacy**: Built-in anonymization options and disclaimers for sensitive data handling.
- **Cross-Platform**: Compatible with Linux, macOS, and Windows.

## Requirements

- Python 3.10 or higher.
- Dependencies listed in `requirements.txt`:
  - click (for CLI)
  - |
  - psutil (for system info)
  - scikit-learn (for ML)
  - tabulate (for tables)
  - pyyaml (for configurations)
  - watchdog (for file monitoring)
  - pydantic (for data validation)
  - Optional: geoip2 (with MaxMind GeoLite2 database for IP geolocation)

No internet access is required for core functionality, ensuring offline usability.

## Installation

To set up PETRA for development or testing, follow these steps. It is recommended to use a virtual environment to avoid conflicts.

1. Clone the repository:
```bash
   git clone https://github.com/yourusername/petra.git
   cd petra
```

2. Create venv
```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
    pip install -r requirements.txt
```

4. Install PETRA in editable mode.
```bash
    pip install -e .
```

This makes the petra command available globally within the virtual environment.

For GeoIP enrichment (optional):
- Download the free MaxMind GeoLite2-City database from MaxMind.
- Place the .mmdb file in ~/.petra/geoip/ or configure the path in configs/default.yaml.

## Usage
```bash
petra --help  #list of available commands
```
(Working on it)
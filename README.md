# 🛡️ Darknet Monitor

A self-hosted honeypot network with real-time threat intelligence dashboard.

Fake SSH, FTP, and HTTP services exposed to the internet capture real attack attempts — logged, enriched with GeoIP and threat intel, and visualized on a live dashboard.

## Architecture
- Honeypots: SSH (Cowrie), FTP, HTTP — each in isolated Docker containers
- Collector: aggregates logs from all honeypot services
- Enrichment: GeoIP lookup + AbuseIPDB threat scoring per attacker IP
- Dashboard: Flask app with live attack map and charts
- Nginx: reverse proxy with HTTPS via Let's Encrypt

## Stack
Python · Docker · PostgreSQL · Flask · Nginx · Let's Encrypt

## Setup
Copy `.env.example` to `.env` and fill in your API keys before running.
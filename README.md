![Censys](docs/images/censys_io_logo.jpg)

# Censys.IO for Splunk App

## Introduction

Censys.io is a leading internet intelligence platform providing real-time visibility into internet-connected devices, infrastructure, and threats. It helps security teams discover, monitor, and analyze their external attack surfaces to proactively identify vulnerabilities, track changes, and manage risk across global networks. Censys operates using a comprehensive **Internet Map** built from continuous, large-scale scanning.

## Overview

Censys.io for Splunk provides full visibility into an organization’s externally exposed digital footprint by querying the Censys public scan database using Python-based modular inputs. 

This Splunk App enables security teams to **discover, monitor, analyze, and operationalize external attack surface data** directly within Splunk—without reliance on the Censys Web User Interface.


---

![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active%20development-yellow.svg)

---

## Key Functions & Features

- **Internet Mapping**: Continuous scanning of public IP addresses and domains to build a detailed, searchable map of internet assets (hosts, services, certificates).
- **Attack Surface Management (ASM)**: Identification of unknown, vulnerable, or misconfigured internet-facing assets to reduce blind spots.
- **Threat Hunting**: Rich datasets and pivots for proactive investigation and detection.
- **Deep Context**: Asset-level metadata including software, TLS, WHOIS, geolocation, and CVE associations.
- **Platform & API Access**: Search engine, REST APIs, and integrations supporting large-scale analytics.

---

## Supported Asset and Intelligence Types

Censys provides visibility into the following externally observable assets and metadata:

- IP Addresses
- Hosts and Services
- Open Ports and Protocols
- Software and Product Fingerprints
- SSL/TLS Certificates
- Certificate Authorities
- Domains and Hostnames
- Autonomous System Numbers (ASNs)
- Organizations
- Geolocation Metadata
- Internet-Wide Search Results
- ASM Inventory and Discoveries (licensed)

---

## Features

### 🛡️ Core Capabilities

| Feature | Description |
|------|-------------|
| 🌐 External Asset Discovery | Identify exposed hosts and services |
| 🔍 Internet-Wide Search | Query the global Censys scan index |
| 🧭 Host Intelligence | Deep inspection of services and banners |
| 🧬 Certificate Intelligence | SSL/TLS certificate visibility |
| 🕵️ Exposure Context | Protocols, software, and metadata |
| 🧾 Evidence Preservation | Raw API responses retained |

---

### 📈 Analytics and Visibility

| Feature | Description |
|------|-------------|
| 📊 Exposure Trends | Track asset and service changes |
| 🔄 First-Seen Detection | Identify newly observed assets |
| 🧱 Infrastructure Mapping | IP → ASN → Organization |
| 🔐 Certificate Monitoring | Certificate inventory and metadata |
| 🧠 Investigative Pivoting | Pivot across IPs, domains, certs |

---

### ⚙️ Operational Excellence

| Feature | Description |
|------|-------------|
| 📡 Modular Input Framework | Secure API-based ingestion |
| 🔑 Credential Management | Encrypted credential storage |
| 🌐 Proxy Support | Enterprise proxy compatibility |
| 🩺 Health Monitoring | API reachability and status |
| 📋 Operational Logging | Full ingestion traceability |
| ⏱️ Rate-Limit Awareness | Throttling-safe polling |

---

## 📊 Dashboards

| Dashboard | Description |
|---------|-------------|
| Overview | High-level external exposure summary |
| Hosts | Internet-exposed hosts and services |
| Services | Port, protocol, and software analysis |
| Certificates | SSL/TLS certificate inventory |
| Domains | Domain and hostname visibility |
| ASN Exposure | ASN-level exposure analysis |
| New Assets | Newly observed assets |
| Search Analytics | Search query trends |
| Operations | Ingestion status and metrics |
| Health | API and data freshness monitoring |

Dashboards are designed for **investigation-first workflows**, not executive summaries.

---

# Censys for Splunk App  
## Sourcetype → Dashboard Mapping (Authoritative)

### 🟦 Core Internet Scan (Data Plane)

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:host` | Overview, Hosts, Inventory, Locations, ASNs |
| `censys:host:service` | Services & Ports |
| `censys:host:software` | Software |
| `censys:host:os` | Operating Systems |
| `censys:host:dns` | DNS |
| `censys:host:whois` | WHOIS |
| `censys:host:tls` | TLS |
| `censys:host:jarm` | JARM |
| `censys:host:label` | Labels |
| `censys:location` | Locations |
| `censys:asn` | Autonomous Systems |

---

### 🟨 Certificates & Cryptography

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:certificate` | Certificates |
| `censys:certificate:transparency` | Certificate Transparency |
| `censys:certificate:precertificate` | Precertificates |
| `censys:certificate:lite` | Lite Certificates |
| `censys:certificate:history` | Certificate History |
| `censys:certificate:cve` | CVE Context |

---

### 🟥 Threat Intelligence & Hunting

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:threat` | Threat Overview |
| `censys:cve:context` | CVE Context |
| `censys:c2:label` | C2 Infrastructure |
| `censys:malicious:infrastructure` | Malicious Infrastructure |
| `censys:detection:pivot` | Detection Pivots |
| `censys:host:history` | Historical Changes |

---

### 🟩 Attack Surface Management (ASM)

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:asm:asset` | ASM Overview, Inventory |
| `censys:asm:risk` | Risks |
| `censys:asm:risk:category` | Risk Categories |
| `censys:asm:cve:risk` | CVE Risks |
| `censys:asm:trend` | Trends & Benchmarks |
| `censys:asm:port` | Ports & Protocols |
| `censys:asm:metric` | Metrics |
| `censys:asm:seed` | Seeds |
| `censys:asm:excluded_asset` | Excluded Assets |

---

### 🟪 Logbook, Audit & Change Tracking

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:logbook:event` | Logbook Events |
| `censys:audit:user_activity` | User Activity |
| `censys:audit:role_change` | Configuration Changes |
| `censys:audit:asset_change` | Asset Changes |
| `censys:audit:risk_change` | Risk Changes |

---

### 🟫 Organization, Access & Usage

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:user` | Users |
| `censys:role` | Roles & Permissions |
| `censys:api_key` | API Keys |
| `censys:credit:usage` | Credit Usage |
| `censys:usage:trend` | Usage Trends |

---

### ⚙️ Operations & Health

| Sourcetype | Dashboards |
|-----------|------------|
| `censys:health` | Data Health |
| `censys:api:status` | API Status |
| `censys:ingestion:metric` | Ingestion Metrics |
| `censys:error` | Error Tracking |

---

## Deployment

### Step 1: Install the App

1. Download `Censys_For_Splunk_App-1.0.0.tar.gz`
2. In Splunk Web, go to **Apps → Manage Apps**
3. Select **Install app from file**
4. Upload the package
5. Restart Splunk if prompted

---

### Step 2: Configure the App

Navigate to **Apps → Censys.io for Splunk → Setup** to configure:

- Censys API credentials (stored securely)
- Optional proxy settings
- Modular input enablement and polling intervals

All inputs are **disabled by default**.

---

### Step 3: Validate Configuration

- Test API connectivity
- Validate authentication
- Verify API plan and ASM entitlements

---

### Step 4: Verify Data Collection

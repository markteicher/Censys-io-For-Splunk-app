# bin/censys_setup_handler.py
#
# Censys.io for Splunk App
# Guided Setup Handler (Model 2)
#
# What it does:
# - Validates setup form inputs
# - Stores secrets in Splunk secure password storage (storage/passwords)
#   - Censys API Secret (paired with API ID)
#   - Optional Proxy Password (paired with Proxy Username)
# - Writes runtime configuration into:
#   - local/inputs.conf (enables/disables input groups, sets index + intervals)
#
# Notes:
# - default/inputs.conf must ship with all stanzas disabled=1
# - local/inputs.conf is runtime-generated and MUST NOT ship in the package
#
# Requires: Splunk Python, splunklib (Splunk SDK)

from __future__ import annotations

import sys
import traceback
from typing import Dict, Tuple, Optional

import splunk.admin as admin
import splunklib.client as client


APP_REALM_CENSYS = "censys"
APP_REALM_PROXY = "censys_proxy"

DEFAULT_API_BASE_URL = "https://search.censys.io/api"
DEFAULT_TIMEOUT_SECONDS = "60"
DEFAULT_VERIFY_SSL = "true"
DEFAULT_INDEX = "security_censys"

# Stanza -> (interval, sourcetype, group_name)
# Group enablement is controlled by setup boolean switches.
STANZAS: Dict[str, Tuple[int, str, str]] = {
    # -----------------------------
    # Core Internet Scan
    # -----------------------------
    "censys://hosts": (3600, "censys:host", "internet_scan"),
    "censys://host_services": (3600, "censys:host:service", "internet_scan"),
    "censys://host_software": (3600, "censys:host:software", "internet_scan"),
    "censys://host_os": (3600, "censys:host:os", "internet_scan"),
    "censys://host_dns": (3600, "censys:host:dns", "internet_scan"),
    "censys://host_whois": (3600, "censys:host:whois", "internet_scan"),
    "censys://host_tls": (3600, "censys:host:tls", "internet_scan"),
    "censys://host_jarm": (3600, "censys:host:jarm", "internet_scan"),
    "censys://host_labels": (3600, "censys:host:label", "internet_scan"),
    "censys://locations": (86400, "censys:location", "internet_scan"),
    "censys://asns": (86400, "censys:asn", "internet_scan"),

    # -----------------------------
    # Certificates & Cryptography
    # -----------------------------
    "censys://certificates": (3600, "censys:certificate", "certificates"),
    "censys://certificate_transparency": (3600, "censys:certificate:transparency", "certificates"),
    "censys://precertificates": (3600, "censys:certificate:precertificate", "certificates"),
    "censys://certificate_lite": (3600, "censys:certificate:lite", "certificates"),
    "censys://certificate_history": (3600, "censys:certificate:history", "certificates"),
    "censys://certificate_cve": (3600, "censys:certificate:cve", "certificates"),

    # -----------------------------
    # Threat Intelligence & Hunting
    # -----------------------------
    "censys://threats": (3600, "censys:threat", "threat_hunting"),
    "censys://cve_context": (3600, "censys:cve:context", "threat_hunting"),
    "censys://c2_labels": (3600, "censys:c2:label", "threat_hunting"),
    "censys://malicious_infrastructure": (3600, "censys:malicious:infrastructure", "threat_hunting"),
    "censys://detection_pivots": (3600, "censys:detection:pivot", "threat_hunting"),
    "censys://host_history": (3600, "censys:host:history", "threat_hunting"),

    # -----------------------------
    # Attack Surface Management (ASM)
    # -----------------------------
    "censys://asm_assets": (21600, "censys:asm:asset", "asm"),
    "censys://asm_risks": (21600, "censys:asm:risk", "asm"),
    "censys://asm_risk_categories": (21600, "censys:asm:risk:category", "asm"),
    "censys://asm_cve_risks": (21600, "censys:asm:cve:risk", "asm"),
    "censys://asm_trends": (21600, "censys:asm:trend", "asm"),
    "censys://asm_ports": (21600, "censys:asm:port", "asm"),
    "censys://asm_metrics": (21600, "censys:asm:metric", "asm"),
    "censys://asm_seeds": (21600, "censys:asm:seed", "asm"),
    "censys://asm_excluded_assets": (21600, "censys:asm:excluded_asset", "asm"),

    # -----------------------------
    # Logbook, Audit & Change Tracking
    # -----------------------------
    "censys://logbook_events": (3600, "censys:logbook:event", "logbook_audit"),
    "censys://user_activity": (3600, "censys:audit:user_activity", "logbook_audit"),
    "censys://role_changes": (3600, "censys:audit:role_change", "logbook_audit"),
    "censys://asset_changes": (3600, "censys:audit:asset_change", "logbook_audit"),
    "censys://risk_changes": (3600, "censys:audit:risk_change", "logbook_audit"),

    # -----------------------------
    # Organization, Access & Usage
    # -----------------------------
    "censys://users": (86400, "censys:user", "org_access"),
    "censys://roles": (86400, "censys:role", "org_access"),
    "censys://api_keys": (86400, "censys:api_key", "org_access"),
    "censys://credit_usage": (3600, "censys:credit:usage", "org_access"),
    "censys://usage_trends": (3600, "censys:usage:trend", "org_access"),

    # -----------------------------
    # Operations & Health
    # -----------------------------
    "censys://health": (1800, "censys:health", "ops_health"),
    "censys://api_status": (1800, "censys:api:status", "ops_health"),
    "censys://ingestion_metrics": (1800, "censys:ingestion:metric", "ops_health"),
    "censys://errors": (1800, "censys:error", "ops_health"),
}


# -----------------------------
# Helpers
# -----------------------------

def _as_bool(v: Optional[str], default: bool = False) -> bool:
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return default


def _required(params: Dict[str, str], key: str) -> str:
    v = (params.get(key) or "").strip()
    if not v:
        raise ValueError(f"Missing required field: {key}")
    return v


def _connect(session_key: str) -> client.Service:
    return client.connect(token=session_key, autologin=False)


def _upsert_password(svc: client.Service, realm: str, username: str, password: str) -> None:
    """
    Splunk secure credential storage:
      - realm groups the secrets for this app
      - username is the lookup key (API ID / proxy username)
    """
    username = (username or "").strip()
    password = (password or "").strip()

    if not username:
        raise ValueError("Username for secure storage cannot be empty")
    if not password:
        raise ValueError("Password for secure storage cannot be empty")

    # Remove existing (if any), then create
    # IDs look like: /servicesNS/<user>/<app>/storage/passwords/<realm>:<username>:
    for cred in svc.storage_passwords:
        try:
            if cred.content.get("realm") == realm and cred.content.get("username") == username:
                cred.delete()
                break
        except Exception:
            continue

    svc.storage_passwords.create(password=password, username=username, realm=realm)


def _write_inputs_conf(
    svc: client.Service,
    app_name: str,
    stanza_enable_groups: Dict[str, bool],
    index_name: str,
    common_kv: Dict[str, str],
) -> None:
    """
    Writes stanzas into local/inputs.conf for this app context.
    """
    conf = svc.confs["inputs"]  # creates/updates under local automatically

    for stanza_name, (interval, sourcetype, group) in STANZAS.items():
        enabled = bool(stanza_enable_groups.get(group, False))
        disabled = "0" if enabled else "1"

        stanza_kv = {
            "disabled": disabled,
            "interval": str(interval),
            "index": index_name,
            "sourcetype": sourcetype,
        }

        # Common keys used by the modular input (safe even if ignored)
        stanza_kv.update(common_kv)

        if stanza_name in conf:
            st = conf[stanza_name]
            st.update(**stanza_kv)
        else:
            conf.create(stanza_name, **stanza_kv)


# -----------------------------
# Setup Handler
# -----------------------------

class CensysSetupHandler(admin.MConfigHandler):
    """
    Splunk setup handler that writes configuration and enables input groups.

    Expected setup.xml keys (recommended):
      - api_id
      - api_secret
      - api_base_url
      - verify_ssl
      - request_timeout
      - index
      - proxy_enabled
      - proxy_url
      - proxy_username
      - proxy_password
      - enable_internet_scan
      - enable_certificates
      - enable_threat_hunting
      - enable_asm
      - enable_logbook_audit
      - enable_org_access
      - enable_ops_health
    """

    def setup(self):
        if self.requestedAction in (admin.ACTION_CREATE, admin.ACTION_EDIT):
            for k in (
                "api_id",
                "api_secret",
                "api_base_url",
                "verify_ssl",
                "request_timeout",
                "index",
                "proxy_enabled",
                "proxy_url",
                "proxy_username",
                "proxy_password",
                "enable_internet_scan",
                "enable_certificates",
                "enable_threat_hunting",
                "enable_asm",
                "enable_logbook_audit",
                "enable_org_access",
                "enable_ops_health",
            ):
                self.supportedArgs.addOptArg(k)

    def handleCreate(self, confInfo):
        self._handle(confInfo)

    def handleEdit(self, confInfo):
        self._handle(confInfo)

    def _handle(self, confInfo):
        params = self.callerArgs.data

        # Required
        api_id = _required(params, "api_id")
        api_secret = _required(params, "api_secret")

        # Optional w/ defaults
        api_base_url = (params.get("api_base_url") or DEFAULT_API_BASE_URL).strip() or DEFAULT_API_BASE_URL
        verify_ssl = (params.get("verify_ssl") or DEFAULT_VERIFY_SSL).strip() or DEFAULT_VERIFY_SSL
        request_timeout = (params.get("request_timeout") or DEFAULT_TIMEOUT_SECONDS).strip() or DEFAULT_TIMEOUT_SECONDS

        index_name = (params.get("index") or DEFAULT_INDEX).strip() or DEFAULT_INDEX

        proxy_enabled = _as_bool(params.get("proxy_enabled"), default=False)
        proxy_url = (params.get("proxy_url") or "").strip()
        proxy_username = (params.get("proxy_username") or "").strip()
        proxy_password = (params.get("proxy_password") or "").strip()

        # Group enablement (Model 2)
        enable_internet_scan = _as_bool(params.get("enable_internet_scan"), default=True)
        enable_certificates = _as_bool(params.get("enable_certificates"), default=True)
        enable_threat_hunting = _as_bool(params.get("enable_threat_hunting"), default=False)
        enable_asm = _as_bool(params.get("enable_asm"), default=False)
        enable_logbook_audit = _as_bool(params.get("enable_logbook_audit"), default=False)
        enable_org_access = _as_bool(params.get("enable_org_access"), default=False)
        enable_ops_health = _as_bool(params.get("enable_ops_health"), default=True)

        # Validation
        if not api_base_url.startswith("http"):
            raise ValueError("api_base_url must start with http/https")

        try:
            int(request_timeout)
        except Exception:
            raise ValueError("request_timeout must be an integer")

        if proxy_enabled and not proxy_url:
            raise ValueError("proxy_enabled is true but proxy_url is empty")

        if proxy_enabled and proxy_username and not proxy_password:
            # Proxy password required only if proxy username is provided
            raise ValueError("proxy_username provided but proxy_password is empty")

        # Connect to splunkd
        session_key = self.getSessionKey()
        svc = _connect(session_key)

        # Store Censys API secret securely (username=api_id, password=api_secret)
        _upsert_password(svc, realm=APP_REALM_CENSYS, username=api_id, password=api_secret)

        # Store Proxy password securely if provided (username=proxy_username, password=proxy_password)
        if proxy_enabled and proxy_username and proxy_password:
            _upsert_password(svc, realm=APP_REALM_PROXY, username=proxy_username, password=proxy_password)

        # Common KV placed into each input stanza so the modular input can run without
        # relying on default/inputs.conf for credentials/settings.
        common_kv = {
            # API connectivity
            "api_id": api_id,
            "api_base_url": api_base_url,
            "verify_ssl": str(_as_bool(verify_ssl, default=True)).lower(),
            "request_timeout": str(int(request_timeout)),

            # Password storage (so the modular input can retrieve the secret)
            "password_realm": APP_REALM_CENSYS,
            "password_username": api_id,

            # Proxy config (password stored in storage/passwords if username present)
            "proxy_enabled": str(proxy_enabled).lower(),
            "proxy_url": proxy_url if proxy_enabled else "",
            "proxy_username": proxy_username if proxy_enabled else "",
            "proxy_password_realm": APP_REALM_PROXY if (proxy_enabled and proxy_username) else "",
            "proxy_password_username": proxy_username if (proxy_enabled and proxy_username) else "",
        }

        stanza_enable_groups = {
            "internet_scan": enable_internet_scan,
            "certificates": enable_certificates,
            "threat_hunting": enable_threat_hunting,
            "asm": enable_asm,
            "logbook_audit": enable_logbook_audit,
            "org_access": enable_org_access,
            "ops_health": enable_ops_health,
        }

        # Write local/inputs.conf (enable/disable groups + index)
        _write_inputs_conf(
            svc=svc,
            app_name=svc.app,
            stanza_enable_groups=stanza_enable_groups,
            index_name=index_name,
            common_kv=common_kv,
        )

        # Return something minimal to setup UI (optional informational fields)
        confInfo["setup"]["index"] = index_name
        confInfo["setup"]["api_base_url"] = api_base_url
        confInfo["setup"]["proxy_enabled"] = str(proxy_enabled).lower()
        confInfo["setup"]["enable_internet_scan"] = str(enable_internet_scan).lower()
        confInfo["setup"]["enable_certificates"] = str(enable_certificates).lower()
        confInfo["setup"]["enable_threat_hunting"] = str(enable_threat_hunting).lower()
        confInfo["setup"]["enable_asm"] = str(enable_asm).lower()
        confInfo["setup"]["enable_logbook_audit"] = str(enable_logbook_audit).lower()
        confInfo["setup"]["enable_org_access"] = str(enable_org_access).lower()
        confInfo["setup"]["enable_ops_health"] = str(enable_ops_health).lower()


def main():
    try:
        admin.init(CensysSetupHandler, admin.CONTEXT_NONE)
    except SystemExit:
        raise
    except Exception:
        # Never print secrets; just surface a safe traceback
        msg = traceback.format_exc()
        sys.stderr.write(msg)
        raise


if __name__ == "__main__":
    main()

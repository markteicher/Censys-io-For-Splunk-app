# bin/censys_input_handler.py
#
# Censys.io for Splunk App
# Modular Input Execution Handler
#
# Responsibilities:
# - Read per-stanza configuration from inputs.conf (local runtime state)
# - Retrieve secrets from Splunk secure storage
# - Execute the correct Censys API workflow per stanza
# - Emit events to Splunk with correct sourcetype + index
#
# This handler is intentionally strict:
# - No defaults are assumed
# - All behavior is driven by inputs.conf + secure storage
#
# This file DOES NOT:
# - Enable/disable inputs (setup handler does that)
# - Store secrets
# - Guess API scope or entitlements

from __future__ import annotations

import sys
import json
import time
import traceback
from typing import Dict, Any, Iterable

import splunklib.client as client
import splunklib.modularinput as smi


APP_REALM_CENSYS = "censys"
APP_REALM_PROXY = "censys_proxy"


# -----------------------------
# Utilities
# -----------------------------

def _bool(v: str, default: bool = False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _get_password(
    svc: client.Service,
    realm: str,
    username: str,
) -> str:
    """
    Retrieve password from Splunk secure storage.
    """
    for cred in svc.storage_passwords:
        if (
            cred.content.get("realm") == realm
            and cred.content.get("username") == username
        ):
            return cred.content.get("clear_password")

    raise RuntimeError(f"Credential not found for realm={realm}, username={username}")


def _connect(session_key: str) -> client.Service:
    return client.connect(token=session_key, autologin=False)


# -----------------------------
# API Dispatch (placeholders)
# -----------------------------

def fetch_censys_data(
    stanza_name: str,
    settings: Dict[str, str],
    api_secret: str,
) -> Iterable[Dict[str, Any]]:
    """
    Dispatches to the correct Censys API workflow based on stanza name.

    This function intentionally contains NO logic yet.
    Each stanza maps to a concrete API implementation added later.

    Yield dict events.
    """
    # Placeholder implementation
    yield {
        "stanza": stanza_name,
        "status": "not_implemented",
        "timestamp": int(time.time()),
    }


# -----------------------------
# Modular Input
# -----------------------------

class CensysModularInput(smi.Script):

    def get_scheme(self):
        scheme = smi.Scheme("Censys Modular Input")
        scheme.description = "Ingests data from the Censys platform APIs"
        scheme.use_external_validation = False
        scheme.streaming_mode_xml = True

        scheme.add_argument(
            smi.Argument(
                name="api_id",
                description="Censys API ID",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                name="api_base_url",
                description="Censys API base URL",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                name="verify_ssl",
                description="Verify SSL certificates",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                name="request_timeout",
                description="HTTP request timeout",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                name="password_realm",
                description="Password storage realm",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                name="password_username",
                description="Password storage username",
                required_on_create=True,
            )
        )

        scheme.add_argument(
            smi.Argument(
                name="proxy_enabled",
                description="Enable proxy",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                name="proxy_url",
                description="Proxy URL",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                name="proxy_username",
                description="Proxy username",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                name="proxy_password_realm",
                description="Proxy password realm",
                required_on_create=False,
            )
        )

        scheme.add_argument(
            smi.Argument(
                name="proxy_password_username",
                description="Proxy password username",
                required_on_create=False,
            )
        )

        return scheme

    def stream_events(self, inputs, ew):
        session_key = self._input_definition.metadata["session_key"]
        svc = _connect(session_key)

        for stanza_name, stanza in inputs.inputs.items():
            try:
                settings = stanza.parameters

                api_id = settings["api_id"]
                password_realm = settings["password_realm"]
                password_username = settings["password_username"]

                api_secret = _get_password(
                    svc,
                    realm=password_realm,
                    username=password_username,
                )

                proxy_enabled = _bool(settings.get("proxy_enabled"))

                if proxy_enabled and settings.get("proxy_username"):
                    _ = _get_password(
                        svc,
                        realm=settings.get("proxy_password_realm"),
                        username=settings.get("proxy_password_username"),
                    )

                for record in fetch_censys_data(
                    stanza_name=stanza_name,
                    settings=settings,
                    api_secret=api_secret,
                ):
                    event = smi.Event(
                        data=json.dumps(record),
                        sourcetype=stanza.sourcetype,
                        index=stanza.index,
                    )
                    ew.write_event(event)

            except Exception as e:
                err = {
                    "stanza": stanza_name,
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                }
                ew.write_event(
                    smi.Event(
                        data=json.dumps(err),
                        sourcetype="censys:error",
                        index=stanza.index,
                    )
                )


def main():
    smi.ScriptRunner(CensysModularInput).run()


if __name__ == "__main__":
    main()

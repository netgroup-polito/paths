#!/usr/bin/env python3
"""Append a 5G attack-scenario knowledge base to a generated Prolog file.

Usage:
    python3 filler.py [input.p [output.p]]
    Defaults: input=parser/generated.p, output=parser/filled.p
"""

import os
import sys
from datetime import datetime


def pl(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


THREATS = [
    "denial_of_service",
    "subscriber_data_leak",
    "callback_hijacking",
    "suci_decryption",
    "memory_exhaustion",
    "information_disclosure",
]

MISBEHAVIORS = [
    "service_disruption",
    "data_exfiltration",
    "session_hijacking",
]

CAUSE = [
    ("denial_of_service",      "service_disruption"),
    ("memory_exhaustion",      "service_disruption"),
    ("subscriber_data_leak",   "data_exfiltration"),
    ("information_disclosure", "data_exfiltration"),
    ("callback_hijacking",     "session_hijacking"),
    ("suci_decryption",        "session_hijacking"),
]

EXPLOITABLE = [
    # Chain 2: PFCP DoS
    ("CVE-2025-69232", "denial_of_service"),
    ("CVE-2025-65562", "denial_of_service"),
    ("CVE-2025-65563", "denial_of_service"),
    ("CVE-2025-65564", "denial_of_service"),
    ("CVE-2025-65565", "denial_of_service"),
    ("CVE-2025-65566", "denial_of_service"),
    ("CVE-2025-65567", "denial_of_service"),
    ("CVE-2025-65568", "denial_of_service"),
    ("CVE-2026-26025", "denial_of_service"),
    ("CVE-2026-25501", "denial_of_service"),
    ("CVE-2025-70122", "denial_of_service"),
    ("CVE-2025-69247", "denial_of_service"),
    # Chain 3: SBI wipeout
    ("CVE-2025-55904", "denial_of_service"),
    # Chain 1: UDR/UDM espionage
    ("CVE-2026-40245", "subscriber_data_leak"),
    ("CVE-2026-40246", "subscriber_data_leak"),
    ("CVE-2026-40247", "subscriber_data_leak"),
    ("CVE-2026-40248", "callback_hijacking"),
    ("CVE-2026-40249", "subscriber_data_leak"),
    ("CVE-2026-40343", "subscriber_data_leak"),
    ("CVE-2026-41135", "memory_exhaustion"),
    ("CVE-2023-46324", "suci_decryption"),
    ("CVE-2026-27642", "information_disclosure"),
    ("CVE-2025-69252", "denial_of_service"),
    ("CVE-2025-69250", "denial_of_service"),
    ("CVE-2025-69251", "denial_of_service"),
]

INDUCE = [
    ("service_disruption", "CVE-2025-69232"),
    ("service_disruption", "CVE-2026-26025"),
    ("data_exfiltration",  "CVE-2026-40248"),
]

EXTRA_EXPOSED = [
    # Chain 3: CVE-2025-55904 crashes all Open5GS SBI NFs
    ("amf_app",  "CVE-2025-55904"),
    ("ausf_app", "CVE-2025-55904"),
    ("bsf_app",  "CVE-2025-55904"),
    ("nrf_app",  "CVE-2025-55904"),
    ("smf_app",  "CVE-2025-55904"),
    ("udm_app",  "CVE-2025-55904"),
    # Chain 2: SMF receives PFCP from UPF
    ("smf_app",  "CVE-2026-26025"),
    ("smf_app",  "CVE-2026-25501"),
    ("smf_app",  "CVE-2025-69232"),
    # Chain 1: UDM
    ("udm_app",  "CVE-2023-46324"),
    ("udm_app",  "CVE-2026-27642"),
    ("udm_app",  "CVE-2025-69252"),
]

SPREAD = [
    # Chain 2: UPF → SMF via N4 PFCP
    # CVE-2025-69232: PFCP assoc disruption that cascades from UPF to SMF
    # CVE-2025-65562: heap overflow via PFCP modify request sent by UPF
    ("upf_app",        "denial_of_service", "CVE-2025-69232"),
    ("upf_app",        "denial_of_service", "CVE-2025-65562"),
    ("upf_netfun_nat", "denial_of_service", "CVE-2025-69232"),
    ("upf_netfun_nat", "denial_of_service", "CVE-2025-65562"),
    ("smf_app",        "denial_of_service", "CVE-2026-26025"),
    ("smf_app",        "denial_of_service", "CVE-2026-25501"),
    ("smf_netfun_nat", "denial_of_service", "CVE-2026-26025"),
    ("udr_app",        "memory_exhaustion", "CVE-2026-41135"),
    ("udr_netfun_nat", "memory_exhaustion", "CVE-2026-41135"),
    # Chain 1: UDR leaks subscriber data → UDM SUCI decryption
    ("udr_app",        "subscriber_data_leak",  "CVE-2026-40245"),
    ("udr_app",        "subscriber_data_leak",  "CVE-2026-40246"),
    ("udr_app",        "callback_hijacking",    "CVE-2026-40248"),
    ("udr_netfun_nat", "subscriber_data_leak",  "CVE-2026-40245"),
    ("udr_netfun_nat", "callback_hijacking",    "CVE-2026-40248"),
    ("udm_app",        "suci_decryption",       "CVE-2023-46324"),
    ("udm_netfun_nat", "suci_decryption",       "CVE-2023-46324"),
    ("udm_netfun_nat", "information_disclosure", "CVE-2026-27642"),
    # Chain 3: SBI wipeout spreads to all peers
    ("amf_app",                    "denial_of_service", "CVE-2025-55904"),
    ("amf_netfun_nat",             "denial_of_service", "CVE-2025-55904"),
    ("ausf_app",                   "denial_of_service", "CVE-2025-55904"),
    ("ausf_netfun_nat",            "denial_of_service", "CVE-2025-55904"),
    ("bsf_app",                    "denial_of_service", "CVE-2025-55904"),
    ("bsf_netfun_nat",             "denial_of_service", "CVE-2025-55904"),
    ("nrf_app",                    "denial_of_service", "CVE-2025-55904"),
    ("nrf_netfun_nat",             "denial_of_service", "CVE-2025-55904"),
    ("nssf_app",                   "denial_of_service", "CVE-2025-55904"),
    ("nssf_netfun_nat",            "denial_of_service", "CVE-2025-55904"),
    ("pcf_app",                    "denial_of_service", "CVE-2025-55904"),
    ("pcf_netfun_nat",             "denial_of_service", "CVE-2025-55904"),
    ("smf_app",                    "denial_of_service", "CVE-2025-55904"),
    ("smf_netfun_nat",             "denial_of_service", "CVE-2025-55904"),
    ("udm_app",                    "denial_of_service", "CVE-2025-55904"),
    ("udm_netfun_nat",             "denial_of_service", "CVE-2025-55904"),
    ("udr_app",                    "denial_of_service", "CVE-2025-55904"),
    ("udr_netfun_nat",             "denial_of_service", "CVE-2025-55904"),
    ("upf_app",                    "denial_of_service", "CVE-2025-55904"),
    ("upf_netfun_nat",             "denial_of_service", "CVE-2025-55904"),
    ("discovery_app",              "denial_of_service", "CVE-2025-55904"),
    ("k8s-pod-network_network_ip", "denial_of_service", "CVE-2025-55904"),
]


def _section(out, title: str, facts: list) -> None:
    if not facts:
        return
    bar = "─" * max(0, 62 - len(title))
    out.write(f"\n% ── {title} {bar}\n")
    for f in facts:
        out.write(f + "\n")


def build_sections() -> list[tuple[str, list[str]]]:
    return [
        ("threat/1",       [f"threat({pl(t)})."                    for t in THREATS]),
        ("misbehavior/1",  [f"misbehavior({pl(m)})."               for m in MISBEHAVIORS]),
        ("cause/2",        [f"cause({pl(t)},{pl(m)})."             for t, m in CAUSE]),
        ("exploitable/2",  [f"exploitable({pl(c)},{pl(t)})."       for c, t in EXPLOITABLE]),
        ("induce/2",       [f"induce({pl(m)},{pl(c)})."            for m, c in INDUCE]),
        ("exposed/2",      [f"exposed({pl(e)},{pl(c)})."           for e, c in EXTRA_EXPOSED]),
        ("spread/3",       [f"spread({pl(e)},{pl(t)},{pl(c)})."    for e, t, c in SPREAD]),
    ]


def fill_prolog_file(input_path: str, output_path: str) -> None:
    with open(input_path, "r", encoding="utf-8") as fh:
        base = fh.read()

    sections = build_sections()
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_path, "w", encoding="utf-8") as out:
        out.write(base)
        out.write("\n\n")
        out.write("% ════════════════════════════════════════════════════════════\n")
        out.write(f"% 5G attack-scenario knowledge base — filler.py  {stamp}\n")
        out.write("%\n")
        out.write("%  Chain 1  Subscriber Harvest → Session Wiretap\n")
        out.write("%  Chain 2  Cascading Core Collapse (UPF → SMF → UDR)\n")
        out.write("%  Chain 3  Whole-Stack Wipeout (CVE-2025-55904)\n")
        out.write("% ════════════════════════════════════════════════════════════\n")
        for title, facts in sections:
            _section(out, title, facts)


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    input_path  = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "generated.p")
    output_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(here, "filled.p")

    if not os.path.exists(input_path):
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    fill_prolog_file(input_path, output_path)

    sections = build_sections()
    total = sum(len(f) for _, f in sections)
    print(f"Written {total} facts → {output_path}")
    for title, facts in sections:
        print(f"  {len(facts):3d}  {title}")


if __name__ == "__main__":
    main()

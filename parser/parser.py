#!/usr/bin/env python3
import json
import sys
import argparse
from datetime import datetime
from itertools import combinations


def extract_name(name_obj: dict) -> str:
    if not name_obj or not isinstance(name_obj, dict):
        return ""
    for key in ("local", "hostname", "uri", "uuid"):
        if key in name_obj:
            return name_obj[key]
    return ""


def get_entity_id(sid: dict) -> str:
    """Derive a human-readable entity id from a sid dict.
    Priority: name_type_subtype > name_type > name_subtype > namespace_name > domain_name > name
    """
    if not sid or not isinstance(sid, dict):
        return ""
    name = sid.get("name", "")
    if not name:
        return ""
    type_val = sid.get("type", "")
    subtype_val = sid.get("subtype", "")
    if type_val and subtype_val:
        suffix = f"{type_val}_{subtype_val}"
    elif type_val:
        suffix = type_val
    elif subtype_val:
        suffix = subtype_val
    else:
        for field in ("namespace", "domain"):
            val = sid.get(field, "")
            if val and val != name:
                return f"{val}_{name}"
        return name
    if suffix != name:
        return f"{name}_{suffix}"
    return name


def sid_key(sid: dict) -> tuple:
    if not sid:
        return ()
    return (
        sid.get("type", ""),
        sid.get("subtype", ""),
        sid.get("domain", ""),
        sid.get("namespace", ""),
        sid.get("name", ""),
    )


def pl(s: str) -> str:
    escaped = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def build_name_registry(services: list, links: list) -> dict:
    """Pre-compute entity ids, adding domain disambiguation only for colliding base names."""
    all_sids: dict[tuple, dict] = {}
    for item in services:
        svc = item.get("service", {})
        for s in [svc.get("sid", {})] + svc.get("subservices", []):
            if s:
                k = sid_key(s)
                if k not in all_sids:
                    all_sids[k] = s
    for item in links:
        link = item.get("link", {})
        for s in [link.get("sid", {})] + [p.get("sid", {}) for p in link.get("peers", [])]:
            if s:
                k = sid_key(s)
                if k not in all_sids:
                    all_sids[k] = s

    base_to_keys: dict[str, list] = {}
    for k, s in all_sids.items():
        base = get_entity_id(s)
        if base:
            base_to_keys.setdefault(base, []).append(k)
    colliding: set[str] = {b for b, keys in base_to_keys.items() if len(keys) > 1}

    registry: dict[tuple, str] = {}
    for k, s in all_sids.items():
        base = get_entity_id(s)
        if not base:
            registry[k] = ""
            continue
        if base not in colliding:
            registry[k] = base
            continue
        name = s.get("name", "")
        domain_val = s.get("domain", "")
        type_val = s.get("type", "")
        subtype_val = s.get("subtype", "")
        if type_val and subtype_val:
            type_suffix = f"{type_val}_{subtype_val}"
        elif type_val:
            type_suffix = type_val
        elif subtype_val:
            type_suffix = subtype_val
        else:
            type_suffix = ""
        if domain_val and domain_val != name:
            registry[k] = f"{name}_{domain_val}_{type_suffix}" if type_suffix else f"{domain_val}_{name}"
        else:
            registry[k] = base
    return registry


def collect_entities(services: list, registry: dict = None) -> tuple[list[str], list[dict]]:
    seen_keys: set[tuple] = set()
    entity_ids: list[str] = []
    dropped: list[dict] = []

    for item in services:
        svc = item.get("service", {})
        sid = svc.get("sid", {})
        if not sid:
            dropped.append({"kind": "service", "sid": sid, "reason": "missing sid"})
            continue
        key = sid_key(sid)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        eid = registry[key] if registry and key in registry else get_entity_id(sid)
        if eid:
            entity_ids.append(eid)
        else:
            dropped.append({"kind": "service", "sid": sid, "reason": "empty entity id"})

        for sub in svc.get("subservices", []):
            sub_key = sid_key(sub)
            if sub_key in seen_keys:
                continue
            seen_keys.add(sub_key)
            sub_eid = registry[sub_key] if registry and sub_key in registry else get_entity_id(sub)
            if sub_eid:
                entity_ids.append(sub_eid)
            else:
                dropped.append({"kind": "subservice", "sid": sub, "reason": "empty entity id"})

    return sorted(set(entity_ids)), dropped


def process_links(links: list, registry: dict = None) -> dict:
    """Parse all links and return sets of Prolog relations: contains, controls, connects, defends, unmatched, skipped."""
    contains: set[tuple] = set()
    controls: set[tuple] = set()
    connects: set[tuple] = set()
    defends: set[str] = set()
    unmatched: list[dict] = []
    skipped: list[dict] = []
    fwd_endpoints: dict[str, set] = {}

    for item in links:
        link = item.get("link", {})
        link_type = link.get("link_type", "")
        sid = link.get("sid", {})
        role = link.get("role", "")
        peers = link.get("peers", [])

        sk = sid_key(sid)
        subject_id = registry[sk] if registry and sk in registry else get_entity_id(sid)

        for peer in peers:
            peer_sid = peer.get("sid", {})
            peer_role = peer.get("role", "")
            pk = sid_key(peer_sid)
            peer_id = registry[pk] if registry and pk in registry else get_entity_id(peer_sid)

            if not subject_id or not peer_id:
                skipped.append({
                    "link_type": link_type,
                    "subject": subject_id or f"<empty sid: {sid}>",
                    "role": role,
                    "peer": peer_id or f"<empty sid: {peer_sid}>",
                    "peer_role": peer_role,
                })
                continue

            pair_matched = False

            if link_type in ("containing", "hosting"):
                if role == "guest" and peer_role == "host":
                    contains.add((peer_id, subject_id))
                    pair_matched = True
                elif role == "host" and peer_role == "guest":
                    contains.add((subject_id, peer_id))
                    pair_matched = True
                elif role == "guest" and peer_role == "contained":
                    contains.add((subject_id, peer_id))
                    pair_matched = True

            elif link_type == "controlling":
                if role == "controlled" and peer_role == "control":
                    controls.add((peer_id, subject_id))
                    pair_matched = True
                elif role == "control" and peer_role == "controlled":
                    controls.add((subject_id, peer_id))
                    pair_matched = True

            elif link_type == "packet_flow":
                if role == "endpoint" and peer_role == "forwarding":
                    fwd_endpoints.setdefault(peer_id, set()).add(subject_id)
                    pair_matched = True
                elif role == "forwarding" and peer_role == "endpoint":
                    fwd_endpoints.setdefault(subject_id, set()).add(peer_id)
                    pair_matched = True
                elif role == "forwarding" and peer_role == "forwarding":
                    connects.add(("packet_flow", subject_id, peer_id))
                    connects.add(("packet_flow", peer_id, subject_id))
                    pair_matched = True

            elif link_type == "api":
                if role == "client" and peer_role == "server":
                    connects.add(("api", subject_id, peer_id))
                    connects.add(("api", peer_id, subject_id))
                    pair_matched = True
                elif role == "server" and peer_role == "client":
                    connects.add(("api", peer_id, subject_id))
                    connects.add(("api", subject_id, peer_id))
                    pair_matched = True

            elif link_type == "protecting":
                if role == "protected":
                    defends.add(subject_id)
                    pair_matched = True
                elif peer_role == "protected":
                    defends.add(peer_id)
                    pair_matched = True

            if not pair_matched:
                unmatched.append({
                    "link_type": link_type,
                    "subject": subject_id,
                    "role": role,
                    "peer": peer_id,
                    "peer_role": peer_role,
                })

    for fwd, endpoints in fwd_endpoints.items():
        ep_list = sorted(endpoints)
        for ep_a, ep_b in combinations(ep_list, 2):
            connects.add((fwd, ep_a, ep_b))
            connects.add((fwd, ep_b, ep_a))

    return {
        "contains": contains,
        "controls": controls,
        "connects": connects,
        "defends": defends,
        "unmatched": unmatched,
        "skipped": skipped,
    }


def collect_vulnerabilities(service_vulns: list, registry: dict = None) -> tuple[list, list]:
    vulns: set[str] = set()
    exposed: set[tuple] = set()

    for entry in service_vulns:
        sid = entry.get("service_sid", {})
        k = sid_key(sid)
        entity_id = registry[k] if registry and k in registry else get_entity_id(sid)
        if not entity_id:
            continue
        for vuln in entry.get("vulnerabilities", []):
            cve_id = vuln.get("cve_id", "").strip()
            if cve_id:
                vulns.add(cve_id)
                exposed.add((entity_id, cve_id))

    return sorted(vulns), sorted(exposed)


def write_prolog(
    out,
    input_path: str,
    entity_ids: list[str],
    relations: dict,
    load_rule: bool,
    vulnerabilities: list = None,
    exposed_pairs: list = None,
) -> None:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    out.write(f"% Auto-generated from {input_path} on {stamp}\n")
    out.write("% DO NOT EDIT — regenerate with parser.py\n\n")

    if load_rule:
        out.write(":- ['rule.p'].\n\n")

    out.write("%%%%%% ENTITIES\n\n")
    for eid in entity_ids:
        out.write(f"digital_entity({pl(eid)}).\n")

    out.write("\n%%%%% RELATIONS\n")

    contains = sorted(relations["contains"])
    if contains:
        out.write("\n% --- Containment ---\n")
        for container, guest in contains:
            out.write(f"contain({pl(container)},{pl(guest)}).\n")

    controls = sorted(relations["controls"])
    if controls:
        out.write("\n% --- Controls ---\n")
        for controller, controlled in controls:
            out.write(f"control({pl(controller)},{pl(controlled)}).\n")

    connects = sorted(relations["connects"])
    if connects:
        out.write("\n% --- Connections ---\n")
        for via, e1, e2 in connects:
            out.write(f"connect({pl(via)},{pl(e1)},{pl(e2)}).\n")

    if vulnerabilities:
        out.write("\n% --- Vulnerabilities ---\n")
        for cve in vulnerabilities:
            out.write(f"vulnerability({pl(cve)}).\n")

    if exposed_pairs:
        out.write("\n% --- Exposed ---\n")
        for entity, cve in exposed_pairs:
            out.write(f"exposed({pl(entity)},{pl(cve)}).\n")


def parse_args():
    p = argparse.ArgumentParser(
        description="Convert a ctxd-v2.0 JSON file to a Miranda Prolog .p file."
    )
    p.add_argument("input", help="Input JSON file (ctxd-v2.0 format)")
    p.add_argument("-o", "--output", help="Output .p file (default: input with .p extension)")
    p.add_argument("--no-load-rule", action="store_true", help="Do not prepend :- ['rule.p'].")
    p.add_argument("--audit", action="store_true", help="Print a coverage report after parsing.")
    return p.parse_args()


def _print_audit(links: list, relations: dict, dropped: list, services: list = None) -> None:
    from collections import Counter

    unmatched = relations["unmatched"]
    skipped = relations["skipped"]

    total_pairs = 0
    seen_by_type: Counter = Counter()
    for item in links:
        link = item.get("link", {})
        link_type = link.get("link_type", "")
        sid = link.get("sid", {})
        peers = link.get("peers", [])
        subject_id = get_entity_id(sid)
        for peer in peers:
            peer_id = get_entity_id(peer.get("sid", {}))
            if subject_id and peer_id:
                seen_by_type[link_type] += 1
                total_pairs += 1

    unmatched_by_type: Counter = Counter(e["link_type"] for e in unmatched)
    matched_by_type = {lt: seen_by_type[lt] - unmatched_by_type[lt] for lt in seen_by_type}

    print("\n--- AUDIT REPORT ---")
    print(f"Total peer pairs with valid ids : {total_pairs}")
    print(f"Pairs skipped (missing entity id): {len(skipped)}")
    print()
    print(f"{'link_type':<20} {'seen':>6} {'matched':>8} {'unmatched':>10}")
    print("-" * 48)
    for lt in sorted(seen_by_type):
        seen = seen_by_type[lt]
        unm = unmatched_by_type[lt]
        mat = matched_by_type[lt]
        flag = "  <-- !" if unm else ""
        print(f"{lt:<20} {seen:>6} {mat:>8} {unm:>10}{flag}")
    print()

    if unmatched:
        print(f"UNMATCHED pairs ({len(unmatched)}) — no Prolog fact generated:")
        combo: Counter = Counter(
            (e["link_type"], e["role"], e["peer_role"]) for e in unmatched
        )
        for (lt, r, pr), count in sorted(combo.items()):
            print(f"  {lt:<20}  role={r!r:<20}  peer_role={pr!r:<20}  × {count}")
        print()
        print("  Sample entries (up to 5 per combo):")
        shown: Counter = Counter()
        for e in unmatched:
            key = (e["link_type"], e["role"], e["peer_role"])
            if shown[key] < 5:
                print(f"    {e['link_type']}  {e['subject']!r} [{e['role']}]"
                      f"  ↔  {e['peer']!r} [{e['peer_role']}]")
                shown[key] += 1
    else:
        print("All peer pairs with valid ids were matched.")

    if skipped:
        print(f"\nSKIPPED pairs ({len(skipped)}) — empty entity id (sample up to 10):")
        for e in skipped[:10]:
            print(f"  {e['link_type']}  {e['subject']!r} [{e['role']}]"
                  f"  ↔  {e['peer']!r} [{e['peer_role']}]")

    print()
    if dropped:
        raw_counts: Counter = Counter()
        if services:
            for item in services:
                svc = item.get("service", {})
                s = svc.get("sid", {})
                if s:
                    raw_counts[sid_key(s)] += 1
                for sub in svc.get("subservices", []):
                    if sub:
                        raw_counts[sid_key(sub)] += 1

        print(f"DROPPED services ({len(dropped)} unique) — sid present but produced no entity id:")
        for e in dropped:
            count = raw_counts.get(sid_key(e["sid"]), 1) if services else 1
            times = f"  (seen ×{count} across all services)" if count > 1 else ""
            print(f"  [{e['kind']}]  sid={e['sid']}  reason={e['reason']!r}{times}")
    else:
        print("All services/subservices with a sid produced a valid entity id.")
    print("--- END AUDIT ---\n")


def main():
    args = parse_args()

    if args.output:
        output_path = args.output
    else:
        base = args.input
        if base.endswith(".json"):
            base = base[:-5]
        output_path = base + ".p"

    try:
        with open(args.input, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    services = data.get("services", [])
    links = data.get("links", [])
    service_vulns = data.get("service_vulnerabilities", [])

    print(f"Loaded {len(services)} service entries, {len(links)} link entries, "
          f"{len(service_vulns)} vulnerability entries.")

    registry = build_name_registry(services, links)
    entity_ids, dropped = collect_entities(services, registry)
    relations = process_links(links, registry)
    vulnerabilities, exposed_pairs = collect_vulnerabilities(service_vulns, registry)

    print(
        f"Unique entities: {len(entity_ids)} | "
        f"contain: {len(relations['contains'])} | "
        f"control: {len(relations['controls'])} | "
        f"connect: {len(relations['connects'])} | "
        f"vulnerabilities: {len(vulnerabilities)} | "
        f"exposed pairs: {len(exposed_pairs)}"
    )

    if args.audit:
        _print_audit(links, relations, dropped, services)

    with open(output_path, "w", encoding="utf-8") as out:
        write_prolog(
            out,
            args.input,
            entity_ids,
            relations,
            load_rule=not args.no_load_rule,
            vulnerabilities=vulnerabilities,
            exposed_pairs=exposed_pairs,
        )

    print(f"Written: {output_path}")


if __name__ == "__main__":
    main()

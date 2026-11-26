"""Network context layer.

Loads a description of YOUR network — zones, criticality, the allowed flows between zones,
and a threat model mapped to MITRE ATT&CK and to the hunts — and uses it to:
  * annotate each finding with its src/dst zone, whether the flow breaks policy, and which
    threat-model scenario (and ATT&CK technique) it matches;
  * add a score bonus for policy violations and hits on critical zones (so a workstation
    reaching the domain zone outranks a louder but harmless anomaly);
  * hand the LLM a compact summary to reason over (grounding / RAG, not fine-tuning).

The context is a YAML or JSON file; see network_context.yaml for the format. Point the
pipeline at it with NSM_NETCONTEXT=/path. If it is absent, the context is simply "off" and
everything falls back to the plain behaviour.
"""
import ipaddress
import json
import os

BONUS_BY_CRIT = {5: 10, 4: 8, 3: 5, 2: 3, 1: 1, 0: 0}
BONUS_CAP = 14


def _load_file(path):
    text = open(path).read()
    try:
        import yaml
        return yaml.safe_load(text)
    except ImportError:
        return json.loads(text)   # a JSON context needs no extra dependency


class NetContext:
    def __init__(self, data=None):
        self.enabled = bool(data)
        data = data or {}
        self.name = data.get("name", "network")
        self.zones = data.get("zones", [])
        self._nets = []  # (network, zone_name, criticality)
        for z in self.zones:
            for c in z.get("cidrs", []):
                try:
                    self._nets.append((ipaddress.ip_network(c, strict=False), z["name"], int(z.get("criticality", 1))))
                except ValueError:
                    pass
        self._nets.sort(key=lambda n: n[0].prefixlen, reverse=True)  # most specific wins
        self.allowed = {(f["from"], f["to"]) for f in data.get("allowed_flows", [])}
        self.violation_hunts = set(data.get("violation_hunts", []))
        self.threats = data.get("threat_model", [])
        self._threat_by_hunt = {}
        for t in self.threats:
            for h in t.get("hunts", []):
                self._threat_by_hunt[h] = t
        self.asset_crit = {a["ip"]: int(a["criticality"]) for a in data.get("critical_assets", []) if "ip" in a}
        self.raw = data

    # ---- lookups ----
    def zone_of(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "external"   # a domain name or non-IP dst is outside the network
        for net, name, _ in self._nets:
            if addr in net:
                return name
        return "unknown"

    def criticality_of(self, ip):
        if ip in self.asset_crit:
            return self.asset_crit[ip]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return 1
        for net, _, crit in self._nets:
            if addr in net:
                return crit
        return 1

    def flow_policy(self, src, dst):
        """'allowed' | 'violation' | 'external' for a src->dst flow, by zone."""
        zs, zd = self.zone_of(src), self.zone_of(dst)
        if zd == "external":
            return "external"
        if (zs, zd) in self.allowed or zs == zd and zs not in ("workstations",):
            return "allowed"
        return "violation"

    def threat_for(self, hunt):
        return self._threat_by_hunt.get(hunt)

    # ---- annotation ----
    def annotate_findings(self, findings):
        if not self.enabled:
            return
        for f in findings:
            zs, zd = self.zone_of(f["src"]), self.zone_of(f["dst"])
            flow_pol = self.flow_policy(f["src"], f["dst"])
            policy = "violation" if (flow_pol == "violation" or f["hunt"] in self.violation_hunts) else flow_pol
            t = self.threat_for(f["hunt"])
            f["zone_src"], f["zone_dst"] = zs, zd
            f["policy"] = policy                      # allowed | violation | external
            f["dst_criticality"] = self.criticality_of(f["dst"])
            f["threat_id"] = t["id"] if t else None
            f["threat_name"] = t["name"] if t else None

    def case_context(self, case):
        """Summarise the context signal for one case and the score bonus it earns."""
        fs = case["findings"]
        violations = [f for f in fs if f.get("policy") == "violation"]
        max_crit = max((f.get("dst_criticality", 1) for f in violations), default=0)
        threats = []
        for f in fs:
            if f.get("threat_id") and f["threat_id"] not in [t["id"] for t in threats]:
                t = self.threat_for(f["hunt"])
                if t:
                    threats.append({"id": t["id"], "name": t["name"], "technique": t.get("technique")})
        crit_zones = sorted({f["zone_dst"] for f in violations if f.get("dst_criticality", 1) >= 3})
        bonus = 0
        if violations:
            bonus = BONUS_BY_CRIT.get(max_crit, 0) + min(4, len(threats))
        bonus = min(BONUS_CAP, bonus)
        return {"violations": len(violations), "max_criticality": max_crit,
                "critical_zones_reached": crit_zones, "threats": threats, "bonus": bonus}

    def bonus_for(self, case):
        return self.case_context(case)["bonus"] if self.enabled else 0

    # ---- exports ----
    def summary(self):
        """Compact context for the LLM prompt."""
        return {"network": self.name,
                "zones": [{"name": z["name"], "criticality": z.get("criticality"),
                           "description": z.get("description", "")} for z in self.zones],
                "allowed_flows": sorted(f"{a}->{b}" for a, b in self.allowed),
                "policy": "any internal flow not in allowed_flows, and any of these hunts anywhere, is a policy violation: "
                          + ", ".join(sorted(self.violation_hunts)),
                "threat_model": [{"id": t["id"], "name": t["name"], "technique": t.get("technique"),
                                  "hunts": t.get("hunts", []), "path": t.get("path", "")} for t in self.threats]}

    def to_json(self):
        """Full context baked into the dashboard (so the browser can draw the zone map and re-score)."""
        return {"name": self.name, "zones": self.zones, "allowed_flows": sorted(list(self.allowed)),
                "violation_hunts": sorted(self.violation_hunts), "threat_model": self.threats,
                "critical_assets": self.raw.get("critical_assets", [])}


def load(path=None):
    """Load the context from `path` or $NSM_NETCONTEXT, or a nearby network_context.yaml. Never raises."""
    path = path or os.environ.get("NSM_NETCONTEXT")
    if not path:
        for c in ("network_context.yaml", "network_context.yml", "network_context.json",
                  os.path.join(os.path.dirname(__file__), "..", "network_context.yaml")):
            if os.path.exists(c):
                path = c
                break
    if path and os.path.exists(path):
        try:
            return NetContext(_load_file(path))
        except Exception as e:
            print(f"[netcontext] could not load {path}: {e}")
    return NetContext(None)


if __name__ == "__main__":
    import sys
    nc = load(sys.argv[1] if len(sys.argv) > 1 else None)
    print("enabled:", nc.enabled, "| zones:", [z["name"] for z in nc.zones])
    for ip in ("10.77.0.104", "10.77.0.10", "10.77.0.20", "10.77.0.250"):
        print(f"  {ip}: zone={nc.zone_of(ip)} crit={nc.criticality_of(ip)}")
    print("WS->WS:", nc.flow_policy("10.77.0.104", "10.77.0.102"),
          "| WS->DC:", nc.flow_policy("10.77.0.104", "10.77.0.10"),
          "| WS->FS:", nc.flow_policy("10.77.0.104", "10.77.0.20"))

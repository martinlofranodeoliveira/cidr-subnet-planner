# cidr-subnet-planner

[Português](README.pt-BR.md) · [Contract](docs/contract.md) · [Design](docs/design.md)

Development version **0.1.0** by [Lofrano Tecnologia](https://lofranotecnologia.com.br). Deterministic IPv4/IPv6 CIDR auditing, VLSM carving, and minimal exact route summarization in Python 3.13. Runtime and tests use only the standard library; no model, API, telemetry, or network access is used by the application. All demo data is synthetic.

## Run and install

From the project directory with Python 3.13 or newer, no installation is needed:

```sh
python3 -m unittest discover -s tests -v
python3 -m cidr_planner demo
python3 -m cidr_planner demo --format text
```

Optional package installation, with pip and setuptools >=68 already available:

```sh
python3 -m pip install --no-build-isolation --no-deps .
cidr-planner demo --format text
```

Setuptools is a packaging dependency only. The source-tree commands above work offline without pip or setuptools. Installation needs a writable Python environment, such as an existing virtual environment.

## What it does

- Flags non-zero host bits with a canonical suggestion, never silently repairing strict input.
- Reports every nested or exact collision with both labels, direction, family, and overlap count.
- Uses a selected explicit special-purpose scope table, including mixed-prefix detection. `other_or_reserved` means **unclassified by this table**, not globally reachable or necessarily reserved.
- Allocates largest blocks first, then names in Unicode code-point order, from the lowest aligned free address, respecting validated reservations.
- Returns the exact minimal free CIDR cover and a structured first-failure diagnostic when aligned space runs out.
- Summarizes the exact union without adding addresses; non-aligned adjacent blocks stay separate.

The design uses integer intervals and binary prefix splits rather than enumerating hosts or possible subnets, including for IPv6 `/0`. Explicit size limits bound inventory, collisions, demands, intermediate free inventories, and CLI input. See the [precise contract](docs/contract.md).

## Small library examples

```python
from cidr_planner import audit_inventory, plan_vlsm, summarize_cidrs

audit = audit_inventory([
    {"label": "vpc", "cidr": "10.10.0.0/16"},
    {"label": "subnet", "cidr": "10.10.4.0/22"},
], strict=True)
print(audit["collisions"][0]["overlapping_addresses"])  # 1024

plan = plan_vlsm("10.0.0.0/24", [
    {"name": "workers", "prefix_length": 25},
    {"name": "db", "required_hosts": 50},
], reserved_cidrs=["10.0.0.64/26"])
print([(a["name"], a["cidr"]) for a in plan["allocations"]])
# [('workers', '10.0.0.128/25'), ('db', '10.0.0.0/26')]

print(summarize_cidrs(["10.0.0.0/25", "10.0.0.128/25"])["summarized_cidrs"])
# ['10.0.0.0/24']
```

Strict parsing raises `NonCanonicalCIDRError` for `192.168.1.42/24`, with `canonical_cidr='192.168.1.0/24'`. Strict inventory auditing instead retains a rejected record and excludes it from collisions. Lenient auditing always flags host bits and checks the canonical suggestion too.

## CLI JSON input

```sh
printf '%s\n' '[{"label":"lab","cidr":"192.0.2.42/24"}]' | python3 -m cidr_planner audit --strict --input -
printf '%s\n' '{"parent_supernet":"10.0.0.0/24","demands":[{"name":"lab","required_hosts":50}]}' | python3 -m cidr_planner plan --input -
printf '%s\n' '["10.0.0.0/25","10.0.0.128/25"]' | python3 -m cidr_planner summarize --input -
```

`--input` also accepts an explicitly selected local JSON file. Reports go to stdout; input errors are JSON on stderr. Exit codes: `0` success/clean audit, `1` audit findings or insufficient space, `2` invalid input/resource/I/O error. The demo exits `0` despite its intentional audit findings.

Example excerpt from the text demo:

```text
[1] Inventory Audit
  Entries: 9 (IPv4: 7, IPv6: 2)
  Non-canonical inputs flagged: 1
```

The full demo reports four collisions and the following accounting and summarization:

```text
  Accounting: reserved=128 + allocated=259 + free=125 = 512

[3] Contiguous Prefix Summarization
  Input prefixes: 7 -> Summarized: 4 (reduced by 3)
    - 10.80.0.0/23
    - 10.80.2.128/25
    - 10.80.3.0/25
    - 2001:db8:10::/48
```

## Addressing and limitations

`standard_ipv4` subtracts network and broadcast for `/0` through `/30`, gives `/31` zero usable hosts, and `/32` one host. `rfc3021_p2p` differs only by giving `/31` two hosts. `ipv6` counts all addresses and emits counts, including reported host demands, as decimal strings for JSON precision.

This is offline address math, not a network scanner, DNS/WHOIS client, IPAM database, BGP validator, or proof of registrability/reachability. The scope snapshot is deliberately incomplete and does not model nested registry exceptions. No broad RFC compliance is claimed. Cloud providers may reserve additional addresses, such as the first four and last one; these vendor rules are not implemented. Largest-first greedy allocation is deterministic, not a general placement optimizer. Failed plans contain provisional allocations and must not be treated as complete plans.

MIT © 2026 Lofrano Tecnologia. General contact: [official homepage](https://lofranotecnologia.com.br). Security: [private vulnerability reporting](https://github.com/martinlofranodeoliveira/cidr-subnet-planner/security/advisories/new).

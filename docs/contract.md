# Development 0.1.0 contract / Contrato de desenvolvimento 0.1.0

## English

### Input grammar and API

Python >=3.13. Library collections are finite `Sequence` objects, excluding strings/bytes as collections. CIDRs themselves must be strings: one address, one `/`, then an ASCII decimal prefix length without leading zeros except `0`. Addresses use `ipaddress.ip_address` syntax; IPv4 dotted decimal and compressed/expanded IPv6 are supported. No whitespace, zones (`%`), bare addresses, netmasks, hostmasks, signs, integer/bool address substitutes, or out-of-family prefix lengths. Equivalent IPv6 text is normalized; textual case/compression differences are not host-bit errors. Strict flags must be actual booleans.

`parse_cidr(value, strict=True, limits=DEFAULT_LIMITS)` returns `ParsedCIDR`. Non-zero host bits raise `NonCanonicalCIDRError`, code `non_canonical_host_bits`, with `input_cidr`, `canonical_cidr`, `host_bits_hex`, and `family`. `inspect_cidr` records those bits without rejecting; `parse_cidr(strict=False)` explicitly opts into the same behavior. Parsed objects expose integer intervals, counts and the `ipaddress` network; `to_dict()` provides JSON-compatible metadata. `classify_prefix_scope` and `calculate_addressing_metrics` accept canonical CIDR strings or `ipaddress` network objects; standalone string inputs are strict.

`audit_inventory(entries, strict=False, limits=...)` accepts `InventoryEntry(label, cidr)`, dictionaries containing `cidr`, `(label, cidr)` tuples, or CIDR strings. Dictionary label resolution is `label`, then `name`, then `entry-{index}`; string entries get the generated label. Duplicate labels are allowed; zero-based indices distinguish entries. Labels/names must be printable, nonblank strings; surrounding spaces are trimmed, and length is checked before trimming. Control characters, surrogate code points and invisible formatting controls are rejected by `str.isprintable()`.

Audit reports contain `entries`, `non_canonical_inputs`, `collisions`, `summary`, `strict_mode`, `strict_validation_passed`, and `valid`. Malformed syntax aborts with an exception, not a partial report. Host-bit errors are retained as findings in either mode. Strict mode marks them `rejected_non_canonical` and excludes them from collisions; non-strict mode marks them `non_canonical_flagged` and compares their suggested canonical networks. `strict_validation_passed` means no host-bit findings, independently of collisions and the selected mode. `valid` means neither findings nor collisions.

Each same-family intersecting pair is reported once, ordered by original `(first_index, second_index)`. `classification` describes the first relative to the second: `exact_duplicate`, `subnet_contained_by_supernet`, or `supernet_contains_subnet`; `inverse_classification` reverses direction. Both labels/CIDRs, family, overlap CIDR, and address count are included. Canonical CIDRs are laminar: an intersection is the smaller network, never an arbitrary crossing interval. Different families never collide. Summary type counts count the primary classification once per pair.

### Allocation and addressing

`plan_vlsm(parent_supernet, demands, *, reserved_cidrs=(), default_addressing_profile=None, limits=...)` requires a strict parent and strict reservations. Reservations must match the family, be contained in the parent, and be pairwise disjoint, including duplicates. Equality with the parent is allowed for a reservation or allocation; containment never permits addresses outside the parent.

Demands are `SubnetDemand` objects or dictionaries with a unique trimmed `name`, exactly one non-null `prefix_length` or `required_hosts`, and optional `addressing_profile`. Integers exclude bool. Host counts must be positive and within the family capacity; explicit prefixes are in 0..32 or 0..128. Null means unspecified. Unknown dictionary fields are ignored. The default profile is `standard_ipv4` or `ipv6` according to the parent; a demand can override it only with a family-compatible profile.

| Profile | Prefix | Usable count |
| --- | --- | --- |
| standard_ipv4 | /0 through /30 | total minus 2 |
| standard_ipv4 | /31 | 0; usable endpoints are null |
| standard_ipv4 | /32 | 1 |
| rfc3021_p2p | /31 | 2 |
| rfc3021_p2p | other IPv4 prefixes | same as standard_ipv4 |
| ipv6 | /0 through /128 | total, including both endpoints |

`prefix_length_for_required_hosts(count, version=4|6, profile=None)` selects the most specific sufficient prefix. The previous spelling `prefix_length_for_Required_hosts` remains an alias. IPv4 capacity tops out at 4294967294 usable addresses under these profiles. `calculate_addressing_metrics` reports endpoints, profile, prefix, total and usable counts; IPv4 has `broadcast_address`, IPv6 has `last_address` without implying an IPv6 broadcast concept.

Demands sort by ascending resolved prefix length (largest block), then case-sensitive Unicode name order. Each takes the lowest available aligned subnet. Reservations, free blocks, and allocations are deterministic; reservation/free lists sort by address. `free_blocks` is the disjoint minimal CIDR cover of exactly the unallocated, unreserved portion. No host enumeration is performed.

Success: `status='allocated'`, `valid=true`, `diagnostic=null`. On the first unfulfillable demand: `status='insufficient_contiguous_space'`, `valid=false`; no later demand is attempted. Earlier allocations are provisional and retained. The diagnostic includes `unfulfilled_demand` with name, resolved prefix, requested hosts/profile and required addresses; the largest aligned free CIDR (size first, lowest-address tie), its prefix/count, and the total remaining free count. No free space yields null block/prefix and zero counts. A demand larger than its parent also uses this diagnostic. Total free addresses can exceed the demand while fragmentation prevents allocation.

The report also includes parent metadata, `reserved_cidrs`, `allocations`, `free_block_details`, and `accounting`. Each allocation includes requested/resolved sizing, profile, scope, usable endpoints and counts. Accounting states parent = reserved + allocated + free, including on exhaustion. `conservation_verified` records this internal count check; tests additionally verify disjoint interval coverage.

### Summarization and JSON types

`summarize_cidrs(cidrs, strict=True, limits=...)` returns `input_count`, `output_count`, `reduction_count`, `summarized_cidrs`, per-family `ipv4`/`ipv6` records, and `non_canonical_inputs`. Per-family records include counts and `unique_addresses`. Overlap, containment and duplicates are removed before aligned siblings are collapsed. Output covers exactly the input union, sorted IPv4 first, then IPv6 by address. Empty input returns empty output and zero counts. Adjacent non-siblings stay separate. Explicit `strict=False` permits normalization but records each host-bit input, index, and canonical suggestion.

Families are `ipv4`/`ipv6`. Address cardinalities are JSON integers for IPv4 and decimal strings for IPv6, including reported `required_hosts`; null sizing stays null. Corresponding `*_str` count fields are always decimal strings. Prefix lengths, indices and item/result counts remain integers. Library sizing input is an integer even for IPv6; the CLI accepts up to 39 digits, sufficient for 2^128.

### Bounds and errors

| PlannerLimits field | Default |
| --- | ---: |
| max_inventory_items | 2000 |
| max_collision_results | 10000 |
| max_vlsm_demands | 1000 |
| max_reserved_cidrs | 1000 |
| max_summarize_inputs | 4096 |
| max_free_blocks_output | 8192 |
| max_cidr_string_length | 64 characters |
| max_label_length | 128 characters before trimming |

All configured limits must be positive integers, not bool. The free-block limit applies during reservation subtraction and after each allocation, not just at return; a plan may therefore hit it even if later demands could reduce the inventory. A binary split adds at most 128 temporary entries. Callers raising limits take responsibility for increased resource use. No partial report is returned on a limit exception.

Validation errors derive from `CIDRPlannerError` with `code`, `message`, and JSON-compatible `to_dict()` details for ordinary data inputs. Principal codes include `non_canonical_host_bits`, `invalid_cidr_type`, syntax-specific codes, `invalid_strict_flag`, `invalid_label_characters`, `invalid_required_hosts`, `invalid_ip_version`, `required_hosts_exceeds_family_capacity`, `invalid_addressing_profile`, `profile_family_mismatch`, `invalid_demand_sizing`, `duplicate_demand_name`, `mixed_family_reservation`, `reservation_outside_supernet`, `overlapping_reservations`, and `resource_limit_exceeded`. Resource errors include `limit_name`, `limit_value`, `actual_value`. Messages are explanatory, not parsing interfaces. Internal invariant failures raise `RuntimeError`; they are not disguised as user errors.

### CLI

`python3 -m cidr_planner demo [--format json|text]` uses only synthetic fixed fixtures. Other commands require `--input FILE` or `--input -` for stdin:

- `audit [--strict]`: an entry array or `{"entries": [...]}`.
- `plan`: object with `parent_supernet`, `demands`; optional `reserved_cidrs`, `default_addressing_profile`.
- `summarize`: a CIDR array or `{"cidrs": [...]}`; strict parsing.

JSON input: UTF-8 without BOM, at most 1048576 bytes, at most 64 nested arrays/objects. Integers have at most 39 digits; floats, non-finite constants and duplicate object keys are rejected. Strings containing brackets do not consume nesting depth. Files are read only when explicitly selected; no recursive discovery, URL fetching or output-file writing occurs. Unknown dictionary fields are ignored, but still subject to JSON bounds.

Reports are indented JSON on stdout with no timestamps or randomness; only demo offers text. Errors emit `{"valid":false,"error":{"code":...,"message":...}}` on stderr, leaving stdout empty for input errors. Additional CLI codes: `invalid_input_schema`, `invalid_json`, `input_encoding_error`, `input_io_error`, `output_io_error`; byte/depth limits use `resource_limit_exceeded`. Exit 0 means clean/success, 1 means audit findings or allocation exhaustion, 2 means input/resource/read error. Demo exits 0 despite intentional findings. Argument syntax/help uses argparse's conventional text and exit codes, not the report schema. Output writes are flushed before success; output write/flush failures return 2 with code output_io_error when stderr remains available. An I/O failure may leave partial stdout. Diagnostics are best effort if stderr also fails. Named inputs must be regular local files and are opened nonblocking where the OS supports it; FIFOs/devices are rejected. Explicit stdin and filesystem faults still have no wall-clock deadline.

### Complete selected scope snapshot / Tabela completa de escopos selecionados

This table is intentionally bounded, not a complete special-purpose registry. Labels describe these whole ranges without modeling nested exceptions. Outside it, `other_or_reserved` means unclassified, NOT proof of reservation, allocation, public routability or reachability. A prefix touching multiple classes, including fallback, is `mixed`. Matched scopes/ranges follow table order; fallback is last. `/0` is mixed in both families. Neither `is_private` nor a default global category is used.

| Family | CIDR | Class | Basis |
| --- | --- | --- | --- |
| IPv4 | 0.0.0.0/8 | this_network | RFC 1122 / 6890 |
| IPv4 | 10.0.0.0/8 | private_rfc1918 | RFC 1918 |
| IPv4 | 100.64.0.0/10 | shared_cgnat | RFC 6598 |
| IPv4 | 127.0.0.0/8 | loopback | RFC 1122 |
| IPv4 | 169.254.0.0/16 | link_local | RFC 3927 |
| IPv4 | 172.16.0.0/12 | private_rfc1918 | RFC 1918 |
| IPv4 | 192.0.0.0/24 | ietf_protocol_assignments | RFC 6890 |
| IPv4 | 192.0.2.0/24 | documentation | RFC 5737 |
| IPv4 | 192.168.0.0/16 | private_rfc1918 | RFC 1918 |
| IPv4 | 198.18.0.0/15 | benchmarking | RFC 2544 |
| IPv4 | 198.51.100.0/24 | documentation | RFC 5737 |
| IPv4 | 203.0.113.0/24 | documentation | RFC 5737 |
| IPv4 | 224.0.0.0/4 | multicast | RFC 5771 |
| IPv4 | 240.0.0.0/4 | future_reserved | RFC 1112 / 6890 |
| IPv6 | ::/128 | unspecified | RFC 4291 |
| IPv6 | ::1/128 | loopback | RFC 4291 |
| IPv6 | ::ffff:0:0/96 | ipv4_mapped | RFC 4291 |
| IPv6 | 64:ff9b::/96 | ipv4_translated | RFC 6052 |
| IPv6 | 64:ff9b:1::/48 | ipv4_translated | RFC 8215 |
| IPv6 | 100::/64 | discard_only | RFC 6666 |
| IPv6 | 2001::/32 | teredo | RFC 4380 |
| IPv6 | 2001:2::/48 | benchmarking | RFC 5180 |
| IPv6 | 2001:db8::/32 | documentation | RFC 3849 |
| IPv6 | fc00::/7 | unique_local | RFC 4193 |
| IPv6 | fe80::/10 | link_local | RFC 4291 |
| IPv6 | ff00::/8 | multicast | RFC 4291 |

## Português

### Regras e resultados

O contrato é da versão de desenvolvimento 0.1.0. As assinaturas, campos, tipos e limites acima são os identificadores exatos da API. CIDRs exigem endereço, `/` e comprimento decimal ASCII sem zeros iniciais; sem espaços, zonas, máscaras textuais ou tipos impostores. `strict` exige bool. Bits de host em parsing estrito produzem exceção com sugestão canônica; na auditoria estrita produzem registros rejeitados, excluídos das colisões. A auditoria não estrita sempre sinaliza os bits e compara a sugestão. Nomes são strings imprimíveis, limitadas antes de remover espaços das pontas; nomes de demandas devem ser únicos após essa remoção. Dicionários ignoram campos desconhecidos.

Colisões são todos os pares da mesma família em ordem dos índices originais, com classificação da primeira entrada em relação à segunda, direção inversa, rótulos e cardinalidade. `valid` exige ausência de colisões e bits de host; `strict_validation_passed` considera apenas bits de host. Erros de sintaxe abortam a auditoria.

Reservas e rede pai são estritas, da mesma família, contidas e sem sobreposição entre reservas. Igualdade com a rede pai é permitida. Demandas usam exatamente um tamanho não nulo: prefixo inteiro ou quantidade positiva de hosts. Ordenação: maior bloco primeiro, depois nome sensível a maiúsculas por pontos de código Unicode. Cada demanda recebe o menor endereço alinhado disponível. Falha interrompe no primeiro pedido não atendido e conserva alocações provisórias, inventário livre exato e diagnóstico com demanda, maior bloco alinhado restante e total livre. Não se deve aplicar um plano incompleto.

Os perfis da tabela acima são regras matemáticas explícitas: `/31` padrão tem zero hosts; `/31` ponto a ponto tem dois; `/32` tem um; IPv6 conta todos os endereços. Não há regras de reservas de fornecedores de nuvem. Contagens de endereços e demandas reportadas de IPv6 são strings decimais; em IPv4 são inteiros. Campos `*_str` são sempre strings; índices, comprimentos e contagens de itens são inteiros. Entradas de demanda continuam sendo inteiros Python/JSON.

A sumarização retorna a cobertura CIDR mínima da união exata, IPv4 antes de IPv6, sem preencher lacunas. Duplicatas e blocos contidos são removidos; adjacentes não irmãos não se agregam. `strict=False` é opção explícita e retorna os bits de host em `non_canonical_inputs`. Blocos livres também são mínimos, sem irmãos agregáveis. Contabilidade exige reservado + alocado + livre = pai, inclusive em falhas.

### Escopo, limites e CLI

A tabela compartilhada acima é toda a seleção de escopos desta versão, não o registro completo de endereços especiais. Não há exceções aninhadas. `other_or_reserved` significa apenas não classificado por essa tabela, nunca prova de reserva ou alcance global. Interseção de classes gera `mixed`, inclusive com fallback; `/0` é misto nas duas famílias. Não se usa `is_private` para inferir alcance.

Os limites padrão estão na tabela `PlannerLimits`. Devem ser inteiros positivos, sem bool. O limite de blocos livres também vale durante o processamento; pode interromper um plano antes de demandas posteriores reduzirem o inventário. Quem aumentar limites assume o custo adicional. Exceções de domínio têm `code`, `message` e `to_dict()`; falhas internas de invariantes usam `RuntimeError`.

Comandos: `demo [--format json|text]`, `audit [--strict] --input FILE`, `plan --input FILE`, `summarize --input FILE`; `-` seleciona stdin. As estruturas aceitas são as descritas acima. Entrada JSON: UTF-8 sem BOM, até 1048576 bytes, profundidade 64, inteiros até 39 dígitos. Floats, constantes não finitas e chaves duplicadas são rejeitados. Não há busca recursiva de arquivos nem acesso a URLs.

Relatórios usam stdout; erros de entrada usam JSON em stderr e deixam stdout vazio. Códigos de saída: 0 sucesso/limpo, 1 achados ou falta de espaço, 2 erro de entrada/recurso/leitura. A demonstração retorna 0 com achados intencionais. Argumentos inválidos e ajuda usam o formato textual convencional do argparse. Escrita e flush são verificados antes do sucesso; falhas retornam 2 e código output_io_error quando stderr está disponível. A saída pode ser parcial, e diagnósticos são uma tentativa se stderr também falhar. Arquivos nomeados devem ser locais regulares; FIFOs/dispositivos são rejeitados com abertura não bloqueante quando suportada pelo sistema. Stdin explícito e falhas de filesystem continuam sem prazo de leitura.

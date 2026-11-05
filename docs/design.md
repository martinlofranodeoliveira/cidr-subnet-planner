# Design / Projeto

## English

Development 0.1.0 keeps the existing small module boundaries: parser, explicit scopes, profiles, auditor, summarizer, VLSM engine, limits/errors, and CLI. The library has no file or network side effects. The CLI reads only the selected file or stdin and writes reports to the supplied standard streams. There is no model/API dependency, persistence or telemetry.

### Arithmetic and determinism

A canonical CIDR is an aligned integer interval of power-of-two length. Intersecting CIDRs in the same family must be equal or nested. The auditor checks every pair, preserving original indices rather than silently deduplicating allocations. At the default 2000-entry cap there are at most 1999000 pair checks; output is independently limited to 10000 collisions. No partial collision list is returned on a limit failure.

Scopes are interval intersections with disjoint selected special ranges. Summing their covered lengths determines whether fallback space exists in the prefix. More than one distinct class means mixed, even when the first address is special. The table deliberately does not assert a public/global class by exclusion, nor promise complete registry semantics.

VLSM starts with the parent, subtracts disjoint reservations by following binary splits to each target, and keeps untouched siblings as free blocks. Demands are resolved before allocation, sorted largest-first/name-second, and carved from the first fitting address-ordered free block. Each subtraction replaces a free node by maximal untouched subtrees; it cannot introduce two free siblings without their parent already having been free. This maintains a minimal free cover without a full merge pass. Each split requires at most the family width, 32 or 128, rather than materializing all subnets. The free inventory is bounded during processing, with at most 128 temporary additions per split.

The allocator is intentionally greedy and does not search alternative complete layouts. Exhaustion returns the exact first failure and the current provisional partition, not a fabricated empty success. All state is local to the call; callers' collections are not modified. Size accounting is checked internally; tests independently check intervals, absence of gaps/overlap and absence of mergeable free siblings.

Summarization separates families, uses `ipaddress.collapse_addresses`, and independently checks union cardinality with merged integer intervals. It never fills address gaps. Work is driven by the input prefix count, not the number of represented addresses.

### Validation and resource boundary

Defaults bound all collections and collision/free output. Pairwise auditing and reservation validation are quadratic in bounded input counts; allocation scans the bounded free list per demand. Summarization sorts prefixes. Custom larger limits are a deliberate caller responsibility.

CLI reads at most 1 MiB plus one sentinel byte before UTF-8 decoding. An escape-aware scan limits JSON nesting before decoding. Duplicate keys, floats/non-finite constants and oversized integer tokens are rejected so ambiguous specifications do not silently change meaning. Shape validation and I/O/encoding errors become structured diagnostics. Label length is checked before trimming, and non-printable characters are rejected to reduce terminal/log injection risks. This is not an HTML escaping API; applications embedding labels in other contexts must escape them appropriately.

Limits bound memory/work, not elapsed time on a blocking input stream. The CLI is not a sandbox for arbitrary Python objects passed to the library. Deployment wrappers handling untrusted callers should retain default limits and impose process-level deadlines.

### Regression strategy

Existing tests retain nested/duplicate overlap checks, strict suggestions, scope straddles including both `/0`s, profile boundaries, sibling/non-sibling aggregation, VLSM reservations and exhaustion. Additional tests include a hand-calculated 1024-address partition, 40 fixed tiny-space allocation cases checked by a separate occupied-address oracle, all 256 subsets of eight IPv4 hosts for exact minimal summaries, and large IPv6 counts without enumeration. Tiny address enumeration is confined to bounded test oracles, never application code. CLI tests cover malformed schemas/JSON, invalid encoding, duplicate keys, depth/byte caps, read errors, exit status, and independent subprocess demo determinism. These tests specify behavior; this document does not assert a particular test-run outcome.

### References and non-goals

Primary references: [Python 3.13 ipaddress](https://docs.python.org/3.13/library/ipaddress.html), [RFC 3021](https://www.rfc-editor.org/rfc/rfc3021), [RFC 4632](https://www.rfc-editor.org/rfc/rfc4632), [RFC 4291](https://www.rfc-editor.org/rfc/rfc4291). Individual scope-table RFC bases are listed in the contract.

Only the documented address-math subset is implemented. There is no cloud reservation model, live routing validation, registrability check, scanner, address assignment service, or claim of broad standards compliance. Route aggregation here says nothing about whether an operator may advertise a route.

## Português

A versão de desenvolvimento 0.1.0 separa parsing, escopos explícitos, perfis, auditoria, sumarização, VLSM, limites/erros e CLI. A biblioteca não lê arquivos nem usa rede; a CLI lê apenas a entrada escolhida. Não há persistência, telemetria, modelos ou APIs.

CIDRs canônicos são intervalos inteiros alinhados de tamanho potência de dois. Interseções são igualdade ou contenção. A auditoria compara todos os pares com índices originais; com 2000 entradas há no máximo 1999000 comparações, e no máximo 10000 colisões reportadas. A tabela de escopos usa interseções e comprimentos cobertos para detectar fallback e classes mistas, sem inferir alcance por exclusão.

VLSM subtrai reservas por divisões binárias, mantendo irmãos não utilizados como blocos livres máximos. Depois ordena demandas pelo maior bloco e nome e usa o primeiro bloco livre adequado em ordem de endereço. Cada divisão exige no máximo 32 ou 128 passos; não se enumeram hosts ou todas as sub-redes. A representação continua mínima, pois a subtração não cria irmãos livres que poderiam ser unidos sem que o pai já estivesse livre. Limites se aplicam também às etapas intermediárias. O algoritmo guloso não pesquisa posicionamentos alternativos. Falhas retornam partição provisória e a primeira demanda não atendida; não alteram as entradas do chamador.

A sumarização separa famílias, usa `collapse_addresses` e verifica cardinalidade por união de intervalos, sem incluir lacunas. Contabilidade interna não substitui os testes independentes de cobertura, alinhamento, disjunção e minimalidade.

A CLI lê no máximo 1 MiB mais um byte sentinela, verifica profundidade JSON respeitando escapes e rejeita ambiguidades como chaves duplicadas, floats e constantes não finitas. Rótulos têm comprimento limitado antes de aparar espaços e rejeitam caracteres não imprimíveis. Consumidores que inserem rótulos em HTML ou outros contextos devem fazer seu próprio escape. Arquivos nomeados usam descritor não bloqueante quando suportado e devem ser regulares. Stdin explícito e falhas de filesystem ainda podem exigir prazo imposto por um supervisor. A biblioteca não é um sandbox para objetos Python arbitrários.

A suíte mantém os testes existentes e acrescenta oráculos independentes de espaços IPv4 pequenos, o caso calculado manualmente de 1024 endereços, os 256 subconjuntos de oito hosts, grandes contagens IPv6 sem enumeração, entradas CLI adversariais e determinismo em subprocessos. Enumeração pequena ocorre apenas nos testes. Não se afirma aqui um resultado de execução de testes.

As referências primárias estão nos links acima. Implementa-se somente o subconjunto matemático documentado: sem regras de nuvem, validação de anúncios BGP, scanner ou prova de registrabilidade/alcance. Sumarizar endereços não concede autorização para anunciar uma rota.

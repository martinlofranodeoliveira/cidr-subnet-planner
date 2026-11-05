# cidr-subnet-planner

[English](README.md) · [Contrato](docs/contract.md) · [Design](docs/design.md)

Versão de desenvolvimento **0.1.0**, por [Lofrano Tecnologia](https://lofranotecnologia.com.br). Auditoria CIDR IPv4/IPv6, particionamento VLSM e sumarização mínima exata em Python 3.13. Aplicação e testes usam apenas a biblioteca padrão, sem modelos, APIs, telemetria ou acesso à rede. Os dados da demonstração são sintéticos.

## Execução e instalação

Na pasta do projeto, com Python 3.13 ou superior, não é necessário instalar:

```sh
python3 -m unittest discover -s tests -v
python3 -m cidr_planner demo
python3 -m cidr_planner demo --format text
```

Instalação opcional, com pip e setuptools >=68 já disponíveis:

```sh
python3 -m pip install --no-build-isolation --no-deps .
cidr-planner demo --format text
```

Setuptools é necessário apenas para empacotamento. Os comandos diretamente no código-fonte funcionam offline sem pip ou setuptools. A instalação exige um ambiente Python gravável, como um ambiente virtual existente.

## Funcionalidades e decisões

- Sinaliza bits de host com sugestão canônica, sem corrigir silenciosamente entradas estritas.
- Detecta todas as colisões exatas ou por contenção, com rótulos, direção, família e quantidade sobreposta.
- Classifica escopo por uma tabela explícita e limitada. `other_or_reserved` significa **não classificado pela tabela**, não prova de reserva ou alcance global. Prefixos que cruzam classes recebem `mixed`.
- Ordena demandas pelo maior bloco, depois pelo nome em ordem de pontos de código Unicode; aloca o menor endereço alinhado livre.
- Valida reservas e retorna a cobertura CIDR livre mínima e exata. Falhas identificam a primeira demanda não atendida e o maior bloco alinhado restante.
- Sumariza a união exata sem incluir endereços extras.

Intervalos inteiros e divisões binárias evitam enumerar hosts ou todas as sub-redes possíveis, inclusive em IPv6 `/0`. Limites explícitos restringem entrada CLI, inventários, colisões e blocos livres intermediários. Consulte o [contrato](docs/contract.md).

## Exemplos da biblioteca

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

`parse_cidr` estrito lança `NonCanonicalCIDRError` para `192.168.1.42/24`, indicando `192.168.1.0/24`. A auditoria estrita mantém o registro rejeitado no relatório e o exclui das colisões. A auditoria não estrita sinaliza os bits e também compara a rede canônica sugerida.

## CLI e saída reproduzível

```sh
printf '%s\n' '[{"label":"lab","cidr":"192.0.2.42/24"}]' | python3 -m cidr_planner audit --strict --input -
printf '%s\n' '{"parent_supernet":"10.0.0.0/24","demands":[{"name":"lab","required_hosts":50}]}' | python3 -m cidr_planner plan --input -
printf '%s\n' '["10.0.0.0/25","10.0.0.128/25"]' | python3 -m cidr_planner summarize --input -
```

`--input` também aceita um arquivo JSON local escolhido explicitamente. Relatórios usam stdout; erros de entrada são JSON em stderr. Códigos: `0` sucesso/auditoria limpa; `1` achados na auditoria ou falta de espaço; `2` entrada inválida, limite excedido ou erro de leitura. A demonstração retorna `0`, embora inclua colisões intencionais.

Trecho da saída textual da demonstração:

```text
[1] Inventory Audit
  Entries: 9 (IPv4: 7, IPv6: 2)
  Non-canonical inputs flagged: 1
```

São quatro colisões. A contabilidade e a sumarização são:

```text
  Accounting: reserved=128 + allocated=259 + free=125 = 512

[3] Contiguous Prefix Summarization
  Input prefixes: 7 -> Summarized: 4 (reduced by 3)
    - 10.80.0.0/23
    - 10.80.2.128/25
    - 10.80.3.0/25
    - 2001:db8:10::/48
```

## Perfis e limitações

`standard_ipv4`: desconta rede e broadcast em `/0` a `/30`; `/31` tem zero hosts utilizáveis; `/32` tem um. `rfc3021_p2p`: mesmas regras, exceto `/31` com dois hosts. `ipv6`: conta todos os endereços e retorna contagens, inclusive demandas de hosts reportadas, como strings decimais no JSON.

É matemática offline, não scanner, cliente DNS/WHOIS, banco IPAM, validador BGP ou prova de registrabilidade/alcance. A tabela de escopos é incompleta e não modela exceções aninhadas de registros. Não há alegação de conformidade ampla com RFCs. Provedores de nuvem podem reservar endereços adicionais, como os quatro primeiros e o último; regras específicas de fornecedores não são implementadas. O algoritmo guloso determinístico não é um otimizador geral de posicionamento. Alocações presentes em um plano com falha são provisórias.

MIT © 2026 Lofrano Tecnologia. Contato geral: [site oficial](https://lofranotecnologia.com.br). Segurança: [relato privado de vulnerabilidades](https://github.com/martinlofranodeoliveira/cidr-subnet-planner/security/advisories/new).

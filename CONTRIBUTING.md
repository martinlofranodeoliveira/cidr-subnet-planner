# Contributing / Como contribuir

## English

Development version 0.1.0 welcomes focused issues and pull requests at [the repository](https://github.com/martinlofranodeoliveira/cidr-subnet-planner). For security concerns use the private channel in [SECURITY.md](SECURITY.md), not a public issue. General contact is the [official homepage](https://lofranotecnologia.com.br).

Use Python 3.13 or newer. From the project directory:

```sh
python3 -m unittest discover -s tests -v
python3 -m cidr_planner demo
python3 -m cidr_planner demo --format text
```

No external test packages are needed. For optional installation see README.md. Keep runtime dependencies at zero unless a narrowly justified change is discussed. CI runs tests and demos; it does not publish or deploy.

For a bug, provide a minimal synthetic input, Python version, expected result, actual result and exit status. Do not submit real inventories, credentials, personal data or private client code. Contributions must be original or have clearly compatible provenance; this repository is MIT licensed.

Preserve documented output types and ordering. Add regression tests that establish expected behavior independently, especially for host-bit rejection, family boundaries, scope straddles, reservations, alignment, fragmentation, conservation and minimal free/summarized covers. Avoid tests that merely compare a function against itself. Large IPv6 tests must not enumerate addresses. Update both READMEs and bilingual contract/design/changelog sections for public behavior changes. Use LF, UTF-8 and the supplied EditorConfig. Do not add release, publication, telemetry or remote-deployment workflows.

## Português

A versão de desenvolvimento 0.1.0 aceita issues e pull requests focados no [repositório](https://github.com/martinlofranodeoliveira/cidr-subnet-planner). Vulnerabilidades devem usar o canal privado de [SECURITY.md](SECURITY.md), não uma issue pública. Contato geral: [site oficial](https://lofranotecnologia.com.br).

Use Python 3.13 ou superior e os três comandos acima na pasta do projeto. Testes não exigem pacotes externos; a instalação opcional está no README.pt-BR.md. Mantenha zero dependências de execução salvo justificativa específica discutida. A CI testa e demonstra, sem publicar ou implantar.

Relatos devem incluir entrada sintética mínima, versão Python, resultado esperado, resultado observado e código de saída. Não envie inventários reais, credenciais, dados pessoais ou código privado de clientes. Contribuições devem ser originais ou ter proveniência compatível explícita; a licença é MIT.

Preserve tipos e ordenação do contrato. Acrescente testes independentes para bits de host, famílias, escopos mistos, reservas, alinhamento, fragmentação, conservação e coberturas mínimas. Não compare apenas a função consigo mesma. Não enumere espaços IPv6 grandes. Atualize os dois READMEs e as seções bilíngues de contrato, design e histórico quando mudar comportamento público. Use UTF-8, LF e EditorConfig. Não adicione workflows de publicação, release, telemetria ou implantação remota.

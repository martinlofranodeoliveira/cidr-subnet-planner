# Security / Segurança

## English

This is development version 0.1.0. It performs offline address math, not network validation or authorization. It reads a selected JSON file or stdin; it does not fetch URLs, scan networks, execute input, write inventories, or send telemetry. It is not presented as production-ready.

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/martinlofranodeoliveira/cidr-subnet-planner/security/advisories/new). Do not disclose exploitable details in public issues. Include the affected version, Python version, minimal synthetic reproduction, expected/observed behavior and likely impact. Never include real personal data, network inventories, credentials or secrets. No response-time SLA is promised. General contact uses the [official homepage](https://lofranotecnologia.com.br).

The current development line is the review target; no maintenance schedule for other versions is promised. Scope tables are selected snapshots, not a source of security policy, global reachability or ownership assertions. Cloud host reservations and routing policy are outside the contract.

Keep default resource limits for untrusted inputs. The CLI bounds input bytes, nesting, number tokens and collections; the library bounds computational collections and outputs. These are not wall-clock deadlines, and explicit stdin and filesystem faults require external supervision where appropriate. Named inputs must be regular files; nonblocking opening where supported rejects FIFOs/devices before reading. Output failures return 2 and may leave partial output. The library expects ordinary data, not hostile Python classes. Printable labels are not HTML sanitization. Treat failed allocation plans as incomplete, and do not apply provisional allocations automatically.

## Português

Esta é a versão de desenvolvimento 0.1.0. A ferramenta faz matemática offline, não validação de rede ou autorização. Lê JSON de arquivo escolhido ou stdin; não busca URLs, varre redes, executa entradas, grava inventários ou envia telemetria. Não é apresentada como pronta para produção.

Relate suspeitas pelo [canal privado de vulnerabilidades do GitHub](https://github.com/martinlofranodeoliveira/cidr-subnet-planner/security/advisories/new). Não exponha detalhes exploráveis em issues públicas. Inclua versão afetada, versão Python, reprodução sintética mínima, comportamento esperado/observado e impacto provável. Nunca inclua dados pessoais reais, inventários reais, credenciais ou segredos. Não há SLA de prazo de resposta. Contato geral: [site oficial](https://lofranotecnologia.com.br).

A linha atual de desenvolvimento é o alvo de análise; não se promete calendário de manutenção para outras versões. Tabelas de escopo são seleções limitadas, não políticas de segurança nem prova de alcance global ou propriedade. Reservas de nuvem e política de roteamento estão fora do contrato.

Mantenha limites padrão para entradas não confiáveis. Limites de bytes, profundidade, tokens numéricos, coleções e saídas não são prazos de execução; stdin explícito e falhas de filesystem podem exigir supervisão externa. Entradas nomeadas devem ser arquivos regulares, com abertura não bloqueante onde suportada para rejeitar FIFOs/dispositivos antes da leitura. Falhas de saída retornam 2 e podem deixar saída parcial. A biblioteca espera dados comuns, não classes Python hostis. Rótulos imprimíveis não equivalem a sanitização HTML. Planos com falha são incompletos; não aplique automaticamente suas alocações provisórias.

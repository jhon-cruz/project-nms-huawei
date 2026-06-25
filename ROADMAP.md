# Huawei NMS Web UI - Roadmap Vivo

Este documento registra a visao do projeto, decisoes tecnicas, pendencias e o que ja foi feito. A ideia e manter este arquivo atualizado a cada etapa para sabermos exatamente em que ponto estamos.

## Visao do Produto

Criar uma interface web externa para roteadores, switches e BRAS/BNG Huawei que nao possuem uma interface web nativa. O sistema deve oferecer uma visao global do equipamento e permitir operacao assistida por uma interface visual, reduzindo a dependencia de linha de comando para tarefas comuns.

O backend fara:

- Leitura e monitoramento preferencialmente via SNMP.
- Configuracoes e comandos sob demanda via SSH.
- Cadastro seguro dos equipamentos e credenciais.
- Auditoria de acoes feitas por operadores.
- Mapeamento visual de portas por modelo de equipamento.

## Principios De Seguranca

- Comecar com um MVP somente leitura antes de liberar configuracoes.
- Usar SNMP para polling frequente e SSH apenas sob demanda.
- Nunca armazenar senha ou community em texto puro.
- Nunca retornar credenciais pela API.
- Separar credenciais de leitura e credenciais de configuracao quando possivel.
- Registrar auditoria de comandos aplicados.
- Exigir confirmacao para acoes destrutivas, como shutdown, reboot, apagar configuracao ou salvar alteracoes globais.
- Preferir SNMPv3 quando o equipamento permitir.
- Em producao, manter a chave de criptografia fora do banco e fora do codigo.

## Dados Necessarios Dos Equipamentos

Para evoluir sem risco em equipamentos de producao, precisamos primeiro coletar amostras somente leitura:

- `display version`
- `display interface brief`
- `display interface`
- `display device`
- `display alarm`
- `display logbuffer`
- `display current-configuration interface <interface>`
- `snmpwalk` de OIDs padrao: `SNMPv2-MIB`, `IF-MIB`, `IF-MIB::ifXTable`
- `snmpwalk` de MIBs Huawei para CPU, memoria, temperatura, fontes, fans, transceivers e inventario.

## Coleta Sem Peso No Equipamento

Leituras frequentes devem usar SNMP:

- Interfaces: 30s a 60s.
- CPU, memoria e temperatura: 60s a 120s.
- Inventario, modelo e versao: 6h a 24h.
- Configuracao completa: apenas manualmente ou em snapshots agendados.

Evitar:

- `display current-configuration` em loop.
- Comandos SSH pesados em muitos equipamentos simultaneamente.
- Coleta de logs muito grandes.
- Polling agressivo em dispositivos de producao.

## Documentacoes Necessarias

- Huawei VRP Command Reference por versao/familia.
- Huawei MIB Reference.
- Manuais dos modelos fisicos para layout frontal e portas.
- Guias de SNMPv2c/SNMPv3 em VRP.
- Guias de AAA e usuarios locais.
- Diferencas entre VRP V5/V200 e VRP V8/V800.

## Documentos Operacionais Recebidos

- [x] `/Volumes/HD6TB-MW/Disco_GTEC/Docs HUAWEI/Comandos Troubleshoting BRAS-NE.txt`
- [x] `/Volumes/HD6TB-MW/Disco_GTEC/Docs HUAWEI/comandos_uteis.txt`

Comandos mapeados para funcionalidades BRAS/BNG:

- Consultas seguras: total de usuarios online, usuarios IPv4/IPv6/dual-stack, consulta por username, IP, MAC, dominio, VLAN, QoS profile, pools, Radius, PPPoE, AAA, ARP e clock.
- Consultas parametrizadas: `display access-user username <usuario> verbose`, `display access-user ip-address <ip>`, `display access-user mac-address <mac>`, `display access-user domain <dominio>`, `display pppoe statistics interface <interface>`.
- Acoes sensiveis: derrubar usuario PPPoE, resetar estatisticas PPPoE, resetar ARP e mover prioridade de pool. Essas acoes devem exigir permissao Admin, preview, confirmacao explicita e auditoria.

## Modelos Iniciais

- S6730-H48X6C
- NetEngine 8000 F1A-8H20Q
- NE40E-M2H

## Funcionalidades Planejadas

- [x] Registrar roadmap vivo do projeto.
- [x] Manter POC FastAPI existente funcionando.
- [x] Login de usuarios do sistema.
- [ ] Perfis de acesso: admin, operador e somente leitura.
- [x] Perfis de acesso iniciais: Admin e Leitura.
- [x] Banco de dados para cadastro de equipamentos.
- [x] Criptografia reversivel para credenciais dos equipamentos.
- [x] Cadastro com IP/dominio, usuario, senha, porta SSH, community SNMP, porta SNMP, descricao e tipo.
- [x] Teste de conexao SSH somente leitura.
- [ ] Teste de conexao SNMP somente leitura.
- [ ] Descoberta automatica de modelo por `display version` e SNMP.
- [ ] Dashboard geral.
- [ ] Tela do equipamento.
- [ ] Lista de interfaces com status, speed, descricao, trafego, erros e descartes.
- [ ] Layout visual de portas por modelo.
- [ ] Hover na porta com descricao, velocidade e estado.
- [ ] Clique na porta abrindo detalhes/configuracao.
- [ ] Terminal web auditado.
- [x] Acoes assistidas: ativar porta, desativar porta e alterar descricao.
- [x] Tela BRAS/BNG com diagnostico de assinantes PPPoE.
- [x] Tela BRAS/BNG com saude de Radius, pools, QoS e estatisticas PPPoE.
- [ ] Historico de metricas.
- [ ] Backup e comparacao de configuracao.
- [ ] Alertas por e-mail, Telegram ou webhook.
- [ ] Integracao com IA local para diagnostico assistido.

## IA Local/Gratuita

A IA pode ser integrada como assistente de diagnostico e documentacao operacional, preferencialmente local:

- Ollama com modelos Llama, Qwen ou Mistral.
- Explicacao de comandos.
- Analise de logs e counters.
- Sugestao de plano de acao.
- Geracao de comandos em modo preview.

Regra importante: a IA nao deve executar comandos diretamente. O operador precisa revisar e confirmar qualquer comando que altere o equipamento.

## Plano De Acao

### Fase 1 - Fundacao Do Sistema

- [x] Criar anotacao/roadmap.
- [x] Criar persistencia local de desenvolvimento.
- [x] Criar API de cadastro de equipamentos.
- [x] Criar UI moderna com dashboard e cadastro.
- [x] Manter endpoint de amostra para demonstracao sem equipamento real.

### Fase 2 - Operacao Somente Leitura

- [x] Criar camada SNMP.
- [ ] Criar descoberta de equipamento.
- [x] Criar inventario de interfaces.
- [ ] Criar layout visual inicial para um modelo piloto.
- [ ] Criar metricas historicas basicas.

### Fase 3 - Configuracao Assistida

- [ ] Criar templates de comandos por tipo/modelo.
- [x] Criar preview de comandos.
- [x] Criar auditoria.
- [ ] Criar terminal web controlado.
- [ ] Liberar acoes simples e seguras por permissao.
- [x] Liberar execucao real de comandos via SSH com confirmacao e auditoria.
- [x] Criar catalogo de comandos BRAS/BNG com parametros validados.
- [x] Criar consultas assistidas de assinante por login, IP, MAC, dominio, VLAN e QoS profile.
- [x] Criar acoes assistidas para desconectar assinante com confirmacao forte.

### Fase 4 - Producao

- [ ] Autenticacao forte.
- [ ] HTTPS/reverse proxy.
- [ ] Rotacao e protecao de secrets.
- [ ] Jobs em background.
- [ ] Observabilidade do proprio sistema.
- [ ] Backup do banco e configuracoes.

## Status Atual

- Projeto original identificado como POC FastAPI + UI estatica.
- Testes existentes passam.
- Servidor local roda em `http://localhost:8000`.
- Banco de testes formalizado em SQLite: `data/nms.db`.
- Persistencia local criada em SQLite para desenvolvimento.
- Credenciais de equipamentos criptografadas e mascaradas nas respostas da API.
- API inicial de equipamentos criada: listar, criar, editar e remover.
- Interface moderna inicial criada com tema escuro em azul, preto, branco e dourado.
- Cadastro ja possui descricao e tipo do equipamento: roteador, switch, BRAS/BNG, OLT, firewall ou outro.
- Tela possui dashboard inicial, representacao visual de portas, inventario e carregamento de amostra segura.
- Login e primeiro acesso criados com senha em hash PBKDF2.
- Usuario padrao de desenvolvimento criado automaticamente quando o banco esta vazio: `admin` / `admin@nms`.
- Sessoes criadas com cookie `HttpOnly`.
- Rotas de cadastro e endpoints SSH protegidos por autenticacao.
- Fail-ban por IP criado: 5 falhas bloqueiam o IP temporariamente por 15 minutos.
- Limites de tamanho adicionados aos campos sensiveis no frontend e backend.
- Preview de comandos criado para ver interface, ativar porta, desativar porta e alterar descricao.
- Previews sao registrados em tabela de auditoria, ainda sem execucao real em equipamentos.
- Tela de auditoria de previews adicionada.
- Interface reorganizada em paginas separadas: Visao geral, Equipamentos, Configuracao, Auditoria e Seguranca.
- Cadastro de equipamentos movido para pagina propria no menu lateral.
- Configuracao assistida movida para dentro da pagina Equipamentos.
- Menu lateral Configuracao removido.
- Atualizacao SNMP automatica configuravel por segundos/minutos adicionada.
- Controle de atualizacao SNMP compactado na barra de Equipamentos, com minimo de 1 segundo.
- Pagina Equipamentos ajustada para proporcao 50/50 entre equipamento e porta selecionada.
- Execucao SSH de comandos de configuracao otimizada para reconhecer prompts VRP em modo system-view.
- Leitura SNMP e atualizada imediatamente apos aplicar configuracao em porta.
- Informacoes internas removidas da pagina principal.
- Auditoria movida para pagina propria com filtro por equipamento e periodo.
- Auditoria passou a registrar IP de origem e usuario.
- Pagina de seguranca adicionada com criacao, edicao de senha/permissao e remocao de usuarios.
- Usuarios Leitura nao acessam Auditoria/Seguranca nem acoes de cadastro/configuracao.
- Teste SSH por equipamento adicionado.
- Execucao real de comandos do preview adicionada para laboratorio EVE-NG.
- Documentacao do banco local criada em `DATABASE.md`.
- Coleta real de interfaces via SNMP adicionada usando `ifName`, `ifAlias`, `ifAdminStatus`, `ifOperStatus`, velocidade e contadores.
- Faceplate passou a usar interfaces reais do equipamento ativo em vez de portas genericas.
- Clique em porta real busca `display current interface <interface>` via SSH.
- Ordem dos comandos VRP V8 corrigida para executar `commit` antes de sair da interface.
- Servidor local validado em `http://localhost:8000`.
- Documentos operacionais BRAS/NE recebidos e mapeados para consultas seguras e acoes sensiveis.
- Modulo BRAS/BNG adicionado dentro da pagina Equipamentos com consultas de assinantes, Radius, pools, QoS, PPPoE, ARP e clock.
- Acoes BRAS/BNG sensiveis adicionadas para Admin com preview, confirmacao e auditoria.
- Visualizacao de falhas AAA adicionada com atualizacao manual ou polling leve e simplificacao inicial dos motivos de falha.

## Proximas Acoes Imediatas

- [x] Criar fluxo de primeiro acesso/login do sistema.
- [x] Criar tabela de usuarios, sessoes e permissoes iniciais.
- [x] Proteger rotas de cadastro atras de autenticacao.
- [ ] Adicionar SNMP real em modo somente leitura.
- [x] Adicionar templates de comandos por tipo de equipamento.
- [ ] Criar tela de detalhes do equipamento.
- [ ] Criar layout fisico real para o primeiro modelo piloto.
- [x] Criar catalogo inicial de layouts fisicos por modelo.
- [x] Criar modulo BRAS/BNG: consulta de assinantes, Radius, pools, QoS e PPPoE.
- [ ] Ajustar parsers BRAS/BNG com saidas reais do laboratorio EVE-NG.

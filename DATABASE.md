# Banco De Dados De Testes

O projeto esta configurado para usar SQLite no ambiente de desenvolvimento.

## Arquivo

- Banco: `data/nms.db`
- Chave local de criptografia: `data/.nms_secret.key`

## Por Que SQLite Agora

- Ja esta disponivel no macOS.
- Nao exige servico externo para os testes com EVE-NG.
- Permite salvar usuarios, sessoes, equipamentos, credenciais criptografadas e auditoria.
- Facilita mover rapido enquanto validamos os fluxos com VRP em laboratorio.

## Tabelas Principais

- `users`
- `sessions`
- `login_attempts`
- `devices`
- `command_audit_logs`

## Producao

Quando o sistema sair do laboratorio, o caminho recomendado e migrar para PostgreSQL, mantendo:

- Criptografia das credenciais dos equipamentos.
- Segredo `NMS_SECRET_KEY` fora do codigo.
- Backup automatico.
- Usuario de banco com menor privilegio possivel.

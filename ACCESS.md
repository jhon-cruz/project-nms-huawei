# Acesso De Desenvolvimento

Este arquivo registra credenciais iniciais apenas para o ambiente de desenvolvimento local.

## Usuario Padrao

- Usuario: `admin`
- Senha: `admin@nms`

O sistema cria esse usuario automaticamente quando o banco local esta vazio.

## Observacoes

- Trocar essa senha antes de usar o sistema em qualquer ambiente compartilhado.
- Em producao, criar fluxo de troca obrigatoria no primeiro login.
- Manter `NMS_SECRET_KEY` configurada fora do codigo para proteger credenciais de equipamentos.

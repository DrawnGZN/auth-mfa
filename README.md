# Central de Autenticação Segura com MFA

API de autenticação em Python (FastAPI) com senhas em Argon2id, JWT de vida curta,
refresh token com rotação e 2FA via TOTP (Google Authenticator).

## Como rodar
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
# Windows (PowerShell): $env:JWT_SECRET="uma-chave-com-32-ou-mais-caracteres-aqui"
uvicorn main:app --reload
```
Documentação interativa: http://127.0.0.1:8000/docs

## Fluxo
1. `POST /register` – cria o usuário (senha mínima de 10 caracteres).
2. `POST /login` – devolve `access_token` (5 min) e `refresh_token` (7 dias).
3. `POST /mfa/setup` (Bearer) – devolve o segredo e a URI `otpauth://` para o app autenticador.
4. `POST /mfa/enable` (Bearer) – confirma com o código de 6 dígitos e ativa o MFA.
5. A partir daí, `POST /login` exige o campo `totp_code`.
6. `POST /refresh` – troca o refresh token por um novo par (o antigo é revogado).
7. `POST /logout` – revoga o refresh token.

## Arquitetura de segurança
| Requisito | Decisão |
|---|---|
| Senhas | Argon2id (`argon2-cffi`), com salt automático |
| Access token | JWT HS256, expira em 5 minutos, claim `type=access` validada |
| Refresh token | Valor aleatório de 48 bytes, guardado só como SHA-256, uso único (rotação) |
| MFA | TOTP (RFC 6238), janela de ±1 passo |
| Força bruta | Bloqueio de 5 min após 5 falhas; erro genérico para não revelar se o e-mail existe |
| Segredos | `JWT_SECRET` via variável de ambiente, nunca no código |

## Limitações conhecidas
Sem rate limit por IP, sem verificação de e-mail e sem HTTPS embutido (em produção, usar proxy reverso com TLS).

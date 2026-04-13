# 🔐 SecureAuth MFA — Sistema de Autenticação Multi-Fator

Sistema completo de autenticação com MFA (TOTP / RFC 6238) construído com Flask + SQLite.

---

## Stack

| Camada     | Tecnologia                                   |
|------------|----------------------------------------------|
| Backend    | Python 3 + Flask                             |
| Banco      | SQLite (via `sqlite3` nativo)                |
| Auth       | Werkzeug (hash de senha) + TOTP manual       |
| QR Code    | `qrcode` + `Pillow`                          |
| Frontend   | HTML5 + CSS3 + JavaScript puro               |

---

## Instalação

```bash
# 1. Crie e ative um ambiente virtual
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows

# 2. Instale dependências
pip install -r requirements.txt

# 3. Inicie o servidor
python app.py
# Acesse: http://127.0.0.1:5000
```

---

## Fluxo de Autenticação

```
[Cadastro] ──▶ [Login: usuário+senha] ──▶ [MFA ativo?]
                                               │ Não ──▶ [Dashboard]
                                               │ Sim ──▶ [Tela TOTP]
                                                           │ Código OK ──▶ [Dashboard]
                                                           │ Backup OK ──▶ [Dashboard]
```

---

## Funcionalidades

### Segurança
- ✅ Hash de senha com **bcrypt** (via Werkzeug)
- ✅ **TOTP RFC 6238** implementado do zero (sem pyotp)
- ✅ QR Code para apps autenticadores (Google Authenticator, Authy, etc.)
- ✅ **Códigos de backup** para recuperação de acesso (8 × 8 chars)
- ✅ **Rate limiting**: bloqueia após 5 tentativas falhas em 10 min
- ✅ Log de tentativas de login (IP + timestamp + sucesso/falha)
- ✅ Cookies HttpOnly + sessão com expiração (30 min)
- ✅ HMAC compare_digest (proteção contra timing attack)

### Interface
- ✅ Login em 2 etapas (senha → código TOTP)
- ✅ Auto-submit ao digitar 6 dígitos
- ✅ Temporizador circular animado (countdown 30s)
- ✅ Alternância para código de backup
- ✅ Indicador de força de senha
- ✅ Dashboard com histórico de acessos

---

## Banco de Dados

```sql
users            -- id, username, email, password, mfa_secret, mfa_enabled, backup_codes
login_attempts   -- user_id, ip_address, success, timestamp
sessions         -- user_id, token, expires_at
```

---

## Apps compatíveis para TOTP

- **Google Authenticator** (iOS / Android)
- **Authy** (multiplataforma)
- **Microsoft Authenticator**
- **Bitwarden** (autenticador integrado)

---

## Estrutura de Arquivos

```
mfa_app/
├── app.py                  ← Servidor Flask principal
├── requirements.txt
├── mfa_app.db              ← Criado automaticamente
└── templates/
    ├── base.html           ← Layout base + estilos
    ├── login.html          ← Etapa 1: usuário + senha
    ├── register.html       ← Cadastro
    ├── mfa_verify.html     ← Etapa 2: código TOTP
    ├── mfa_setup.html      ← Configuração do MFA
    └── dashboard.html      ← Painel do usuário
```

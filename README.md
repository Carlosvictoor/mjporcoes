# MJ Porcoes - Sistema de Delivery

Aplicacao web de delivery feita com Flask + SQLite.

## Recursos principais

- Cardapio por categorias
- Carrinho e checkout rapido (com ou sem cadastro)
- Checkout com:
  - Nome
  - Telefone
  - Endereco
  - Bairro (selecionado da lista do admin)
  - Forma de pagamento
  - Troco para pagamento em dinheiro
- Painel admin com:
  - Gestao de produtos e categorias
  - Status da loja (aberta/fechada)
  - Gestao de bairros e taxas de entrega
  - Gestao de pedidos
  - Financeiro por ciclo e historico de fechamento

## Stack

- Python 3.11+
- Flask
- SQLite
- Bcrypt

## Como rodar localmente

1. Criar e ativar ambiente virtual

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Instalar dependencias

```powershell
pip install -r requirements.txt
```

3. (Opcional) Configurar variaveis de ambiente

Use o arquivo `.env.example` como base.

Variaveis importantes:

- `SECRET_KEY`
- `ADMIN_NAME`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `SESSION_COOKIE_SECURE`
- `FORCE_HTTPS`

4. Executar aplicacao

```powershell
python app.py
```

Acesse:

- Home: `http://127.0.0.1:5000/`
- Admin: `http://127.0.0.1:5000/login`

## Login admin padrao

- Email: `marceloirmao@hotmail.com`
- Senha: `199612`

Recomendacao: alterar em producao via variaveis de ambiente.

## Publicacao e seguranca

Ja inclui no projeto:

- CSRF por formulario (acao especifica, expiracao e rotacao)
- Rate limit persistente no SQLite (login e checkout)
- Cookies de sessao com `HttpOnly` e `SameSite=Lax`
- Modo para forcar HTTPS (`FORCE_HTTPS=1`)

Para producao, configure:

- `SESSION_COOKIE_SECURE=1`
- `FORCE_HTTPS=1`
- `SECRET_KEY` forte e unica

## Estrutura principal

- `app.py`: rotas e regras de negocio
- `database.py`: schema e inicializacao do banco
- `templates/`: paginas HTML
- `static/css/style.css`: estilos responsivos

## Licenca

Uso privado/projeto pessoal (defina a licenca desejada no repositorio).

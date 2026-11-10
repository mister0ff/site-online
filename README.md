# Loja Beleza Essencial

E-book interativo (46 páginas) vendido por R$ 7 via Mercado Pago, com liberação **só depois de o servidor confirmar o pagamento na API do Mercado Pago**.

## Rodar
```bash
cp .env.example .env     # preencha (veja abaixo) e exporte as variáveis, ou use o painel do seu host
node test.js             # 41 testes (usa um "Mercado Pago falso", não gasta nada)
node server.js
```
Sem dependências (Node 20+). Hospede em Render, Railway, Fly, VPS etc. (precisa de Node rodando — não funciona em GitHub Pages).

## Configuração do Mercado Pago (obrigatório)
1. Painel Mercado Pago → **Suas integrações** → crie uma aplicação → copie o **Access Token de produção** → `MP_ACCESS_TOKEN`.
2. Na mesma aplicação → **Webhooks** → URL `https://SUALOJA/api/webhook/mp`, evento **Pagamentos** → copie a **chave secreta** → `MP_WEBHOOK_SECRET`.
3. `BASE_URL` = endereço público https da loja. `SESSION_SECRET` = string aleatória de 48+ caracteres.

### Por que não usei o link https://mpago.la/24RGypM
Um link de pagamento fixo **não dá para verificar automaticamente**: quem paga não volta com prova, e qualquer pessoa pode digitar o endereço de retorno. Por isso o servidor cria um checkout de R$ 7 por pedido (via API, com seu token) e depois consulta o pagamento no Mercado Pago (aprovado + valor + BRL + pedido certo). Se quiser, o link fixo pode ficar só como plano B manual, mas ele não libera nada sozinho.

## O que protege seu dinheiro e seus limites
| Risco | Proteção |
|---|---|
| Chaves vazadas | Só em variáveis de ambiente; front-end nunca as recebe; `.gitignore` bloqueia `.env`. Se vazou: revogue no painel do MP e gere outra |
| Burlar pagamento | Liberação só via consulta server-side ao MP; cookie assinado (HMAC); sem "modo teste" que libere |
| Webhook falso | Assinatura `x-signature` validada |
| Bots / cadastro falso | Honeypot, tempo mínimo de preenchimento, Cloudflare Turnstile opcional, limite por e-mail |
| Teste de cartões no checkout | Quem processa o cartão é o MP; aqui há limite de 5 tentativas/10 min por IP, 3/h por e-mail |
| Abuso de requisições | Limite por IP (180/min), por rota, concorrência máx., corpo máx. 4 KB, timeouts |
| Cobrança duplicada | Mesmo e-mail reaproveita pedido pendente; `X-Idempotency-Key`; um `payment_id` só vale 1 pedido |
| Gasto descontrolado | Cotas diárias (pedidos e chamadas ao MP) reservadas **antes** da chamada; alerta em 80% nos logs; corta em 100% |
| Retries infinitos | Sem retry em 4xx; no máx. 1 em 5xx/rede |
| Emergência | `EMERGENCY_STOP=1` ou criar o arquivo `data/STOP` pausa tudo na hora |
| Compartilhamento | Máx. 5 acessos por compra; estorno/chargeback revoga |
| Dados | Pedidos não pagos apagados em 3 dias; uso mantido por 30 dias |

Esta loja **não usa nenhuma API de IA nem de terceiros pagas por token**, então não há risco de "conta de milhares de dólares" por aqui; o único serviço pago chamado é o Mercado Pago, e ele está limitado como acima.

## Imagens
As ilustrações são desenhos próprios gerados por código (sem direitos autorais). Para usar **fotos reais**, licenciadas (Unsplash, Pexels, banco pago), preencha `PHOTOS` no começo do script de `private/ebook.html`, ex.: `{ 4: 'https://.../foto.jpg' }` (número = página).

## Antes de vender
- Preencha `SELLER_NAME` e `SUPPORT_EMAIL` (aparecem nos Termos).
- Peça a um advogado para revisar os Termos/Privacidade.

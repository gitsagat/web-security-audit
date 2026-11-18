# Permissões, RLS e IDOR (OWASP A01:2025, API1/API3/API5:2023)

Controle de acesso quebrado é a categoria nº 1 e quase nunca aparece em scanner: exige entender quem é dono de quê. Gastar aqui a maior parte do tempo.

## Conceitos

- **IDOR / BOLA** (CWE-639): o objeto é buscado pelo ID do request sem checar se pertence ao usuário. `GET /api/pedidos/1043` → troca para `1044` → lê pedido alheio.
- **BOPLA / mass assignment** (API3, CWE-915): o usuário envia campos que não deveria (`is_admin`, `tenant_id`, `price`, `status`) e o serializer aceita; ou a resposta devolve campos que não deveria (hash de senha, token, CPF de terceiros).
- **BFLA** (API5): usuário comum chama função de admin (`POST /api/users/5/promote`) porque a rota só é escondida no front.
- **Multi-tenant**: vazamento entre organizações/filiais/clientes por filtro esquecido em uma única query.
- **RLS (Row Level Security)**: política no banco (PostgreSQL/Supabase) que filtra linhas por usuário — última linha de defesa, ou a única quando o front fala direto com o banco.

## Onde procurar

| Stack | Padrão perigoso |
| --- | --- |
| Django / DRF | `Model.objects.get(pk=pk)` / `get_object_or_404(Model, pk=pk)` sem filtro de dono; `queryset = Model.objects.all()` em ViewSet; `get_queryset` não sobrescrito; `permission_classes = [AllowAny]`; `fields = "__all__"` em serializer; `ModelAdmin` sem `get_queryset` por tenant; `has_object_permission` não chamado em `APIView` custom |
| Express/Nest | `findById(req.params.id)` sem `where: { ownerId }`; guard só em parte das rotas; `Object.assign(entity, req.body)` |
| Spring | `repository.findById(id)` sem checar dono; `@PreAuthorize` ausente; binding direto de entidade JPA |
| Rails | `Model.find(params[:id])` em vez de `current_user.models.find(...)`; `permit!` |
| Laravel | `Model::find($id)` sem Policy; `$fillable` amplo / `$guarded = []` |
| GraphQL | resolvers de campo/aninhados sem checagem (o pai checa, o filho não); introspecção aberta |
| Arquivos | URL de mídia previsível ou pública (S3 bucket público, `/media/` servido sem auth); presigned URL com validade longa |

Também: exportações CSV/PDF, relatórios, buscas e autocompletes, endpoints de contagem, webhooks de saída, tarefas assíncronas (Celery/Sidekiq) que recebem `id` e não revalidam, WebSockets/canais que assinam por nome previsível.

## Checklist

- [ ] Toda busca por ID parte de um queryset já restrito ao usuário/tenant (`request.user.tenant.pedidos.get(pk=...)`), não de `.objects`.
- [ ] Restrição de tenant centralizada (manager/mixin/política) em vez de repetida em cada view; testes que provam que cada rota usa.
- [ ] Negar por padrão: rota nova sem permissão declarada falha fechada.
- [ ] Serializers/forms com lista explícita de campos graváveis; `tenant_id`, `owner`, `role`, `is_staff`, preço e status nunca vêm do body.
- [ ] Respostas com lista explícita de campos de saída.
- [ ] Funções administrativas checadas no servidor, não escondidas no front.
- [ ] IDs não sequenciais (UUID) **reduzem** enumeração mas **não** substituem a checagem.
- [ ] Respostas iguais (404) para "não existe" e "não é seu" — evita enumeração.
- [ ] Mídia privada servida por view com checagem ou URL assinada de curta duração.

## RLS — PostgreSQL / Supabase

Quando o cliente (navegador/app) fala direto com o banco via chave pública (`anon key` do Supabase, PostgREST, Hasura), **RLS é o controle de acesso**. Tabela sem RLS = tabela pública.

- [ ] `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` em **toda** tabela do schema exposto (`public`). Tabelas criadas por SQL/migration/API **não** ganham RLS automaticamente — só as criadas pelo Table Editor do Supabase.
- [ ] Políticas separadas para `SELECT`, `INSERT`, `UPDATE`, `DELETE`; `UPDATE` com `USING` **e** `WITH CHECK` (senão o usuário move a linha para outro dono).
- [ ] Política não usa `true` nem `auth.role() = 'authenticated'` sozinho para dado por usuário — usar `auth.uid() = user_id` ou associação de tenant.
- [ ] Dados de autorização lidos de `auth.jwt() -> 'app_metadata'`, **nunca** de `user_metadata` (editável pelo próprio usuário).
- [ ] `FORCE ROW LEVEL SECURITY` quando o dono da tabela também consulta.
- [ ] Views criadas com `security_invoker = true` (senão a view ignora o RLS da tabela base); funções `SECURITY DEFINER` fora do schema exposto e com `search_path` fixo.
- [ ] `service_role` key nunca no front, no bundle JS ou no app mobile.
- [ ] Storage: buckets privados com políticas; nada de bucket público para documento de usuário.
- [ ] Rodar o Security Advisor do Supabase (`supabase db lint` / painel) e listar tabelas sem RLS:

```sql
select schemaname, tablename from pg_tables
where schemaname = 'public' and not rowsecurity;
```

Casos: **CVE-2025-48757** (apps gerados no Lovable com tabelas sem RLS: leitura e escrita anônima); **Moltbook, fev/2026** (Supabase vazando 35 mil e-mails e 1,5 milhão de tokens de API); **UpGuard, set/2026**: varredura de ~300 mil domínios com Supabase achou dado pessoal em mais da metade dos bancos expostos. Padrão comum: app feito com assistente de IA que cria tabelas por API, sem RLS, e embute a chave no front.

Mesmo em backend tradicional (Django/Rails com um usuário de banco só), RLS por `tenant_id` com `SET app.tenant_id` por request é uma segunda camada que transforma "esqueci o filtro" de vazamento em erro.

## Teste (alvo autorizado) — duas contas são obrigatórias

1. Criar conta A e conta B em tenants/donos diferentes; criar recurso com B; anotar IDs.
2. Logado como A, repetir cada requisição de B trocando só o ID (GET, PUT, PATCH, DELETE, exportação, download de anexo).
3. Logado como usuário comum, chamar cada rota de admin vista no front ou no código.
4. Enviar campos extras no body (`"role":"admin"`, `"tenant_id": <de B>`, `"is_staff": true`) e conferir se gravou.
5. Sem login, chamar cada rota de API e de mídia.
6. Supabase: com só a `anon key` extraída do bundle, `GET /rest/v1/<tabela>?select=*` em cada tabela.

Burp Suite com as extensões Autorize ou AuthMatrix automatiza os passos 2 e 3.

Caso de referência: **Optus (2022)** — API sem autenticação, IDs sequenciais, 10 milhões de clientes.

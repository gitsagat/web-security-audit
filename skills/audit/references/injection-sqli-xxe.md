# SQL Injection, XXE e outras injeções

## SQL Injection (CWE-89, OWASP A05:2025)

ORM não é imunidade: as falhas modernas aparecem em SQL cru, em nomes de coluna/ordenação vindos do usuário e em kwargs expandidos (`**request.GET`) que chegam a APIs internas do ORM.

### Onde procurar

| Stack | Padrão perigoso |
| --- | --- |
| Django | `.raw(`, `.extra(`, `RawSQL(`, `cursor.execute(f"...")` ou com `%` / `.format`, `order_by(request.GET[...])`, `filter(**request.GET.dict())`, `annotate(**dados_do_usuario)`, `values(*campos_do_usuario)`, `Q(**...)` com chaves do usuário |
| SQLAlchemy | `text(f"...")`, `session.execute(f"...")`, `order_by(text(param))`, `literal_column(param)` |
| Node | template string em `db.query(`, `knex.raw(`, `sequelize.query(` sem `replacements`, `prisma.$queryRawUnsafe(`, `$executeRawUnsafe(` |
| Java | `Statement.execute(` com concatenação, `@Query(nativeQuery=true)` com `+`, JPQL concatenado, `ORDER BY ${}` no MyBatis (usar `#{}`) |
| PHP | `mysqli_query($c, "... $var")`, `DB::raw(`, `whereRaw(` com interpolação |
| Rails | `where("name = '#{params[:n]}'")`, `order(params[:sort])`, `find_by_sql` |

Identificadores (nome de tabela, coluna, direção de ordenação) **não** são parametrizáveis: validar contra lista de permitidos (`{"nome", "-nome", "criado_em"}`).

### Checklist

- [ ] Toda consulta com valor externo usa parâmetro ligado (`%s` + tupla, `?`, `:nome`, `$1`).
- [ ] Ordenação, colunas e filtros dinâmicos passam por allowlist.
- [ ] Nenhum `**kwargs` vindo de request chega a `filter`, `exclude`, `annotate`, `alias`, `values`, `Q`.
- [ ] Usuário do banco da aplicação sem `SUPERUSER`, sem `CREATEROLE`, sem acesso a outros bancos; `COPY ... PROGRAM` indisponível.
- [ ] Erros de banco não voltam para o cliente (mensagem genérica + log).

### Teste (alvo autorizado)

```text
'                       → erro 500 ou mensagem do banco = indício
' OR '1'='1             → mais resultados que o esperado
1 AND SLEEP(2)          → MySQL, tempo
1; SELECT pg_sleep(2)-- → PostgreSQL, tempo
?ordering=(SELECT 1)    → injeção em ORDER BY
```

`sqlmap` só com autorização explícita, `--risk=1 --level=1`, contra homologação.

### Casos reais

- **Django CVE-2025-64459** (nov/2025, crítica): `_connector` e `_negated` passados por `**kwargs` a `filter()`/`Q()` permitiam SQLi. Corrigido em 5.2.8, 5.1.14, 4.2.26.
- **Django CVE-2025-57833** (set/2025): SQLi por alias de coluna em `FilteredRelation`.
- **Django CVE-2026-1207, CVE-2026-1287, CVE-2026-1312** (fev/2026, altas): SQLi em lookups raster do PostGIS, em alias de coluna com caracteres de controle via `annotate()`/`values()` com dicionário expandido, e em ordenação. Corrigidas em **6.0.2, 5.2.11, 4.2.28**.
- **PostgreSQL CVE-2025-1094**: escape incorreto em `libpq` com UTF-8 inválido → SQLi no `psql`; usada na cadeia do ataque à BeyondTrust/Tesouro dos EUA.

---

## XXE — XML External Entity (CWE-611)

Parser XML resolve entidade externa: leitura de arquivo local, SSRF, negação de serviço (billion laughs).

### Onde procurar

Tudo que lê XML ou formato baseado em XML: SAML, SOAP, RSS, SVG, DOCX/XLSX/PPTX, ODF, XMP em PDF/imagem, NF-e e integrações fiscais, webhooks XML de bancos e gateways.

| Stack | Seguro / inseguro |
| --- | --- |
| Python | usar `defusedxml`. `lxml.etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)`. **lxml < 6.1.0: CVE-2026-41066**, XXE na configuração padrão de entradas comuns. `xml.etree` da stdlib não resolve entidades externas, mas é vulnerável a expansão (DoS). |
| Java | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory` são **inseguros por padrão**: setar `disallow-doctype-decl=true`, `FEATURE_SECURE_PROCESSING`, `ACCESS_EXTERNAL_DTD=""`. |
| .NET | `XmlReaderSettings.DtdProcessing = Prohibit`. |
| PHP | libxml ≥ 2.9 desliga entidades externas por padrão; procurar `LIBXML_NOENT`, `LIBXML_DTDLOAD`. |
| Node | `libxmljs` com `noent: true`; `xml2js` não resolve entidades. |

### Checklist

- [ ] DTD desligado em todo parser que recebe XML externo.
- [ ] Bibliotecas de documento (Apache Tika, POI, docx, openpyxl) atualizadas — elas parseiam XML por baixo.
- [ ] Biblioteca SAML atualizada e validando assinatura sobre o documento canônico (ver [auth-2fa.md](auth-2fa.md)).

### Teste

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>
<r>&x;</r>
```

Se o hostname aparecer na resposta ou no erro, é XXE. Versão blind: `SYSTEM "http://coletor-proprio/x"`.

### Casos reais

- **Apache Tika CVE-2025-54988 e CVE-2025-66516** (2025, crítica): XXE via XFA dentro de PDF no módulo de PDF.
- **lxml CVE-2026-41066** (abr/2026): XXE com parser padrão; atualizar para ≥ 6.1.0.
- **http4s-scala-xml CVE-2026-61741** (2026, crítica): decodificador XML com padrão inseguro → leitura de arquivo e SSRF.
- **AssertJ CVE-2026-24400**: XXE em código de teste (pretty-printer XML) — lembrete de que dependência de teste também roda em CI com segredos.

---

## Outras injeções que entram no mesmo passe

| Tipo | Padrão perigoso | Defesa |
| --- | --- | --- |
| Comando (CWE-78) | `os.system`, `subprocess(..., shell=True)`, `child_process.exec(`, `Runtime.exec(String)`, crases no PHP | lista de argumentos sem shell; allowlist |
| SSTI | `render_template_string(user)`, `Template(user).render()`, `new Function` com template | nunca compilar template vindo do usuário; Jinja2 ≥ 3.1.6 (**CVE-2025-27516**, fuga do sandbox via `\|attr`) |
| Desserialização (CWE-502) | `pickle.loads`, `yaml.load` sem `SafeLoader`, `ObjectInputStream`, `unserialize(` do PHP, `node-serialize` | formato de dados (JSON) + schema |
| Path traversal (CWE-22) | `open(base + nome)`, `send_file(nome)`, `path.join(dir, req.params.f)` | `resolve()` + checar prefixo; nome gerado pelo servidor |
| NoSQL | `find(req.body)` no Mongo (`{"$ne": null}`) | validar tipos; `mongo-sanitize` |
| LDAP / XPath / header (CRLF) | concatenação em filtro LDAP; `\r\n` em header de resposta/e-mail | escape específico; rejeitar `\r\n` |
| Prompt injection (apps com LLM) | conteúdo externo concatenado no prompt com ferramentas que agem | separar dado de instrução; ferramentas com menor privilégio; confirmação humana em ação |

Casos: **React Server Components CVE-2025-55182 ("React2Shell")**, CVSS 10, desserialização insegura no protocolo Flight → RCE sem autenticação em Next.js App Router (dez/2025); **Livewire CVE-2025-54068** (RCE por hidratação de propriedades); **PHP CVE-2024-4577** (injeção de argumento no PHP-CGI no Windows, KEV).

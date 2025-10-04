<p align="center">
  <img src="assets/logo.png" alt="EPSSight Logo" width="320"/>
</p>

> Foco na priorização de vulnerabilidades baseada em EPSS (Exploit Prediction Scoring System), gerando um XLSX e um resumo (KPIs) direto no terminal.

## O que é
EPSSight lê um CSV (usado o padrão de export do Tenable) e gera uma planilha XLSX com filtros aplicáveis e visual moderno (faixas zebras, badges por severidade, barra de dados no EPSS). No terminal, imprime um resumo executivo (KPIs) e as Top 10 CVEs por ativos afetados com base exatamente no conjunto filtrado.

## Principais recursos
- Filtros via CLI:
  - `-e/--epss`: limiar mínimo (aceita `90` ou `0.90`).
  - `-s/--severity`: `critical,high,medium,low` (qualquer combinação).
  - `--lang pt|en`: rótulos PT/EN (padrão: EN).
  - `--no-theme`: modo compat (sem formatação pesada no Excel).
- Ordenação padrão: `Critical > High > Medium > Low` e, dentro de cada severidade, por EPSS desc.
- Excel estilizado (tema red-team):
  - Barra de dados na coluna EPSS SCORE (em `%`).
  - Badges de severidade (cores distintas para Critical/High/Medium/Low).
  - Zebra striping e borda sutil em todo o range.
  - `LAST SEEN` normalizado para `dd/MM/aaaa`.
- Abas do Excel:
  - `vulns_filtradas`
  - `por_severidade`
  - `top_cves_por_ativos`
  - `top_ativos_por_vulns`
- Resumo no terminal:
  - KPIs (itens, ativos únicos, contagem por severidade).
  - Top 10 CVEs por ativos afetados.
- Auto-timestamp para o arquivo de saída se você não passar `-o`: `report_YYYYMMDD_HHMM.xlsx`.
- Heurística KEV/Exploit (_opcional_): se houver colunas no CSV contendo `kev`, `cisa`, `known_exploit`, `metasploit`, `canvas`, `exploit`, `edb`, o relatório adiciona flags KEV / EXPLOIT (Yes/No).

## Instalação

Requisitos: Python 3.8+

```bash
# opcional: criar venv
python3 -m venv .venv && source .venv/bin/activate   # (Windows: .venv\Scripts\activate)

pip install -U pandas xlsxwriter numpy
```

## Entrada esperada (CSV)

Export de vulnerabilidades Tenable/Nessus contendo, idealmente, os campos:

```
asset.name
asset.display_ipv4_address
asset.operating_system
definition.cve
definition.epss.score        # 0..1 (a ferramenta aceita também 0..100 via --epss)
definition.id
definition.name
definition.solution
last_seen                    # qualquer formato legível pelo pandas (será normalizado)
severity                     # Critical/High/Medium/Low/Info
id                           # (opcional; usado para contagem por ativo quando presente)
```

Flags opcionais (qualquer coluna que contenha os termos): `kev`, `cisa`, `known_exploit`, `metasploit`, `canvas`, `exploit`, `edb`.

## Uso

### Básico

```bash
# EPSS >= 90% e todas as severidades — saída com timestamp
python3 epssight.py -i tenable_input.csv -e 90
```

### Com severidades

```bash
# EPSS >= 90%, somente críticas e altas, PT-BR
python3 epssight.py -i tenable_input.csv -e 90 -s critical,high --lang pt -o report_epss.xlsx -v
```

### Modo compat (sem tema)

```bash
python3 epssight.py -i tenable_input.csv -e 85 --no-theme
```

## Opções (CLI)

| Opção | Descrição |
|---|---|
| `-i, --input` | (Obrigatório) CSV de entrada. |
| `-o, --output` | XLSX de saída. Se ausente, gera `report_YYYYMMDD_HHMM.xlsx`. |
| `-e, --epss` | EPSS mínimo. Aceita `90` (interpreta 90%) ou `0.90`. Padrão: `90`. |
| `-s, --severity` | Severidades a incluir, por exemplo: `critical,high` (sem espaços). |
| `--lang` | `pt` ou `en`. Padrão: `en`. |
| `--no-theme` | Desliga a formatação (cores, zebra, barra de dados etc.). |
| `-v, --verbose` | Loga etapas no terminal. |
| `-h, --help` | Ajuda. |

## Resumo impresso no terminal (exemplo)

```
Resumo executivo (KPIs)
Métrica  Valor
Itens (EPSS 90%+)            799
Ativos únicos impactados     248
Críticas                     394
Altas                        318
Médias                       73
Baixas                       14

Top CVEs por ativos afetados
CVE-2020-XXXX    106
CVE-2019-YYYY     31
...
```

O resumo e o Top 10 refletem exatamente o conjunto filtrado por `--epss` e `--severity`.

## Detalhes de implementação

- EPSS: se `--epss` > 1, assume que veio em porcentagem e converte para 0..1.
- Ordenação: categoria de severidade ordenada (`Critical > High > Medium > Low > Info`) e EPSS desc dentro da categoria.
- `LAST SEEN`: convertido para `dd/MM/aaaa`.
- `Info`: suprimido na aba `por_severidade`.

## Solução de problemas

- Excel avisou que “removeu formatação condicional”  
  Utilize `--no-theme` (modo compat) em versões mais antigas do Excel.
- EPSS fora de 0..1 no CSV  
  A ferramenta aceita `--epss 90` ou `--epss 0.90`. A coluna do CSV deve estar em 0..1 (padrão Tenable).

## Contribuição

1. Abra uma issue com o que deseja ajustar.  
2. Faça um fork, crie um branch e envie um PR.  
3. Requisitos: Python 3.8+, `pandas`, `numpy`, `xlsxwriter`.

## Licença

MIT License.

## Exemplo rápido (Windows)

```powershell
python epssight.py -i .\tenable_input.csv -e 90 -s critical,high --lang pt -o .\report_epss.xlsx -v
```

# Roteiro 4 — Port Scanner TCP (Tecnologias Hacker)

Scanner de portas TCP feito em Python 3 só com a biblioteca padrão (`socket`, `argparse`,
`concurrent.futures`, `csv`, `json`, `logging`, `time`). A técnica é **TCP Connect**: para cada
porta, o programa tenta abrir uma conexão completa com `socket.connect()` e classifica o resultado.
Ele não usa bibliotecas que façam a varredura e não chama o Nmap.

| Estado    | Significado                                   | Como é detectado                                |
|-----------|-----------------------------------------------|-------------------------------------------------|
| `ABERTA`  | conexão estabelecida (handshake completo)     | `connect()` retorna sem exceção                 |
| `FECHADA` | conexão recusada (o host respondeu com RST)   | `ConnectionRefusedError`                        |
| `TIMEOUT` | nenhuma resposta dentro do tempo limite       | `socket.timeout` / `TimeoutError`               |
| `ERRO`    | outra falha de comunicação                    | outro `OSError` (ex.: `EHOSTUNREACH`, `ENETUNREACH`) |

> **Uso ético:** escaneie apenas sistemas próprios ou expressamente autorizados. Todos os testes
> deste trabalho foram feitos contra `127.0.0.1` (a própria máquina).

## Estrutura

```
portscanner.py        # o scanner (entregável principal)
lab/servico_tcp.py    # serviço TCP mínimo para ligar/desligar durante os testes
lab/experimento.sh    # monta o ambiente de teste, roda todos os experimentos e grava as evidências
evidencias/           # saídas reais (scanner, nmap, ss, JSON, CSV, logs)
RELATORIO.md / .pdf   # relatório técnico (o PDF é o mesmo conteúdo, para entrega)
```

## Requisitos

- Python **3.9 ou superior** (testado com 3.10.12 no Ubuntu 22.04/WSL2 e 3.12.10 no Windows 11). Não há dependências externas.
  - No Windows, use `-t 3` ou mais em `127.0.0.1`. O Windows retransmite o SYN depois de receber RST,
    então uma porta fechada leva cerca de 2 s para ser recusada, e com `-t 1` ela aparece como TIMEOUT
    (`evidencias/08_windows_rst.txt`).
- Só para os experimentos (`lab/experimento.sh`): Linux com `nmap`, `iptables`, `tc` (iproute2) e `ss`, rodando como root.
  No WSL: `wsl -u root -- apt-get install -y nmap`.

## Como executar

```bash
python3 portscanner.py <destino> [-p PORTAS] [-t TIMEOUT] [-w WORKERS] [-a] [-o ARQUIVO] [--log ARQUIVO]
python3 portscanner.py --help
```

### Parâmetros

| Parâmetro | Padrão | Descrição |
|---|---|---|
| `destino` | — | IP (v4/v6) ou hostname. É resolvido com `getaddrinfo`; IPv4 é preferido se o nome tiver os dois. |
| `-p, --portas` | `1-1024` | Porta única (`80`), intervalo (`20-25`) ou lista (`22,80,8000-8010`). Aceita portas de 1 a 65535. |
| `-t, --timeout` | `1.0` | Tempo limite de cada tentativa, em segundos (maior que 0 e até 60). |
| `-w, --workers` | `1` | Número de portas testadas ao mesmo tempo (1 a 200). `1` = sequencial. |
| `-a, --todas` | desligado | Lista também as portas FECHADAS quando há mais de 30 portas (senão elas aparecem só no resumo). |
| `-o, --output` | — | Exporta os resultados. O formato vem da extensão: `.json` ou `.csv`. |
| `--log` | — | Grava um log com o início, cada tentativa, os erros e o fim da execução. |

Códigos de saída: `0` ok · `1` falha ao exportar · `2` parâmetro inválido · `130` interrompido com Ctrl+C
(os resultados parciais são mostrados e exportados mesmo assim).

### Exemplos

```bash
python3 portscanner.py 127.0.0.1 -p 22                         # uma porta
python3 portscanner.py localhost -p 1-1024 -t 0.5 -w 50        # intervalo, concorrente
python3 portscanner.py 127.0.0.1 -p 22,80,2222,8080 -t 2       # lista, timeout maior
python3 portscanner.py 127.0.0.1 -p 1-5000 -w 50 -o res.csv --log scan.log
python3 portscanner.py 127.0.0.1 -p 9001 -o res.json -a
```

Exemplo de saída real (trecho de `evidencias/04_comparacao_nmap.txt`):

```
DESTINO           PORTA  ESTADO   SERVICO PROVAVEL*  TEMPO(ms)  DETALHE
127.0.0.1            22  FECHADA  ssh                     0.24  conexao recusada (RST recebido)
127.0.0.1            80  FECHADA  http                    0.16  conexao recusada (RST recebido)
127.0.0.1          2222  ABERTA   -                       0.10  conexao estabelecida (handshake completo)
127.0.0.1          3306  FECHADA  mysql                   0.07  conexao recusada (RST recebido)
127.0.0.1          8080  ABERTA   http-alt                0.14  conexao estabelecida (handshake completo)
127.0.0.1          9001  TIMEOUT  -                    1001.56  sem resposta dentro do tempo limite
127.0.0.1          9002  ERRO     -                       0.47  EHOSTUNREACH: No route to host
Resumo: 2 aberta(s), 3 fechada(s), 1 timeout(s), 1 erro(s) - 7 de 7 porta(s) testada(s) em 1.006 s
```

## Ambiente de teste e demonstração

```bash
# Rodar todos os experimentos (WSL, a partir da pasta do projeto).
# ATENÇÃO: sem argumento, o script SOBRESCREVE evidencias/, que é a pasta citada no relatório.
# Na demonstração, use outra pasta:
wsl -u root -- bash lab/experimento.sh evidencias_demo
```

Para a demonstração manual, no WSL/Linux (por exemplo, quando o professor pedir para parar ou iniciar um serviço):

```bash
python3 -m http.server 8080 &          # liga um serviço  -> 8080 ABERTA
python3 lab/servico_tcp.py 2222 &      # outro serviço    -> 2222 ABERTA
kill %1                                # desliga          -> 8080 FECHADA
sudo iptables -A INPUT -p tcp --dport 9001 -j DROP                                   # -> TIMEOUT
sudo iptables -A INPUT -p tcp --dport 9002 -j REJECT --reject-with icmp-host-unreachable  # -> ERRO
sudo tc qdisc add dev lo root netem delay 300ms   # latência artificial (o timeout passa a influir)
# limpeza: sudo iptables -F INPUT ; sudo tc qdisc del dev lo root
ss -tlnp                                # confere quais portas estão em LISTEN
nmap -sT --reason -p 22,80,2222,3306,8080,9001,9002 127.0.0.1   # comparação
```

## Melhorias implementadas (seção 7)

1. **Execução concorrente com limite de tarefas** (`-w`): usa um `ThreadPoolExecutor` de tamanho fixo
   (no máximo 200), então nunca há mais de `w` conexões abertas ao mesmo tempo, e no máximo `2w` tarefas
   ficam na fila. A saída é ordenada por porta depois da varredura. Medido: 20 portas filtradas com timeout de 0,5 s levaram **10,04 s
   sequencial** e **0,53 s com `-w 20`** (`evidencias/07_melhorias.txt`).
2. **Exportação de resultados** em JSON (com metadados: alvo, parâmetros, duração, contagem e se
   houve interrupção) ou CSV (`-o`).
3. **Identificação de serviços**: a coluna "SERVIÇO PROVÁVEL" vem de `socket.getservbyport()`
   (tabela `/etc/services`). Ela mostra o serviço *normalmente associado* à porta, não o serviço
   que de fato está rodando. Por exemplo, na 8080 estava o `http.server` do Python e a tabela diz `http-alt`.
4. **Medição de desempenho**: o tempo de cada tentativa (ms) e o tempo total da varredura.
5. **Registro de execução** (`--log`): um arquivo com timestamps de cada teste, dos erros e da interrupção.

A interface com `argparse` e `--help` também está implementada, mas ela faz parte dos requisitos
básicos e não foi contada como melhoria.

# Relatório Técnico — Roteiro 4: Port Scanner TCP

**Aluno:** Marcos Augusto Rossi Paulino Costa  
**Disciplina:** Tecnologias Hacker — Insper  **Data dos experimentos:** 20/11/2026  
**Ambiente:** Windows 11 + WSL2 (Ubuntu 22.04), Python 3.10.12, Nmap 7.80. **Alvo:** `127.0.0.1` (a própria
máquina, sob meu controle). As saídas completas estão em `evidencias/` e foram geradas por `lab/experimento.sh`.

## 1. Estratégia de implementação

O scanner usa a técnica **TCP Connect**: para cada porta, pede ao sistema operacional uma conexão TCP completa e
observa como ela termina. Recursos da biblioteca `socket` usados:

- `getaddrinfo()` resolve o IP ou hostname e devolve a família (`AF_INET`/`AF_INET6`). Se falha, lança `gaierror` (destino inválido).
- `socket(família, SOCK_STREAM)` cria um socket TCP novo por porta; `settimeout(t)` limita a espera de `connect()`.
- `connect((ip, porta))`: o kernel envia o SYN e faz o *three-way handshake*. Se recebe RST, lança `ConnectionRefusedError`;
  se recebe um ICMP de erro, lança outro `OSError` (`errno`); sem resposta em `t` segundos, lança `socket.timeout`.
- `with socket.socket(...)` fecha o socket em qualquer caminho, inclusive com exceção (libera o descritor; se a conexão abriu, envia FIN).

Usei `connect()` com exceções, e não `connect_ex()`, porque com timeout o `connect_ex` devolve `EAGAIN`, fácil de
classificar errado. A ordem de teste é `ConnectionRefusedError` → `timeout` → `OSError`, porque as duas primeiras são
subclasses de `OSError`. O código segue as etapas da seção 3.2: **parâmetros** (`interpretar_portas`, `validar_porta`,
`validar_timeout`, `resolver_destino`), **conexão** (`tentar_conexao`), **interpretação** (`interpretar_erro`) e
**apresentação/registro** (`apresentar`, `exportar`, log).

```
ler e validar argumentos (portas 1..65535, INICIO<=FIM, timeout>0); resolver destino
    se inválido -> mensagem clara, sair com código 2
para cada porta (pool de no máximo W threads, fila de até 2W tarefas):
    com socket TCP s:  s.settimeout(timeout);  tentar s.connect((ip, porta))
        sucesso -> ABERTA | ConnectionRefusedError -> FECHADA (RST)
        timeout -> TIMEOUT (sem resposta) | outro OSError -> ERRO (EHOSTUNREACH...)
    socket fechado automaticamente; registrar estado, tempo, serviço provável e log
se Ctrl+C: cancelar tarefas pendentes e manter os resultados parciais
ordenar por porta; imprimir tabela (destino, porta, estado) e resumo; exportar JSON/CSV
```

**Questão — por que uma tentativa de conexão TCP serve para investigar uma porta?** Quem recebe um SYN responde
conforme a porta: se há um processo em `listen()`, o kernel devolve SYN/ACK e o handshake se completa; se não há, a
RFC 793 manda responder com RST. A forma como `connect()` termina revela, portanto, se houve aceite, recusa ou
nenhuma resposta (algo no caminho descartou o pacote).

## 2. Testes iniciais (seção 3.3)

Ambiente (`01_ambiente.txt`): `http.server` na 8080 e `lab/servico_tcp.py` na 2222; nenhum serviço em 22, 80 e 3306;
`iptables DROP` na 9001 e `REJECT --reject-with icmp-host-unreachable` na 9002. O `ss -tlnp` mostrou só 8080 e 2222
em LISTEN (além do DNS local). Varredura com `-t 1` (`02_testes_iniciais.txt`):

| Porta | 22 | 80 | 2222 | 3306 | 8080 | 9001 | 9002 |
|---|---|---|---|---|---|---|---|
| Scanner | FECHADA | FECHADA | **ABERTA** | FECHADA | **ABERTA** | TIMEOUT (1001 ms) | ERRO `EHOSTUNREACH` |

No intervalo `1-10000` (`localhost`, `-t 0.5 -w 100`, 4,90 s): 2 abertas (2222, 8080), 9976 fechadas, 21 timeouts
(9001 e 9100–9119, todas com DROP) e 1 erro (9002), exatamente o que o `ss` e o `iptables` indicavam.

**Questão — o scanner identificou as portas ativas? Como se comportou nas portas sem serviço?** Sim: as únicas
ABERTAS foram as duas em LISTEN no `ss`. Nas portas sem serviço veio um RST imediato (0,07 a 0,38 ms), classificado
como FECHADA sem esperar o timeout. Nas filtradas, o programa esperou o tempo limite e marcou TIMEOUT, não "fechada".

## 3. Tratamento de erros (seção 4)

Evidências em `03_tratamento_erros.txt`. Nenhum caso terminou com *traceback*; os inválidos saem com código 2.

| Situação | Entrada | Comportamento observado |
|---|---|---|
| Serviço ativo / sem serviço / timeout | `-p 8080,3306,9001` | ABERTA / FECHADA / TIMEOUT; uma falha não interrompe as demais portas |
| Porta inválida | `70000`, `0`, `abc` | `porta invalida 70000: deve estar entre 1 e 65535.` |
| Intervalo inválido | `100-50`, `1-2-3`, `80,,81` | `intervalo invalido '100-50': a porta inicial (100) e maior que a final (50).` |
| Destino inválido | `host-que-nao-existe.invalid`, `999.1.1.1` | `destino invalido ou nao resolvido` / `endereco IPv4 mal formado` |
| Timeout, workers ou saída inválidos | `-t 0`, `-t abc`, `-w 0`, `-o x.txt` | `argparse` mostra o uso e o motivo |
| Interrupção (Ctrl+C) | SIGINT após 2,5 s, 20 portas DROP | testou 2 de 20, mostrou e exportou os resultados **parciais** (código 130) |

O `with` fecha todos os sockets. Na interrupção, `pool.shutdown(cancel_futures=True)` descarta as tarefas não
iniciadas; a thread principal espera com `wait(..., timeout=0.2)`, então o Ctrl+C é atendido em até 0,2 s. Um defeito
real apareceu nos testes: com 50 threads, o CSV saiu com nomes de serviço corrompidos (`"# Local services"`) e a
exportação quebrou, porque `getservbyport()` da glibc não é *thread-safe*. Corrigi fazendo essa consulta só na thread
principal e validando o nome; depois disso, as duas execuções com várias threads exportaram corretamente.

**Questão — por que um timeout não deve ser tratado como porta fechada?** Uma porta fechada *responde* com RST; o
timeout é a *ausência* de resposta, que pode vir de firewall descartando o SYN (caso da 9001), perda de pacotes,
congestionamento, host desligado ou latência maior que o limite. O último caso foi provado (§4): com 300 ms de atraso,
as portas 8080 (aberta) e 3306 (fechada) deram TIMEOUT com `-t 0.2`. Tratar timeout como "fechada" esconderia portas
abertas atrás de filtros ou em redes lentas.

## 4. Validação com Nmap (seção 5)

Mesmo alvo e mesmas portas, em sequência (`04_comparacao_nmap.txt`): `portscanner.py 127.0.0.1 -p 22,80,2222,3306,8080,9001,9002 -t 1`
e `nmap -sT --reason -p 22,80,2222,3306,8080,9001,9002 127.0.0.1`.

| Porta TCP | Estado esperado | Scanner desenvolvido | Nmap (`-sT`) |
|---|---|---|---|
| 22 / 80 / 3306 | fechada (sem serviço) | FECHADA | closed (conn-refused) |
| 2222 | aberta (`servico_tcp.py`) | ABERTA (serviço: `-`) | open (syn-ack), "EtherNetIP-1" |
| 8080 | aberta (`http.server`) | ABERTA (`http-alt`) | open (syn-ack), "http-proxy" |
| 9001 | filtrada (DROP) | TIMEOUT (1001 ms) | filtered (no-response) |
| 9002 | filtrada (REJECT ICMP host-unreach) | ERRO (`EHOSTUNREACH`) | filtered (host-unreach) |

**Mesmos resultados?** Os diagnósticos foram equivalentes nas 7 portas; abertas e fechadas coincidem exatamente.
**Diferenças observadas:** (1) o Nmap chama de `filtered` tanto o DROP quanto o REJECT, e o meu scanner os separa em
TIMEOUT e ERRO (o Nmap só mostra a causa com `--reason`); (2) os nomes de serviço vêm de bases diferentes
(`/etc/services` × `nmap-services`) e nenhum é o serviço real, que nos dois casos era um programa em Python; (3) o
Nmap levou 1,35 s e o meu scanner 1,006 s, quase todo gasto no timeout fixo da 9001.
**Fatores que explicam:** as ferramentas interpretam e nomeiam os resultados de forma diferente e têm políticas de
timeout diferentes. O meu timeout é fixo; o Nmap estima o RTT, adapta o timeout e retransmite. Com 300 ms de atraso
por pacote (`05_influencia_timeout.txt`), o meu scanner com `-t 0.2` marcou 8080 e 3306 como TIMEOUT, enquanto o
Nmap mediu RTT de 0,60 s e acertou as duas; com `-t 2`, o meu scanner também acertou.

**Porta aberta permite concluir que há vulnerabilidade?** Não. "Aberta" só diz que o kernel aceitou um handshake
naquele momento, daquele ponto da rede. Não diz qual software atende (a 8080 "http-alt" era o `http.server`), nem a
versão, nem se há falha. Confirmar uma vulnerabilidade exige identificar serviço e versão (*banner grabbing*,
`nmap -sV`), consultar CVEs e validar a falha de forma controlada e autorizada.

## 5. Experimento de mudança de estado (seção 6)

Serviço: `python3 -m http.server 8080`. Em cada rodada rodei `ss`, o scanner e o Nmap (`06_mudanca_estado.txt`):

| Rodada | Horário | `ss -tlnp :8080` | Scanner | Nmap |
|---|---|---|---|---|
| A — serviço ativo | 17:42:58 | LISTEN (pid 662) | ABERTA (0,35 ms) | open (syn-ack) |
| B — interrompido (`kill 662`) | 17:42:59 | nenhum socket | FECHADA (RST) | closed (conn-refused) |
| C — reiniciado | 17:43:00 | LISTEN (pid 913) | ABERTA (0,30 ms) | open (syn-ack) |

Em B, o processo terminou e o socket de escuta foi fechado; sem ninguém em `listen()`, o kernel passou a responder
com RST e a porta virou FECHADA. Em C, um **novo** processo (outro PID) abriu a porta e ela voltou a ABERTA. Para o
scanner, A e C são iguais: ele enxerga a porta, não o processo por trás dela.

**Questão — por que o resultado é uma observação de um momento?** O estado de uma porta depende de coisas que mudam
o tempo todo: processos em escuta, regras de firewall, rota e latência. Três rodadas com cerca de 1 s de intervalo
deram ABERTA, FECHADA e ABERTA para a mesma porta. Uma varredura vale para o instante e o ponto de rede de onde foi
feita; por isso o programa registra data e hora em cada execução (JSON e log).

## 6. Melhoria adicional (seção 7)

Implementei, e documentei no README: execução concorrente com limite (`-w`, até 200), exportação JSON/CSV, serviço
provável (com aviso de que não confirma o serviço real), medição de tempo e log de execução. Medições (`07_melhorias.txt`):

| Cenário | `-w 1` | Concorrente | Observação |
|---|---|---|---|
| 20 portas DROP, `-t 0.5` | 10,04&nbsp;s | 0,53&nbsp;s (20&nbsp;threads) | ganho de ~20×: o tempo é espera por timeout |
| 5000 portas no loopback (RST < 1&nbsp;ms) | 1,10&nbsp;s | 2,49&nbsp;s (50&nbsp;threads) | sem ganho: custo das threads e do GIL supera a espera |
| 5000 portas, `-w 50` + CSV + `--log` | — | 9,65 s | gravar 5000 linhas de log em `/mnt/c` (disco do Windows no WSL) é lento |

A concorrência compensa quando o tempo é dominado por espera na rede; em loopback com respostas imediatas, atrapalha.

## 7. Análise crítica

1. **Uso de sockets:** um socket `AF_INET`/`SOCK_STREAM` por porta, com `settimeout`; o `connect()` delega o handshake
   ao kernel, e a exceção lançada (ou a ausência dela) define o estado. O `with` fecha o socket.
2. **Limitações:** o Connect Scan completa o handshake, então chega à aplicação e aparece em logs de conexão e firewall
   (mais "ruidoso" que o SYN scan); não distingue DROP de rede lenta; não retransmite (um SYN perdido vira TIMEOUT);
   timeout fixo; sem detecção de versão; só TCP, um alvo e o primeiro endereço do DNS; threads sem ganho em loopback
   (GIL); pode acionar IDS ou limites de taxa. O resultado também depende da pilha TCP de quem executa: no Windows 11
   (`08_windows_rst.txt`), uma porta fechada de `127.0.0.1` levou 2,06 s para ser recusada (o Windows retransmite o
   SYN após o RST), virando TIMEOUT com `-t 1` e FECHADA com `-t 3`; o `netstat` confirmou só 135 e 445 em LISTEN.
3. **Influência do timeout:** curto demais em relação ao RTT gera falsos TIMEOUTs (§4 com 300 ms de atraso; a 3306 no
   Windows); longo demais deixa a varredura lenta, pois cada porta filtrada custa o timeout inteiro (§6: 20 × 0,5 s ≈ 10 s).
4. **Diferenças para o Nmap:** abertas e fechadas idênticas; o Nmap agrupa DROP e REJECT como `filtered`, usa outra
   base de nomes e adapta o timeout ao RTT com retransmissões (§4).
5. **Mudança de estado:** o scanner acompanhou ABERTA → FECHADA → ABERTA, sempre de acordo com o `ss` e o Nmap (§5).
6. **Melhorias para confiabilidade e eficiência:** timeout adaptativo pelo RTT; retransmitir as portas com TIMEOUT
   antes de concluir; limitar a taxa de envio; `asyncio` no lugar de threads; *banner grabbing*; vários alvos e IPv6
   completo; SYN scan com raw sockets (exige root).

**Porta aberta, serviço e vulnerabilidade** são etapas distintas de uma investigação. A porta aberta prova só que um
handshake TCP foi aceito (o que este scanner faz). Identificar o serviço exige interagir com a aplicação (banner,
protocolo, versão), porque o número da porta é só convenção, como mostraram o `http.server` na 8080 e o serviço
próprio na 2222. Confirmar uma vulnerabilidade exige relacionar a versão a falhas conhecidas e validá-la de forma
controlada e autorizada. O scanner cobre só a primeira etapa, e isso fica explícito na saída ("não confirma o serviço real").

# Relatório Técnico — Roteiro 4: Port Scanner TCP

**Aluno:** Marcos Augusto Rossi Paulino Costa  
**Disciplina:** Tecnologias Hacker — Insper  **Data dos experimentos:** 20/11/2026  
**Ambiente:** Windows 11 + WSL2 (Ubuntu 22.04, kernel 6.18 WSL2), Python 3.10.12, Nmap 7.80.  
**Alvo:** `127.0.0.1` (a própria máquina, sob meu controle). As saídas completas estão em `evidencias/` e
foram geradas por `lab/experimento.sh`.

## 1. Estratégia de implementação

O scanner usa a técnica **TCP Connect**. Para cada porta, o programa pede ao sistema operacional uma
conexão TCP completa e observa como ela termina. Os recursos da biblioteca `socket` usados foram:

- `socket.getaddrinfo()`: resolve o IP ou hostname e indica a família (`AF_INET` ou `AF_INET6`).
  Quando falha, lança `socket.gaierror`, o que o programa trata como destino inválido.
- `socket.socket(família, SOCK_STREAM)`: cria um socket TCP. Um socket novo por porta.
- `settimeout(t)`: limita quanto tempo `connect()` espera. Depois de `t` segundos sem resposta, ele lança `socket.timeout`.
- `connect((ip, porta))`: o kernel envia o SYN e completa o *three-way handshake*. Se receber RST,
  `connect()` lança `ConnectionRefusedError`. Se receber um ICMP de erro, lança outro `OSError` (`errno`).
- `with socket.socket(...)`: fecha o socket em qualquer caminho, inclusive quando há exceção.
  Isso libera o descritor e, se a conexão abriu, encerra com FIN.

Optei por `connect()` com exceções em vez de `connect_ex()`, porque com timeout o `connect_ex` devolve
`EAGAIN`, que é fácil de classificar errado. As exceções são testadas nesta ordem:
`ConnectionRefusedError`, depois `timeout`, depois `OSError` genérico. A ordem importa porque as duas
primeiras são subclasses de `OSError`. O código segue as etapas sugeridas na seção 3.2:

- **parâmetros**: `interpretar_portas`, `validar_porta`, `validar_timeout`, `resolver_destino`;
- **conexão**: `tentar_conexao`;
- **interpretação**: `interpretar_erro`;
- **apresentação e registro**: `apresentar`, `exportar`, log.

### Pseudocódigo

```
ler argumentos (destino, portas, timeout, workers, saída, log)
validar portas (1..65535, INICIO<=FIM) e timeout; resolver destino (getaddrinfo)
    se inválido -> mensagem clara, sair com código 2
para cada porta (em um pool de no máximo W threads):
    inicio = relógio
    com socket TCP s:
        s.settimeout(timeout)
        tentar s.connect((ip, porta))
            sucesso                 -> ABERTA
            ConnectionRefusedError  -> FECHADA   (RST)
            timeout                 -> TIMEOUT   (sem resposta; causa indeterminada)
            outro OSError           -> ERRO      (errno: EHOSTUNREACH, ENETUNREACH...)
    socket fechado automaticamente; registrar estado, tempo, serviço provável, log
se Ctrl+C: cancelar as tarefas pendentes e manter os resultados parciais
ordenar por porta; imprimir tabela (destino, porta, estado) e resumo; exportar JSON/CSV
```

**Questão — por que uma tentativa de conexão TCP serve para investigar a disponibilidade de uma porta?**
Pelo protocolo TCP, quem recebe um SYN responde de forma diferente conforme a porta. Se houver um
processo em `listen()`, o kernel responde com SYN/ACK e o handshake se completa. Se não houver, a
RFC 793 manda responder com RST. Assim, a forma como `connect()` termina reflete a pilha TCP do alvo:
houve aceite, houve recusa, ou não houve resposta (algo no caminho descartou o pacote).

## 2. Testes iniciais (seção 3.3)

O ambiente (`evidencias/01_ambiente.txt`) foi montado assim:

- `http.server` na porta 8080 e `lab/servico_tcp.py` na porta 2222;
- nenhum serviço nas portas 22, 80 e 3306;
- `iptables DROP` na porta 9001;
- `iptables REJECT --reject-with icmp-host-unreachable` na porta 9002.

O `ss -tlnp` mostrou apenas 8080 e 2222 em LISTEN (além do DNS local). Resultado da varredura
(`02_testes_iniciais.txt`, `-t 1`):

| Porta | 22 | 80 | 2222 | 3306 | 8080 | 9001 | 9002 |
|---|---|---|---|---|---|---|---|
| Scanner | FECHADA | FECHADA | **ABERTA** | FECHADA | **ABERTA** | TIMEOUT (1001 ms) | ERRO `EHOSTUNREACH` |

Também varri o intervalo `1-10000` (`localhost`, `-t 0.5 -w 100`), que levou 4,90 s. O resultado foi
2 portas abertas (2222 e 8080), 9976 fechadas, 21 timeouts (9001 e 9100–9119, todas com DROP) e
1 erro (9002). Exatamente o que o `ss` e as regras do `iptables` indicavam.

**Questão — o scanner identificou corretamente as portas ativas? Como se comportou nas portas sem serviço?**
Sim. As únicas portas ABERTAS foram as duas que o `ss` mostrava em LISTEN. Nas portas sem serviço, a
resposta foi um RST imediato (de 0,07 a 0,38 ms), classificado como FECHADA sem esperar o timeout.
Nas portas filtradas, o programa esperou o tempo limite inteiro e marcou TIMEOUT, sem chamar a porta de fechada.

## 3. Tratamento de erros (seção 4)

Evidências em `03_tratamento_erros.txt`. Nenhum caso terminou com *traceback*.

| Situação | Entrada | Comportamento observado |
|---|---|---|
| Porta com serviço / sem serviço / timeout | `-p 8080,3306,9001` | ABERTA / FECHADA / TIMEOUT. Uma falha não interrompe as outras portas. |
| Porta inválida | `-p 70000`, `-p 0`, `-p abc` | `Erro: porta invalida 70000: deve estar entre 1 e 65535.` (saída 2) |
| Intervalo inválido | `-p 100-50`, `1-2-3`, `80,,81` | `intervalo invalido '100-50': a porta inicial (100) e maior que a final (50).` |
| Destino inválido | `host-que-nao-existe.invalid`, `999.1.1.1` | `destino invalido ou nao resolvido ...` / `endereco IPv4 mal formado` |
| Timeout/workers/saída inválidos | `-t 0`, `-t abc`, `-w 0`, `-o x.txt` | o `argparse` mostra o uso e o motivo (saída 2) |
| Interrupção (Ctrl+C) | SIGINT após 2,5 s em 20 portas DROP | testou 2 de 20 portas, mostrou e exportou os resultados **parciais** marcados como interrompidos (saída 130) |

Os sockets são sempre fechados pelo `with`. Na interrupção, `pool.shutdown(cancel_futures=True)`
descarta as tarefas que ainda não começaram. A thread principal espera os resultados com
`wait(..., timeout=0.2)` e não bloqueia indefinidamente, então o Ctrl+C é atendido em até 0,2 s.
No máximo `2×workers` tarefas ficam na fila ao mesmo tempo.

Um defeito real apareceu durante os testes. Com 50 threads, o CSV saiu com nomes de serviço corrompidos
(`"# Local services\n"`) e a exportação quebrou. A causa é que `getservbyport()` da glibc não é
*thread-safe*. A correção foi fazer essa consulta apenas na thread principal e validar o nome
devolvido. Depois da correção, a exportação funcionou nas duas execuções do experimento que rodaram com várias threads.

**Questão — por que um timeout não deve ser interpretado automaticamente como porta fechada?**
Uma porta fechada *responde* com RST. O timeout é a *ausência* de resposta, e ela tem várias causas
possíveis: um firewall que descarta o SYN (caso da 9001), perda de pacotes, congestionamento, um host
desligado, ou uma latência maior que o tempo limite. O último caso foi provado (`05_influencia_timeout.txt`, ver §4): com 300 ms
de atraso artificial, as portas 8080 (aberta) e 3306 (fechada) deram TIMEOUT com `-t 0.2`. Chamar
timeout de "fechada" esconderia portas abertas atrás de filtros ou em redes lentas.

## 4. Validação com Nmap (seção 5)

Mesmo alvo e mesmas portas, um logo após o outro (`04_comparacao_nmap.txt`):
`python3 portscanner.py 127.0.0.1 -p 22,80,2222,3306,8080,9001,9002 -t 1` e
`nmap -sT --reason -p 22,80,2222,3306,8080,9001,9002 127.0.0.1`.

| Porta TCP | Estado esperado | Scanner desenvolvido | Nmap (`-sT`) |
|---|---|---|---|
| 22 | fechada (sem serviço) | FECHADA | closed (conn-refused) |
| 80 | fechada (sem serviço) | FECHADA | closed (conn-refused) |
| 2222 | aberta (`servico_tcp.py`) | ABERTA (serviço: `-`) | open (syn-ack) — "EtherNetIP-1" |
| 3306 | fechada (sem serviço) | FECHADA | closed (conn-refused) |
| 8080 | aberta (`http.server`) | ABERTA (`http-alt`) | open (syn-ack) — "http-proxy" |
| 9001 | filtrada (DROP) | TIMEOUT (1001 ms) | filtered (no-response) |
| 9002 | filtrada (REJECT ICMP host-unreach) | ERRO (`EHOSTUNREACH`) | filtered (host-unreach) |

**O scanner apresentou os mesmos resultados que o Nmap?** Os diagnósticos foram equivalentes nas 7
portas. As portas abertas e fechadas coincidem exatamente. Só os rótulos das portas filtradas são diferentes.

**Quais diferenças foram observadas?**

1. *Nomenclatura dos estados filtrados.* O Nmap chama de `filtered` tanto o DROP quanto o REJECT com
   ICMP. O meu scanner separa os dois em TIMEOUT e ERRO. O Nmap só mostra essa diferença com `--reason`.
2. *Nome do serviço.* As tabelas de serviços são diferentes. O meu programa usa `/etc/services` (`http-alt`, nenhum
   nome para 2222). O Nmap usa o `nmap-services` (`http-proxy`, `EtherNetIP-1`). Nenhum dos dois é o
   serviço real, que nos dois casos era um programa em Python.
3. *Tempo e estratégia.* O Nmap terminou em 1,35 s e o meu scanner em 1,006 s. Quase todo o tempo do
   meu scanner foi o timeout fixo da 9001. O Nmap estima o RTT, ajusta o timeout dinamicamente, testa
   várias portas em paralelo e retransmite antes de declarar uma porta `filtered`.

**Que fatores explicam as diferenças?** Os dois programas interpretam os resultados de formas diferentes
(o Nmap agrupa as falhas como "filtrado"), usam bases de nomes de serviço diferentes e têm políticas de
timeout diferentes. O meu timeout é fixo e o do Nmap é adaptativo, com retransmissões. Isso pesa quando
há latência. Com 300 ms de atraso por pacote, o meu scanner com `-t 0.2` marcou 8080 e 3306 como TIMEOUT.
O Nmap, com o timeout padrão, acertou as duas (open e closed), porque mediu o RTT de 0,60 s
(`05_influencia_timeout.txt`). Com `-t 2`, o meu scanner também acertou.

**Uma porta aberta permite concluir que o serviço é vulnerável?** Não. "Aberta" quer dizer apenas que o
kernel aceitou um handshake naquele momento, a partir daquele ponto da rede. Isso não diz qual software
está atendendo (a 8080 "http-alt" era o `http.server`), nem a versão, nem se há falha explorável.
Confirmar uma vulnerabilidade exige outras etapas: identificar o serviço e a versão (*banner grabbing*,
`nmap -sV`), consultar CVEs e validar a falha de forma controlada e autorizada.

## 5. Experimento de mudança de estado (seção 6)

O serviço usado foi o `python3 -m http.server 8080`. Em cada rodada rodei o `ss`, o scanner e o Nmap
(`06_mudanca_estado.txt`):

| Rodada | Horário | `ss -tlnp :8080` | Scanner | Nmap |
|---|---|---|---|---|
| A — serviço ativo | 17:42:58 | LISTEN (pid 662) | ABERTA (0,35 ms) | open (syn-ack) |
| B — serviço interrompido (`kill 662`) | 17:42:59 | nenhum socket | FECHADA (RST) | closed (conn-refused) |
| C — serviço reiniciado | 17:43:00 | LISTEN (pid 913) | ABERTA (0,30 ms) | open (syn-ack) |

Na rodada B, o processo deixou de existir e o socket de escuta foi fechado. Sem ninguém em `listen()`,
o kernel passou a responder ao SYN com RST, e a porta passou de ABERTA para FECHADA. Na rodada C, um
**novo** processo (outro PID) abriu a porta e ela voltou a ser ABERTA. Para o scanner, as rodadas A e C
são iguais, embora o processo seja outro. O scanner só enxerga a porta, não o processo por trás dela.

**Questão — por que o resultado é uma observação de um momento e não uma característica permanente?**
O estado de uma porta depende de coisas que mudam o tempo todo: se um processo está em escuta, as
regras de firewall, a rota e a latência. As três rodadas, feitas com cerca de 1 s de intervalo, deram
ABERTA, FECHADA e ABERTA para a mesma porta. Um relatório de varredura vale para o instante e o ponto de
rede de onde foi feito, e por isso o programa registra data e hora em cada execução (JSON e log).

## 6. Melhoria adicional (seção 7)

Implementei estas melhorias, documentadas no README:

- execução concorrente com limite (`-w`, no máximo 200);
- exportação em JSON e CSV;
- serviço provável, com o aviso de que não confirma o serviço real;
- medição de tempo;
- log de execução.

Resultados medidos (`07_melhorias.txt`):

| Cenário | `-w 1` | Concorrente | Observação |
|---|---|---|---|
| 20 portas DROP, `-t 0.5` | 10,04 s | 0,53 s (`-w 20`) | ganho de cerca de 20 vezes: o tempo é gasto esperando timeouts |
| 5000 portas no loopback (RST em menos de 1 ms) | 1,10 s | 2,49 s (`-w 50`) | sem ganho: o custo das threads e do GIL é maior que a espera |
| 5000 portas, `-w 50` + CSV + `--log` | — | 9,65 s | o log de 5000 linhas em `/mnt/c` (disco do Windows visto pelo WSL) é lento |

Conclusão: a concorrência compensa quando o tempo é dominado por espera na rede (timeouts e latência).
Em loopback com respostas imediatas, ela atrapalha.

## 7. Análise crítica

1. **Uso de sockets.** Cada porta recebe um socket `AF_INET`/`SOCK_STREAM` com `settimeout`. O
   `connect()` delega o handshake ao kernel, e a exceção que ele lança (ou a ausência dela) define o
   estado da porta. O socket é fechado pelo `with`.
2. **Limitações.**
    - O Connect Scan completa o handshake. Por isso a conexão chega até a aplicação e pode aparecer
      em logs de conexão e de firewall do alvo. É mais "ruidoso" que o SYN scan.
    - O resultado depende da pilha TCP do sistema que executa o scanner. No Windows 11
      (`08_windows_rst.txt`), uma porta fechada de `127.0.0.1` levou cerca de 2,06 s (2059 ms) para devolver
      "recusada", porque o Windows retransmite o SYN depois de receber RST. Com `-t 1`, ela foi classificada
      como TIMEOUT. Com `-t 3`, foi classificada como FECHADA. O `netstat` confirmou que só 135 e 445 estavam em LISTEN.
    - Não distingue um DROP de uma rede lenta (os dois dão TIMEOUT).
    - Não há retransmissão: um SYN perdido vira TIMEOUT.
    - O timeout é fixo, não adaptativo.
    - Não há detecção de versão do serviço.
    - Só testa TCP, um alvo por vez, e só o primeiro endereço que o DNS devolve.
    - Em loopback, as threads não trazem ganho por causa do GIL.
    - Ao testar porta por porta, podemos acionar sistemas de detecção de intrusão (IDS) ou limites de taxa.
3. **Influência do timeout.** Um timeout menor que o RTT gera falsos TIMEOUTs (§4: `-t 0.2` com 300 ms
   de atraso; Windows: 3306 com `-t 1`). Um timeout grande demais deixa a varredura lenta, porque cada
   porta filtrada custa o timeout inteiro (§6: 20 × 0,5 s ≈ 10 s em modo sequencial).
4. **Diferenças para o Nmap.** Os estados abertos e fechados são idênticos. O Nmap agrupa DROP e REJECT como
   `filtered`, usa outra base de nomes e ajusta o timeout ao RTT com retransmissões (§4).
5. **Mudança de estado.** O scanner acompanhou a sequência ABERTA → FECHADA → ABERTA sempre de acordo
   com o `ss` e o Nmap (§5).
6. **Melhorias para mais confiabilidade e eficiência.**
    - Timeout adaptativo baseado no RTT medido.
    - Retransmissões (repetir o teste das portas com TIMEOUT antes de concluir).
    - Limitar a taxa de envio.
    - Usar `asyncio` em vez de threads, para escalar sem o custo do GIL.
    - *Banner grabbing* para identificar o serviço real.
    - Suporte a vários alvos e a IPv6 completo.
    - SYN scan com raw sockets (exige root).

**Porta aberta, serviço e vulnerabilidade.** São três etapas distintas de uma investigação:

1. a **porta aberta** prova só que um handshake TCP foi aceito (é o que este scanner faz);
2. **identificar o serviço** exige interagir com a aplicação (banner, protocolo, versão), porque o número
   da porta é só uma convenção, como mostrou o `http.server` na 8080 e o serviço próprio na 2222;
3. **confirmar uma vulnerabilidade** exige relacionar a versão a falhas conhecidas e validar a falha de
   forma controlada e autorizada.

O scanner cobre só a primeira etapa, e isso fica explícito na saída ("serviço provável... não confirma o serviço real").

#!/usr/bin/env bash
# experimento.sh - monta o ambiente de teste local, executa todos os experimentos
# do Roteiro 4 e grava as evidencias em evidencias/. Alvo: 127.0.0.1 (a propria maquina).
#
# Requer root (iptables e tc). No WSL:  wsl -u root -- bash lab/experimento.sh [pasta_saida]
# Ambiente montado:
#   8080/tcp  python3 -m http.server      -> servico ativo (ABERTA)
#   2222/tcp  lab/servico_tcp.py          -> servico ativo (ABERTA)
#   22, 80, 3306                          -> sem servico   (FECHADA)
#   9001/tcp  iptables DROP               -> sem resposta  (TIMEOUT)
#   9002/tcp  iptables REJECT host-unreach-> erro ICMP     (ERRO)
#   9100-9119 iptables DROP               -> usado na medicao de desempenho
set -u
cd "$(dirname "$0")/.."
# Pasta de saida: 1o argumento (padrao: evidencias). ATENCAO: o conteudo da pasta e substituido.
# Na demonstracao use outra pasta para preservar as evidencias do relatorio:
#   bash lab/experimento.sh evidencias_demo
EV="${1:-evidencias}"
mkdir -p "$EV"
rm -f "$EV"/*.txt "$EV"/*.json "$EV"/*.csv "$EV"/*.log "$EV"/*.nmap

PORTAS="22,80,2222,3306,8080,9001,9002"
SCAN="python3 portscanner.py"

secao() { echo; echo "=================================================================="; echo "## $*"; echo "=================================================================="; }
cmd()   { echo; echo "\$ $*"; "$@"; echo "[codigo de saida: $?]"; }

iniciar_http() { python3 -m http.server 8080 --bind 0.0.0.0 >/dev/null 2>&1 & HTTP_PID=$!; sleep 1; }
parar_http()   { kill "$HTTP_PID" 2>/dev/null; wait "$HTTP_PID" 2>/dev/null; sleep 0.5; }

limpar() {
    kill "${HTTP_PID:-}" "${SRV_PID:-}" 2>/dev/null
    iptables -D INPUT -p tcp --dport 9001 -j DROP 2>/dev/null
    iptables -D INPUT -p tcp --dport 9002 -j REJECT --reject-with icmp-host-unreachable 2>/dev/null
    iptables -D INPUT -p tcp --dport 9100:9119 -j DROP 2>/dev/null
    tc qdisc del dev lo root 2>/dev/null
}
trap limpar EXIT

# ---------------------------------------------------------------------------
{
secao "0. Ambiente"
date -Iseconds; uname -sr; python3 --version; nmap --version | head -1

secao "1. Montagem do ambiente de teste"
iniciar_http
python3 lab/servico_tcp.py 2222 >/dev/null 2>&1 & SRV_PID=$!
iptables -A INPUT -p tcp --dport 9001 -j DROP
iptables -A INPUT -p tcp --dport 9002 -j REJECT --reject-with icmp-host-unreachable
iptables -A INPUT -p tcp --dport 9100:9119 -j DROP
sleep 1
cmd ss -tlnp
cmd iptables -L INPUT -n --line-numbers
} > "$EV/01_ambiente.txt" 2>&1; cat "$EV/01_ambiente.txt"

# ---------------------------------------------------------------------------
{
secao "2. Testes iniciais (secao 3.3)"
cmd $SCAN --help
cmd $SCAN 127.0.0.1 -p "$PORTAS" -t 1 -o "$EV/scan_inicial.json" --log "$EV/scan_inicial.log"
cmd $SCAN localhost -p 1-10000 -t 0.5 -w 100 -o "$EV/scan_1-10000.csv"
} > "$EV/02_testes_iniciais.txt" 2>&1; cat "$EV/02_testes_iniciais.txt"

# ---------------------------------------------------------------------------
{
secao "3. Tratamento de erros (secao 4)"
echo "--- 3.1 porta com servico ativo / 3.2 porta sem servico / 3.6 timeout"
cmd $SCAN 127.0.0.1 -p 8080,3306,9001 -t 1
echo "--- 3.3 numero de porta invalido"
cmd $SCAN 127.0.0.1 -p 70000
cmd $SCAN 127.0.0.1 -p 0
cmd $SCAN 127.0.0.1 -p abc
echo "--- 3.4 intervalo de portas invalido"
cmd $SCAN 127.0.0.1 -p 100-50
cmd $SCAN 127.0.0.1 -p 1-2-3
cmd $SCAN 127.0.0.1 -p 80,,81
echo "--- 3.5 endereco de destino invalido"
cmd $SCAN host-que-nao-existe.invalid -p 80
cmd $SCAN 999.1.1.1 -p 80
echo "--- parametros invalidos de timeout / workers / exportacao"
cmd $SCAN 127.0.0.1 -p 80 -t 0
cmd $SCAN 127.0.0.1 -p 80 -t abc
cmd $SCAN 127.0.0.1 -p 80 -w 0
cmd $SCAN 127.0.0.1 -p 80 -o saida.txt
echo "--- 3.7 interrupcao pelo usuario (SIGINT = Ctrl+C enviado apos 2,5 s)"
echo "    20 portas filtradas, timeout 1 s, sequencial -> levaria ~20 s"
cmd timeout --preserve-status -s INT 2.5 $SCAN 127.0.0.1 -p 9100-9119 -t 1 -o "$EV/scan_interrompido.json"
} > "$EV/03_tratamento_erros.txt" 2>&1; cat "$EV/03_tratamento_erros.txt"

# ---------------------------------------------------------------------------
{
secao "4. Validacao com Nmap (secao 5) - mesmas portas, mesmo alvo"
cmd ss -tlnp
cmd $SCAN 127.0.0.1 -p "$PORTAS" -t 1 -o "$EV/comparacao_scanner.json"
cmd nmap -sT --reason -p "$PORTAS" -oN "$EV/comparacao_nmap.nmap" 127.0.0.1
} > "$EV/04_comparacao_nmap.txt" 2>&1; cat "$EV/04_comparacao_nmap.txt"

# ---------------------------------------------------------------------------
{
secao "5. Influencia do timeout: atraso artificial de 300 ms em cada pacote (tc netem no loopback)"
tc qdisc add dev lo root netem delay 300ms
cmd tc qdisc show dev lo
echo "--- timeout 0.2 s (menor que o RTT de ~600 ms)"
cmd $SCAN 127.0.0.1 -p 8080,3306 -t 0.2
echo "--- timeout 2 s (maior que o RTT)"
cmd $SCAN 127.0.0.1 -p 8080,3306 -t 2
echo "--- Nmap nas mesmas condicoes (timeout adaptativo)"
cmd nmap -sT --reason -p 8080,3306 127.0.0.1
tc qdisc del dev lo root
} > "$EV/05_influencia_timeout.txt" 2>&1; cat "$EV/05_influencia_timeout.txt"

# ---------------------------------------------------------------------------
{
secao "6. Experimento de mudanca de estado (secao 6) - servico http.server na porta 8080"
echo; echo "### Rodada A - servico ativo"; date -Iseconds
cmd ss -tlnp sport = :8080
cmd $SCAN 127.0.0.1 -p 8080 -t 1 -o "$EV/rodada_A.json"
cmd nmap -sT --reason -p 8080 127.0.0.1

echo; echo "### Rodada B - servico interrompido (kill $HTTP_PID)"
parar_http; date -Iseconds
cmd ss -tlnp sport = :8080
cmd $SCAN 127.0.0.1 -p 8080 -t 1 -o "$EV/rodada_B.json"
cmd nmap -sT --reason -p 8080 127.0.0.1

echo; echo "### Rodada C - servico reiniciado"
iniciar_http; date -Iseconds
cmd ss -tlnp sport = :8080
cmd $SCAN 127.0.0.1 -p 8080 -t 1 -o "$EV/rodada_C.json"
cmd nmap -sT --reason -p 8080 127.0.0.1
} > "$EV/06_mudanca_estado.txt" 2>&1; cat "$EV/06_mudanca_estado.txt"

# ---------------------------------------------------------------------------
{
secao "7. Melhoria: execucao concorrente + medicao de desempenho + exportacao + log"
echo "--- 20 portas filtradas (DROP), timeout 0.5 s"
cmd $SCAN 127.0.0.1 -p 9100-9119 -t 0.5 -w 1
cmd $SCAN 127.0.0.1 -p 9100-9119 -t 0.5 -w 20
echo "--- intervalo 1-5000 sequencial x concorrente (sem log/exportacao, para comparar so a varredura)"
cmd $SCAN 127.0.0.1 -p 1-5000 -t 0.5 -w 1
cmd $SCAN 127.0.0.1 -p 1-5000 -t 0.5 -w 50
echo "--- exportacao CSV + log de execucao"
cmd $SCAN 127.0.0.1 -p 1-5000 -t 0.5 -w 50 -o "$EV/scan_1-5000.csv" --log "$EV/scan_1-5000.log"
echo; echo "\$ head -5 $EV/scan_1-5000.csv"; head -5 "$EV/scan_1-5000.csv"
echo; echo "\$ grep -v FECHADA $EV/scan_1-5000.log"; grep -v FECHADA "$EV/scan_1-5000.log"
} > "$EV/07_melhorias.txt" 2>&1; cat "$EV/07_melhorias.txt"

echo; echo "Evidencias gravadas em $EV/"

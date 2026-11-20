#!/usr/bin/env python3
"""
portscanner.py - Scanner de portas TCP (TCP Connect Scan) - Roteiro 4, Tecnologias Hacker.

Usa apenas a biblioteca padrao do Python. Para cada porta e feita uma tentativa
completa de conexao TCP (three-way handshake) com socket.connect(), e o resultado
e classificado em:

    ABERTA   -> conexao estabelecida (o SYN foi respondido com SYN/ACK)
    FECHADA  -> conexao recusada (o host respondeu com RST: ninguem escuta na porta)
    TIMEOUT  -> nenhuma resposta dentro do tempo limite (filtro, perda, host lento...)
    ERRO     -> outra condicao impediu a conexao (host/rede inalcancavel, etc.)

Melhorias implementadas (secao 7 do roteiro):
    1. Execucao concorrente com limite de tarefas (--workers)
    2. Exportacao dos resultados em JSON ou CSV (--output)
    3. Identificacao do servico *normalmente associado* a porta (getservbyport)
    4. Medicao de desempenho (tempo total e tempo de cada tentativa)
    5. Registro de execucao em arquivo de log (--log)

Uso etico: escaneie apenas sistemas proprios ou expressamente autorizados.
"""

import argparse
import csv
import errno
import ipaddress
import json
import logging
import re
import socket
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime

# Estados possiveis de uma porta
ABERTA = "ABERTA"
FECHADA = "FECHADA"
TIMEOUT = "TIMEOUT"
ERRO = "ERRO"

PORTA_MIN, PORTA_MAX = 1, 65535
MAX_PORTAS = 65535      # limite de portas por execucao
MAX_WORKERS = 200       # teto de tarefas simultaneas (evita carga excessiva)

log = logging.getLogger("portscanner")


# ---------------------------------------------------------------------------
# 1) Receber e validar os parametros
# ---------------------------------------------------------------------------
class ErroParametro(Exception):
    """Erro de validacao de parametro informado pelo usuario."""


def validar_porta(texto):
    """Converte o texto em numero de porta, garantindo que esteja em 1..65535."""
    texto = texto.strip()
    if not texto.isdigit():
        raise ErroParametro(f"porta invalida '{texto}': use apenas numeros inteiros.")
    porta = int(texto)
    if not PORTA_MIN <= porta <= PORTA_MAX:
        raise ErroParametro(f"porta invalida {porta}: deve estar entre {PORTA_MIN} e {PORTA_MAX}.")
    return porta


def interpretar_portas(especificacao):
    """
    Converte a especificacao de portas em uma lista ordenada e sem repeticao.
    Formatos aceitos (podem ser combinados com virgula): "80", "20-25", "22,80,8000-8010".
    """
    portas = set()
    for parte in especificacao.split(","):
        parte = parte.strip()
        if not parte:
            raise ErroParametro(f"lista de portas mal formada: '{especificacao}'.")
        if "-" in parte:
            limites = parte.split("-")
            if len(limites) != 2:
                raise ErroParametro(f"intervalo invalido '{parte}': use o formato INICIO-FIM.")
            inicio, fim = validar_porta(limites[0]), validar_porta(limites[1])
            if inicio > fim:
                raise ErroParametro(
                    f"intervalo invalido '{parte}': a porta inicial ({inicio}) "
                    f"e maior que a final ({fim}).")
            portas.update(range(inicio, fim + 1))
        else:
            portas.add(validar_porta(parte))
    if len(portas) > MAX_PORTAS:
        raise ErroParametro(f"muitas portas ({len(portas)}); o limite e {MAX_PORTAS}.")
    return sorted(portas)


def validar_timeout(valor):
    """Usado pelo argparse: timeout deve ser um numero > 0 e razoavel."""
    try:
        t = float(valor)
    except ValueError:
        raise argparse.ArgumentTypeError(f"timeout invalido '{valor}': informe um numero em segundos.")
    if not 0 < t <= 60:
        raise argparse.ArgumentTypeError(f"timeout invalido {t}: deve estar entre 0 (exclusivo) e 60 s.")
    return t


def validar_workers(valor):
    """Usado pelo argparse: numero de tarefas simultaneas entre 1 e MAX_WORKERS."""
    try:
        w = int(valor)
    except ValueError:
        raise argparse.ArgumentTypeError(f"workers invalido '{valor}': informe um inteiro.")
    if not 1 <= w <= MAX_WORKERS:
        raise argparse.ArgumentTypeError(f"workers invalido {w}: deve estar entre 1 e {MAX_WORKERS}.")
    return w


def resolver_destino(destino):
    """
    Resolve IP ou hostname para (familia, endereco_ip) usando getaddrinfo.
    Lanca ErroParametro se o nome nao puder ser resolvido.
    """
    if re.fullmatch(r"[0-9.]+", destino):
        # Parece um IPv4 (so digitos e pontos): valida antes de tentar resolver como nome.
        try:
            ipaddress.IPv4Address(destino)
        except ValueError:
            raise ErroParametro(f"destino invalido '{destino}': endereco IPv4 mal formado.")
    try:
        infos = socket.getaddrinfo(destino, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ErroParametro(f"destino invalido ou nao resolvido '{destino}': {e.strerror}.")
    except UnicodeError:
        raise ErroParametro(f"destino invalido '{destino}': nome mal formado.")
    # Prefere IPv4 quando houver; senao usa o primeiro endereco retornado.
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    familia, _, _, _, sockaddr = infos[0]
    return familia, sockaddr[0]


def criar_parser():
    p = argparse.ArgumentParser(
        prog="portscanner.py",
        description="Scanner de portas TCP (TCP Connect) usando apenas sockets da biblioteca padrao.",
        epilog="Exemplos:\n"
               "  python3 portscanner.py 127.0.0.1 -p 22\n"
               "  python3 portscanner.py localhost -p 1-1024 -t 0.5 -w 50\n"
               "  python3 portscanner.py 127.0.0.1 -p 22,80,8000-8010 -o resultado.json --log scan.log\n"
               "Use apenas contra sistemas proprios ou expressamente autorizados.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("destino", help="endereco IP (v4/v6) ou hostname do alvo")
    p.add_argument("-p", "--portas", default="1-1024",
                   help="porta unica, intervalo ou lista. Ex.: 80 | 20-25 | 22,80,8000-8010 (padrao: 1-1024)")
    p.add_argument("-t", "--timeout", type=validar_timeout, default=1.0,
                   help="tempo limite de cada tentativa de conexao, em segundos (padrao: 1.0)")
    p.add_argument("-w", "--workers", type=validar_workers, default=1,
                   help=f"numero de portas testadas simultaneamente, 1..{MAX_WORKERS} (padrao: 1 = sequencial)")
    p.add_argument("-a", "--todas", action="store_true",
                   help="mostrar todas as portas na tabela (por padrao, FECHADAS sao resumidas quando ha muitas)")
    p.add_argument("-o", "--output", metavar="ARQUIVO",
                   help="exportar resultados; o formato e definido pela extensao (.json ou .csv)")
    p.add_argument("--log", metavar="ARQUIVO",
                   help="gravar log da execucao (cada tentativa e erros) neste arquivo")
    return p


# ---------------------------------------------------------------------------
# 2) Realizar a tentativa de conexao  +  3) Interpretar o resultado
# ---------------------------------------------------------------------------
def tentar_conexao(familia, ip, porta, timeout):
    """
    Faz UMA tentativa de conexao TCP e devolve um dicionario com o resultado.

    - socket(familia, SOCK_STREAM) cria um socket TCP.
    - settimeout(t) faz connect() desistir apos t segundos sem resposta.
    - connect() executa o three-way handshake pelo sistema operacional.
    - O bloco 'with' garante o fechamento do socket (close) em qualquer caso,
      liberando o descritor e encerrando a conexao (FIN) quando ela foi aberta.
    """
    inicio = time.perf_counter()
    try:
        with socket.socket(familia, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, porta))
        estado, detalhe = ABERTA, "conexao estabelecida (handshake completo)"
    except Exception as exc:  # qualquer falha e classificada; nunca derruba o scan
        estado, detalhe = interpretar_erro(exc)
    duracao_ms = (time.perf_counter() - inicio) * 1000
    return {"porta": porta, "estado": estado, "detalhe": detalhe,
            "tempo_ms": round(duracao_ms, 2)}


def interpretar_erro(exc):
    """
    Traduz a excecao lancada por connect() em (estado, detalhe).
    A ORDEM importa: ConnectionRefusedError e TimeoutError sao subclasses de OSError.
    """
    if isinstance(exc, ConnectionRefusedError):
        return FECHADA, "conexao recusada (RST recebido)"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return TIMEOUT, "sem resposta dentro do tempo limite"
    if isinstance(exc, OSError):
        nome = errno.errorcode.get(exc.errno, "?") if exc.errno else "?"
        return ERRO, f"{nome}: {exc.strerror or exc}"
    return ERRO, f"{type(exc).__name__}: {exc}"


def servico_provavel(porta):
    """
    Nome do servico NORMALMENTE associado a porta (tabela /etc/services do SO).
    Isto NAO confirma o servico real: qualquer programa pode escutar em qualquer porta.

    Atencao: getservbyport() NAO e thread-safe na glibc (usa um buffer estatico).
    Chamada a partir de varias threads, devolveu nomes corrompidos nos testes
    (ex.: "# Local services" seguido de quebra de linha). Por isso so e chamada
    na thread principal, a medida que cada resultado chega, e o nome e higienizado.
    """
    try:
        nome = socket.getservbyport(porta, "tcp").strip()
    except OSError:
        return "-"
    if not nome or nome.startswith("#") or any(c.isspace() for c in nome):
        return "-"
    return nome


def escanear(familia, ip, portas, timeout, workers):
    """
    Testa todas as portas. Com workers > 1 usa um pool de threads de tamanho fixo,
    o que limita quantas conexoes ficam abertas ao mesmo tempo.
    Retorna (resultados, interrompido).
    """
    resultados = []
    interrompido = False
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        # Fila limitada: no maximo 2*workers tarefas submetidas por vez. Isso limita a
        # memoria e mantem barato o wait() abaixo (que percorre o conjunto pendente).
        fila = iter(portas)
        pendentes = set()
        while True:
            while len(pendentes) < 2 * workers:
                porta = next(fila, None)
                if porta is None:
                    break
                pendentes.add(pool.submit(tentar_conexao, familia, ip, porta, timeout))
            if not pendentes:
                break
            # wait() com timeout curto (em vez de bloquear indefinidamente) devolve o
            # controle a thread principal a cada 0,2 s, para que o Ctrl+C seja atendido
            # rapidamente tambem no Windows.
            prontos, pendentes = wait(pendentes, timeout=0.2, return_when=FIRST_COMPLETED)
            for fut in prontos:
                r = fut.result()
                r["servico_provavel"] = servico_provavel(r["porta"])  # so na thread principal
                resultados.append(r)
                log.info("porta=%d estado=%s tempo_ms=%.2f detalhe=%s",
                         r["porta"], r["estado"], r["tempo_ms"], r["detalhe"])
                if r["estado"] == ABERTA:
                    print(f"  [+] {r['porta']}/tcp ABERTA ({r['servico_provavel']})", flush=True)
    except KeyboardInterrupt:
        # Ctrl+C: cancela o que ainda nao comecou e mantem o que ja foi testado.
        interrompido = True
        log.warning("execucao interrompida pelo usuario (Ctrl+C)")
        pool.shutdown(wait=False, cancel_futures=True)
    else:
        pool.shutdown(wait=True)
    resultados.sort(key=lambda r: r["porta"])
    return resultados, interrompido


# ---------------------------------------------------------------------------
# 4) Registrar e apresentar as informacoes
# ---------------------------------------------------------------------------
def apresentar(destino, ip, portas, timeout, workers, resultados, duracao, interrompido, todas):
    contagem = {e: 0 for e in (ABERTA, FECHADA, TIMEOUT, ERRO)}
    for r in resultados:
        contagem[r["estado"]] += 1

    # Quando ha muitas portas, so lista as FECHADAS se o usuario pedir (-a).
    mostrar = [r for r in resultados if todas or len(resultados) <= 30 or r["estado"] != FECHADA]

    print()
    print(f"Destino: {destino} ({ip})   Portas solicitadas: {len(portas)}   "
          f"Timeout: {timeout}s   Workers: {workers}")
    print("-" * 92)
    print(f"{'DESTINO':<16} {'PORTA':>6}  {'ESTADO':<8} {'SERVICO PROVAVEL*':<18} {'TEMPO(ms)':>9}  DETALHE")
    print("-" * 92)
    for r in mostrar:
        print(f"{ip:<16} {r['porta']:>6}  {r['estado']:<8} {r['servico_provavel']:<18} "
              f"{r['tempo_ms']:>9.2f}  {r['detalhe']}")
    if len(mostrar) < len(resultados):
        print(f"  ... {len(resultados) - len(mostrar)} portas FECHADAS omitidas (use -a para listar todas)")
    print("-" * 92)
    print(f"Resumo: {contagem[ABERTA]} aberta(s), {contagem[FECHADA]} fechada(s), "
          f"{contagem[TIMEOUT]} timeout(s), {contagem[ERRO]} erro(s) "
          f"- {len(resultados)} de {len(portas)} porta(s) testada(s) em {duracao:.3f} s")
    if interrompido:
        print("ATENCAO: varredura interrompida pelo usuario; resultados PARCIAIS.")
    print("* servico normalmente associado a porta (/etc/services); nao confirma o servico real.")
    return contagem


def exportar(caminho, meta, resultados):
    """Salva os resultados em JSON ou CSV conforme a extensao do arquivo."""
    if caminho.lower().endswith(".json"):
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump({"metadados": meta, "resultados": resultados}, f, indent=2, ensure_ascii=False)
    elif caminho.lower().endswith(".csv"):
        with open(caminho, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["destino", "ip", "porta", "estado",
                                              "servico_provavel", "tempo_ms", "detalhe", "inicio"])
            w.writeheader()
            for r in resultados:
                w.writerow({"destino": meta["destino"], "ip": meta["ip"],
                            "inicio": meta["inicio"], **r})
    else:
        raise ErroParametro("formato de exportacao desconhecido: use extensao .json ou .csv.")
    print(f"Resultados exportados para {caminho}")


def configurar_log(caminho):
    if not caminho:
        log.addHandler(logging.NullHandler())
        return
    h = logging.FileHandler(caminho, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(h)
    log.setLevel(logging.INFO)


def main(argv=None):
    args = criar_parser().parse_args(argv)  # argparse ja trata timeout/workers invalidos (saida 2)
    try:
        configurar_log(args.log)
        portas = interpretar_portas(args.portas)
        if args.output and not args.output.lower().endswith((".json", ".csv")):
            raise ErroParametro("formato de exportacao desconhecido: use extensao .json ou .csv.")
        familia, ip = resolver_destino(args.destino)
    except ErroParametro as e:
        print(f"Erro: {e}", file=sys.stderr)
        log.error("parametro invalido: %s", e)
        return 2
    except OSError as e:
        print(f"Erro: nao foi possivel abrir o arquivo de log: {e}", file=sys.stderr)
        return 2

    workers = min(args.workers, len(portas))
    inicio_iso = datetime.now().isoformat(timespec="seconds")
    print(f"Iniciando varredura TCP Connect em {args.destino} ({ip}) - {inicio_iso}")
    log.info("inicio destino=%s ip=%s portas=%s timeout=%s workers=%d",
             args.destino, ip, args.portas, args.timeout, workers)

    t0 = time.perf_counter()
    resultados, interrompido = escanear(familia, ip, portas, args.timeout, workers)
    duracao = time.perf_counter() - t0

    contagem = apresentar(args.destino, ip, portas, args.timeout, workers,
                          resultados, duracao, interrompido, args.todas)
    log.info("fim duracao_s=%.3f contagem=%s interrompido=%s", duracao, contagem, interrompido)

    if args.output:
        meta = {"destino": args.destino, "ip": ip, "inicio": inicio_iso,
                "portas_solicitadas": args.portas, "timeout_s": args.timeout,
                "workers": workers, "duracao_s": round(duracao, 3),
                "interrompido": interrompido, "contagem": contagem}
        try:
            exportar(args.output, meta, resultados)
        except (OSError, csv.Error, ValueError) as e:
            print(f"Erro ao exportar resultados: {e}", file=sys.stderr)
            return 1
    return 130 if interrompido else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Ctrl+C fora da varredura (ex.: durante a resolucao do nome)
        print("\nInterrompido pelo usuario.", file=sys.stderr)
        sys.exit(130)

#!/usr/bin/env python3
"""
servico_tcp.py - servico TCP minimo para o ambiente de teste do Roteiro 4.

Escuta em 0.0.0.0:<porta>, envia um banner e fecha a conexao. Serve para
ligar/desligar um servico controlado durante os testes e a demonstracao.

Uso: python3 lab/servico_tcp.py 2222        (Ctrl+C para encerrar)
"""
import socket
import sys

porta = int(sys.argv[1]) if len(sys.argv) > 1 else 2222

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", porta))
    srv.listen(50)
    print(f"servico_tcp escutando em 0.0.0.0:{porta}", flush=True)
    try:
        while True:
            conn, addr = srv.accept()
            with conn:
                try:
                    conn.sendall(b"ROTEIRO4-SERVICO-TESTE\r\n")
                except OSError:
                    pass  # o scanner fecha a conexao logo apos o handshake
    except KeyboardInterrupt:
        print("servico_tcp encerrado", flush=True)

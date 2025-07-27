from collections import defaultdict, deque
from datetime import datetime, timedelta
import time
import random
import re
import os
import threading
import subprocess
import platform
import json
import statistics
import webbrowser # Nova importação para abrir o navegador

# --- Flask e SocketIO para o Dashboard ---
from flask import Flask, render_template_string
from flask_socketio import SocketIO, emit

# --- Parâmetros da detecção ---
TIME_WINDOW = 10
ALERTA_COOLDOWN = 15
BLOCK_DURATION = 50
REPORT_INTERVAL = 60
DASHBOARD_UPDATE_INTERVAL = 2

# --- Parâmetros de Machine Learning Simples ---
HISTORY_WINDOW_SIZE = 60
STD_DEV_MULTIPLIER = 3.0
MIN_HISTORY_POINTS = 5

# --- Arquivos de Log e Relatório ---
LOG_FILE = "access.log"
ALERT_LOG_FILE = "logs_alertas.txt"
REPORT_DIR = "reports"

# --- Estruturas de Dados Globais ---
ip_requests = defaultdict(lambda: deque())
ultimo_alerta = dict()
bloqueados = {}
ip_historical_rates = defaultdict(lambda: deque(maxlen=HISTORY_WINDOW_SIZE))
last_history_update = defaultdict(lambda: datetime.min)

# --- Inicialização do Flask e SocketIO ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'uma_chave_secreta_muito_segura'
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Funções de Simulação ---
def simula_requisicao():
    ip_pool = [
        '192.168.1.1', '192.168.1.2', '192.168.1.3',
        '10.0.0.5', '10.0.0.6', '10.0.0.7',
        '172.16.0.10', '172.16.0.11', '172.16.0.12',
        '200.200.200.200',
        '201.201.201.201'
    ]
    return random.choices(ip_pool, weights=[1, 1, 1, 1, 2, 1, 2, 1, 3, 10, 8])[0]

def simula_log_web():
    ip = simula_requisicao()
    now = datetime.now()
    log_line = f'{ip} - - [{now.strftime("%d/%b/%Y:%H:%M:%S -0300")}] "GET /index.html HTTP/1.1" 200 1234\n'
    with open(LOG_FILE, "a") as f:
        f.write(log_line)

# --- Funções de Detecção e Ação (Multi-plataforma) ---
def block_ip_firewall(ip):
    rule_name = f"block-ddos-{ip}"
    if platform.system() == "Windows":
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"
        ]
        system_name = "Firewall do Windows"
    else:
        command = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
        system_name = "iptables"

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"[{system_name}] IP {ip} BLOQUEADO. Saída: {result.stdout.strip()}")
        bloqueados[ip] = datetime.now()
        socketio.emit('blocked_ips_update', get_blocked_ips_data())
        return True
    except subprocess.CalledProcessError as e:
        print(f"[{system_name}] ERRO ao bloquear IP {ip}: {e.stderr.strip()}")
        print(f"[{system_name}] Comando: {' '.join(command)}")
        print(f"Certifique-se de que o script está sendo executado com permissões de administrador/root.")
        return False
    except FileNotFoundError:
        print(f"[{system_name}] ERRO: Comando '{command[0]}' não encontrado. Verifique sua instalação.")
        return False

def unblock_ip_firewall(ip):
    rule_name = f"block-ddos-{ip}"
    if platform.system() == "Windows":
        command = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        system_name = "Firewall do Windows"
    else:
        command = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
        system_name = "iptables"

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"[{system_name}] IP {ip} DESBLOQUEADO. Saída: {result.stdout.strip()}")
        socketio.emit('blocked_ips_update', get_blocked_ips_data())
        return True
    except subprocess.CalledProcessError as e:
        if "No rules match the specified criteria." in e.stderr or "No matching rule" in e.stderr:
             pass
        else:
            print(f"[{system_name}] ERRO ao tentar desbloquear IP {ip}: {e.stderr.strip()}")
            print(f"[{system_name}] Comando: {' '.join(command)}")
            print(f"Certifique-se de que o script está sendo executado com permissões de administrador/root.")
        return False
    except FileNotFoundError:
        print(f"[{system_name}] ERRO: Comando '{command[0]}' não encontrado. Verifique sua instalação.")
        return False

def gerencia_bloqueios():
    now = datetime.now()
    ips_a_desbloquear = []
    for ip, block_time in list(bloqueados.items()):
        if (now - block_time).total_seconds() > BLOCK_DURATION:
            ips_a_desbloquear.append(ip)

    for ip in ips_a_desbloquear:
        if unblock_ip_firewall(ip):
            del bloqueados[ip]


def registra_requisicao(ip, timestamp=None):
    now = timestamp if timestamp else datetime.now()

    if ip in bloqueados and (now - bloqueados[ip]).total_seconds() < BLOCK_DURATION:
        return

    fila = ip_requests[ip]
    fila.append(now)

    while fila and (now - fila[0]).total_seconds() > TIME_WINDOW:
        fila.popleft()

    current_requests_in_window = len(fila)

    if (now - last_history_update[ip]).total_seconds() >= TIME_WINDOW:
        ip_historical_rates[ip].append(current_requests_in_window)
        last_history_update[ip] = now

    if len(ip_historical_rates[ip]) >= MIN_HISTORY_POINTS:
        mean_rate = statistics.mean(ip_historical_rates[ip])
        stdev_rate = statistics.stdev(ip_historical_rates[ip]) if len(ip_historical_rates[ip]) > 1 else 0

        dynamic_threshold = mean_rate + (STD_DEV_MULTIPLIER * stdev_rate)
        dynamic_threshold = max(1, dynamic_threshold)

        if current_requests_in_window > dynamic_threshold:
            ultimo = ultimo_alerta.get(ip)
            if not ultimo or (now - ultimo).total_seconds() > ALERTA_COOLDOWN:
                mensagem = (
                    f"[{now.strftime('%H:%M:%S')}] ALERTA ML: Possível DDoS do IP {ip} - "
                    f"{current_requests_in_window} requisições em {TIME_WINDOW}s "
                    f"(Limiar Dinâmico: {dynamic_threshold:.2f} - Média: {mean_rate:.2f}, DP: {stdev_rate:.2f})"
                )
                print(mensagem)
                with open(ALERT_LOG_FILE, "a") as f:
                    f.write(f"{now.isoformat()} - IP: {ip} - {current_requests_in_window} reqs em {TIME_WINDOW}s (ML)\n")
                ultimo_alerta[ip] = now

                if ip not in bloqueados:
                    print(f"[{now.strftime('%H:%M:%S')}] TENTANDO BLOQUEAR IP: {ip}...")
                    block_ip_firewall(ip)
    else:
        if current_requests_in_window > 100:
             ultimo = ultimo_alerta.get(ip)
             if not ultimo or (now - ultimo).total_seconds() > ALERTA_COOLDOWN:
                mensagem = (
                    f"[{now.strftime('%H:%M:%S')}] ALERTA INICIAL: Possível DDoS do IP {ip} - "
                    f"{current_requests_in_window} requisições em {TIME_WINDOW}s "
                    f"(Aprendendo comportamento - {len(ip_historical_rates[ip])}/{MIN_HISTORY_POINTS} pontos)"
                )
                print(mensagem)
                with open(ALERT_LOG_FILE, "a") as f:
                    f.write(f"{now.isoformat()} - IP: {ip} - {current_requests_in_window} reqs em {TIME_WINDOW}s (INICIAL)\n")
                ultimo_alerta[ip] = now

                if ip not in bloqueados:
                    print(f"[{now.strftime('%H:%M:%S')}] TENTANDO BLOQUEAR IP: {ip}...")
                    block_ip_firewall(ip)


def processa_log_line(log_line):
    match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] ".*?" \d+ \d+', log_line)
    if match:
        ip = match.group(1)
        timestamp_str = match.group(2)
        try:
            timestamp = datetime.strptime(timestamp_str.split(' ')[0], '%d/%b/%Y:%H:%M:%S')
            registra_requisicao(ip, timestamp)
        except ValueError:
            print(f"Erro ao parsear timestamp na linha: {log_line.strip()}")

def monitora_log_web():
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()

    with open(LOG_FILE, "r", encoding='utf-8') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            processa_log_line(line)

# --- Funções de Geração de Relatórios ---
def gerar_relatorio_json():
    report_data = {
        "timestamp_geracao": datetime.now().isoformat(),
        "ips_ativos_na_janela": [],
        "ips_bloqueados": [],
        "alertas_historico": [],
        "parametros_ml": {
            "history_window_size": HISTORY_WINDOW_SIZE,
            "std_dev_multiplier": STD_DEV_MULTIPLIER,
            "min_history_points": MIN_HISTORY_POINTS
        },
        "parametros_gerais": {
            "time_window": TIME_WINDOW,
            "block_duration": BLOCK_DURATION,
            "alerta_cooldown": ALERTA_COOLDOWN
        }
    }

    ips_ativos_list = sorted(
        [(ip, len(timestamps)) for ip, timestamps in ip_requests.items()],
        key=lambda item: item[1],
        reverse=True
    )
    report_data["ips_ativos_na_janela"] = [{"ip": ip, "requisições_na_janela": count} for ip, count in ips_ativos_list if count > 0]

    for ip, block_time in bloqueados.items():
        report_data["ips_bloqueados"].append({
            "ip": ip,
            "hora_bloqueio": block_time.isoformat(),
            "tempo_restante_segundos": max(0, BLOCK_DURATION - (datetime.now() - block_time).total_seconds())
        })

    if os.path.exists(ALERT_LOG_FILE):
        with open(ALERT_LOG_FILE, "r", encoding='utf-8') as f:
            for line in f:
                try:
                    match = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) - IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (\d+) reqs em (\d+)s \((ML|INICIAL|FIXO)\)', line)
                    if match:
                        report_data["alertas_historico"].append({
                            "timestamp": match.group(1),
                            "ip": match.group(2),
                            "requisicoes": int(match.group(3)),
                            "janela_tempo_segundos": int(match.group(4)),
                            "tipo_alerta": match.group(5)
                        })
                    else:
                        match_old = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) - IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (\d+) reqs em (\d+)s', line)
                        if match_old:
                            report_data["alertas_historico"].append({
                                "timestamp": match_old.group(1),
                                "ip": match_old.group(2),
                                "requisicoes": int(match_old.group(3)),
                                "janela_tempo_segundos": int(match_old.group(4)),
                                "tipo_alerta": "FIXO"
                            })

                except Exception as e:
                    print(f"Erro ao parsear linha de alerta: {line.strip()} - {e}")

    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = datetime.now().strftime("report_%Y%m%d_%H%M%S.json")
    filepath = os.path.join(REPORT_DIR, filename)
    with open(filepath, "w", encoding='utf-8') as f:
        json.dump(report_data, f, indent=4, ensure_ascii=False)
    print(f"[RELATÓRIO] Relatório JSON gerado: {filepath}")

def gerar_relatorio_html():
    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Relatório de Detecção de DDoS</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #e8f5e9; color: #333; line-height: 1.6; }}
            .container {{ max-width: 960px; margin: auto; background: #ffffff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            h1, h2 {{ color: #2e7d32; border-bottom: 2px solid #a5d6a7; padding-bottom: 10px; margin-top: 25px; }}
            h1 {{ text-align: center; color: #1b5e20; }}
            p {{ margin-bottom: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; background-color: #ffffff; }}
            th, td {{ padding: 12px 15px; border: 1px solid #c8e6c9; text-align: left; }}
            th {{ background-color: #4caf50; color: white; font-weight: bold; }}
            tr:nth-child(even) {{ background-color: #f0f4c3; }}
            tr:hover {{ background-color: #e0e0e0; cursor: pointer; }}
            .alert-item {{ background-color: #fff9c4; margin-bottom: 8px; padding: 12px; border-left: 6px solid #fbc02d; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }}
            .blocked-ip-item {{ background-color: #ffcdd2; margin-bottom: 8px; padding: 12px; border-left: 6px solid #d32f2f; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }}
            .info-box {{ background-color: #c8e6c9; padding: 15px; border-radius: 8px; margin-bottom: 25px; border: 1px solid #a5d6a7; }}
            .footer {{ text-align: center; margin-top: 30px; font-size: 0.9em; color: #757575; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Relatório de Detecção de DDoS</h1>
            <p><strong>Gerado em:</strong> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>

            <div class="info-box">
                <p>Este relatório apresenta um resumo das requisições, IPs ativos, IPs bloqueados e histórico de alertas detectados pelo sistema de monitoramento de DDoS.</p>
                <p><strong>Parâmetros de Detecção Atuais:</strong><br>
                Janela de Tempo para Contagem: {TIME_WINDOW} segundos<br>
                Duração do Bloqueio: {BLOCK_DURATION} segundos</p>
                <p><strong>Parâmetros de Machine Learning:</strong><br>
                Janela de Histórico: {HISTORY_WINDOW_SIZE} pontos<br>
                Multiplicador do Desvio Padrão: {STD_DEV_MULTIPLIER}<br>
                Mínimo de Pontos para ML: {MIN_HISTORY_POINTS}</p>
            </div>

            <h2>IPs Mais Ativos na Janela Atual ({TIME_WINDOW}s)</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Requisições na Janela</th>
                    </tr>
                </thead>
                <tbody>
    """

    ips_ativos_list = sorted(
        [(ip, len(timestamps)) for ip, timestamps in ip_requests.items()],
        key=lambda item: item[1],
        reverse=True
    )
    for ip, count in ips_ativos_list:
        if count > 0:
            html_content += f"""
                    <tr>
                        <td>{ip}</td>
                        <td>{count}</td>
                    </tr>
            """
    if not any(count > 0 for _, count in ips_ativos_list):
        html_content += """
                    <tr>
                        <td colspan="2">Nenhum IP ativo na janela atual.</td>
                    </tr>
        """
    html_content += """
                </tbody>
            </table>

            <h2>IPs Atualmente Bloqueados</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Hora do Bloqueio</th>
                        <th>Tempo Restante (segundos)</th>
                    </tr>
                </thead>
                <tbody>
    """
    if bloqueados:
        for ip, block_time in bloqueados.items():
            time_remaining = max(0, BLOCK_DURATION - (datetime.now() - block_time).total_seconds())
            html_content += f"""
                    <tr class="blocked-ip-item">
                        <td>{ip}</td>
                        <td>{block_time.strftime('%d/%m/%Y %H:%M:%S')}</td>
                        <td>{int(time_remaining)}</td>
                    </tr>
            """
    else:
        html_content += """
                    <tr>
                        <td colspan="3">Nenhum IP bloqueado atualmente.</td>
                    </tr>
        """
    html_content += """
                </tbody>
            </table>

            <h2>Histórico de Alertas de DDoS</h2>
            <div>
    """
    if os.path.exists(ALERT_LOG_FILE):
        with open(ALERT_LOG_FILE, "r", encoding='utf-8') as f:
            alerts_found = False
            for line in f:
                match = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) - IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (\d+) reqs em (\d+)s \((ML|INICIAL|FIXO)\)', line)
                if match:
                    timestamp_alert = datetime.fromisoformat(match.group(1)).strftime('%d/%m/%Y %H:%M:%S')
                    alert_type = match.group(5)
                    html_content += f"""
                        <div class="alert-item">
                            <strong>Horário:</strong> {timestamp_alert}<br>
                            <strong>IP Malicioso:</strong> {match.group(2)}<br>
                            <strong>Requisições:</strong> {match.group(3)} em {match.group(4)}s<br>
                            <strong>Tipo de Alerta:</strong> {alert_type}
                        </div>
                    """
                    alerts_found = True
                else:
                    match_old = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) - IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (\d+) reqs em (\d+)s', line)
                    if match_old:
                        timestamp_alert = datetime.fromisoformat(match_old.group(1)).strftime('%d/%m/%Y %H:%M:%S')
                        html_content += f"""
                            <div class="alert-item">
                                <strong>Horário:</strong> {timestamp_alert}<br>
                                <strong>IP Malicioso:</strong> {match_old.group(2)}<br>
                                <strong>Requisições:</strong> {match_old.group(3)} em {match_old.group(4)}s<br>
                                <strong>Tipo de Alerta:</strong> FIXO (Legado)
                            </div>
                        """
                        alerts_found = True

            if not alerts_found:
                html_content += "<p>Nenhum alerta de DDoS registrado até o momento.</p>"
    else:
        html_content += "<p>Nenhum arquivo de log de alertas encontrado.</p>"

    html_content += """
            </div>
            <div class="footer">
                <p>Detector de DDoS Simulado - Projeto Acadêmico</p>
            </div>
        </div>
    </body>
    </html>
    """

    os.makedirs(REPORT_DIR, exist_ok=True)
    filename = datetime.now().strftime("report_%Y%m%d_%H%M%S.html")
    filepath = os.path.join(REPORT_DIR, filename)
    with open(filepath, "w", encoding='utf-8') as f:
        f.write(html_content)

# --- Funções de Dados para o Dashboard ---
def get_active_ips_data():
    active_ips_list = sorted(
        [(ip, len(timestamps)) for ip, timestamps in ip_requests.items()],
        key=lambda item: item[1],
        reverse=True
    )
    return [{"ip": ip, "count": count} for ip, count in active_ips_list if count > 0][:10]

def get_blocked_ips_data():
    blocked_ips_data = []
    for ip, block_time in list(bloqueados.items()):
        time_remaining = max(0, BLOCK_DURATION - (datetime.now() - block_time).total_seconds())
        blocked_ips_data.append({
            "ip": ip,
            "blocked_at": block_time.strftime('%H:%M:%S'),
            "time_remaining": int(time_remaining)
        })
    return blocked_ips_data

def get_recent_alerts_data(num_alerts=10):
    recent_alerts = []
    if os.path.exists(ALERT_LOG_FILE):
        with open(ALERT_LOG_FILE, "r", encoding='utf-8') as f:
            lines = f.readlines()
            for line in reversed(lines):
                if len(recent_alerts) >= num_alerts:
                    break
                match = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) - IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (\d+) reqs em (\d+)s \((ML|INICIAL|FIXO)\)', line)
                if match:
                    recent_alerts.append({
                        "timestamp": datetime.fromisoformat(match.group(1)).strftime('%H:%M:%S'),
                        "ip": match.group(2),
                        "requests": int(match.group(3)),
                        "type": match.group(5)
                    })
                else:
                    match_old = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+) - IP: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (\d+) reqs em (\d+)s', line)
                    if match_old:
                        recent_alerts.append({
                            "timestamp": datetime.fromisoformat(match_old.group(1)).strftime('%H:%M:%S'),
                            "ip": match_old.group(2),
                            "requests": int(match_old.group(3)),
                            "type": "FIXO (Legado)"
                        })
    return recent_alerts

@app.route('/')
def index():
    html_dashboard_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DDoS Detector Dashboard</title>
        <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #f0f2f5; color: #333; }}
            .header {{ background-color: #2e7d32; color: white; padding: 20px 0; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .header h1 {{ margin: 0; font-size: 2.5em; }}
            .container {{ display: flex; flex-wrap: wrap; justify-content: space-around; padding: 20px; }}
            .card {{ background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); margin: 15px; padding: 25px; flex: 1 1 calc(33% - 60px); min-width: 300px; }}
            .card.full-width {{ flex: 1 1 calc(100% - 60px); }}
            .card h2 {{ color: #2e7d32; margin-top: 0; border-bottom: 1px solid #e0e0e0; padding-bottom: 10px; }}
            .card ul {{ list-style: none; padding: 0; }}
            .card li {{ padding: 8px 0; border-bottom: 1px dashed #eee; display: flex; justify-content: space-between; align-items: center; }}
            .card li:last-child {{ border-bottom: none; }}
            .badge {{ background-color: #4caf50; color: white; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; }}
            .badge.alert {{ background-color: #ff9800; }}
            .badge.blocked {{ background-color: #f44336; }}
            .param {{ font-weight: bold; color: #555; }}
            .alert-log-item {{ background-color: #fff9c4; margin-bottom: 5px; padding: 10px; border-left: 5px solid #fbc02d; border-radius: 4px; font-size: 0.9em; }}
            .blocked-log-item {{ background-color: #ffcdd2; margin-bottom: 5px; padding: 10px; border-left: 5px solid #d32f2f; border-radius: 4px; font-size: 0.9em; }}
            canvas {{ max-width: 100%; height: auto; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ DDoS Detector Dashboard 🛡️</h1>
        </div>
        <div class="container">
            <div class="card">
                <h2>Parâmetros do Sistema</h2>
                <ul>
                    <li><span class="param">Janela de Tempo:</span> {TIME_WINDOW}s</li>
                    <li><span class="param">Duração do Bloqueio:</span> {BLOCK_DURATION}s</li>
                    <li><span class="param">Cooldwon de Alerta:</span> {ALERTA_COOLDOWN}s</li>
                </ul>
                <h2>Parâmetros ML</h2>
                <ul>
                    <li><span class="param">Janela de Histórico:</span> {HISTORY_WINDOW_SIZE} pontos</li>
                    <li><span class="param">Multiplicador DP:</span> {STD_DEV_MULTIPLIER}</li>
                    <li><span class="param">Mín. Pontos Histórico:</span> {MIN_HISTORY_POINTS}</li>
                </ul>
            </div>

            <div class="card full-width">
                <h2>Top IPs Ativos por Requisições</h2>
                <canvas id="activeIpsChart"></canvas>
            </div>

            <div class="card">
                <h2>IPs Atualmente Bloqueados</h2>
                <ul id="blocked-ips-list">
                    <li>Nenhum IP bloqueado.</li>
                </ul>
            </div>

            <div class="card full-width">
                <h2>Histórico de Alertas Recentes</h2>
                <div id="recent-alerts-list">
                    <p>Nenhum alerta recente.</p>
                </div>
            </div>

        </div>

        <script>
            var socket = io.connect('http://' + document.domain + ':' + location.port);
            var activeIpsChart;

            socket.on('connect', function() {{
                console.log('Conectado ao servidor SocketIO!');
            }});

            socket.on('update_dashboard', function(data) {{
                updateActiveIpsChart(data.active_ips);

                var blockedIpsList = document.getElementById('blocked-ips-list');
                blockedIpsList.innerHTML = '';
                if (data.blocked_ips && data.blocked_ips.length > 0) {{
                    data.blocked_ips.forEach(function(item) {{
                        var li = document.createElement('li');
                        li.className = 'blocked-log-item';
                        li.innerHTML = `<strong>${{item.ip}}</strong> (Bloqueado às ${{item.blocked_at}}, Restam ${{item.time_remaining}}s)`;
                        blockedIpsList.appendChild(li);
                    }});
                }} else {{
                    blockedIpsList.innerHTML = '<li>Nenhum IP bloqueado.</li>';
                }}

                var recentAlertsList = document.getElementById('recent-alerts-list');
                recentAlertsList.innerHTML = '';
                if (data.recent_alerts && data.recent_alerts.length > 0) {{
                    data.recent_alerts.forEach(function(item) {{
                        var div = document.createElement('div');
                        div.className = 'alert-log-item';
                        div.innerHTML = `<strong>[${{item.timestamp}}]</strong> IP: ${{item.ip}} - ${{item.requests}} reqs (${{item.type}})`;
                        recentAlertsList.appendChild(div);
                    }});
                }} else {{
                    recentAlertsList.innerHTML = '<p>Nenhum alerta recente.</p>';
                }}
            }});

            function updateActiveIpsChart(activeIps) {{
                const labels = activeIps.map(item => item.ip);
                const dataPoints = activeIps.map(item => item.count);

                if (activeIpsChart) {{
                    activeIpsChart.data.labels = labels;
                    activeIpsChart.data.datasets[0].data = dataPoints;
                    activeIpsChart.update();
                }} else {{
                    const ctx = document.getElementById('activeIpsChart').getContext('2d');
                    activeIpsChart = new Chart(ctx, {{
                        type: 'bar',
                        data: {{
                            labels: labels,
                            datasets: [{{
                                label: 'Requisições na Janela',
                                data: dataPoints,
                                backgroundColor: 'rgba(75, 192, 192, 0.6)',
                                borderColor: 'rgba(75, 192, 192, 1)',
                                borderWidth: 1
                            }}]
                        }},
                        options: {{
                            responsive: true,
                            scales: {{
                                y: {{
                                    beginAtZero: true,
                                    title: {{
                                        display: true,
                                        text: 'Número de Requisições'
                                    }}
                                }},
                                x: {{
                                    title: {{
                                        display: true,
                                        text: 'Endereço IP'
                                    }}
                                }}
                            }},
                            plugins: {{
                                legend: {{
                                    display: false
                                }}
                            }}
                        }}
                    }});
                }}
            }}
        </script>
    </body>
    </html>
    """
    return render_template_string(html_dashboard_content)

def emit_dashboard_data():
    with app.app_context():
        while True:
            data = {
                "active_ips": get_active_ips_data(),
                "blocked_ips": get_blocked_ips_data(),
                "recent_alerts": get_recent_alerts_data()
            }
            socketio.emit('update_dashboard', data)
            time.sleep(DASHBOARD_UPDATE_INTERVAL)

# --- Função Principal ---
def main():
    dashboard_url = "http://127.0.0.1:5000/"
    print("Iniciando monitoramento de tráfego DDoS com bloqueio automático e relatórios...\n")
    print(f"**Dashboard disponível em: {dashboard_url}**")
    print("(Pressione Ctrl+C para encerrar)\n")

    # Abre o dashboard automaticamente no navegador padrão
    try:
        webbrowser.open(dashboard_url)
    except Exception as e:
        print(f"Não foi possível abrir o navegador automaticamente: {e}")

    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
    if os.path.exists(ALERT_LOG_FILE):
        os.remove(ALERT_LOG_FILE)

    print("Limpando regras de firewall anteriores (se existirem)...")
    if platform.system() == "Windows":
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", "name=all", "dir=in", "action=block"],
                capture_output=True, text=True, check=False
            )
            print("Regras 'block-ddos-*' removidas no Windows.")
        except Exception as e:
            print(f"Erro ao tentar limpar regras de firewall no Windows: {e}")
    else:
        pass

    os.makedirs(REPORT_DIR, exist_ok=True)

    # --- Threads para Operações Simultâneas ---
    sim_req_thread = threading.Thread(target=lambda: [registra_requisicao(simula_requisicao()) or time.sleep(0.015) for _ in iter(int, 1)])
    sim_req_thread.daemon = True
    sim_req_thread.start()

    log_write_thread = threading.Thread(target=lambda: [simula_log_web() or time.sleep(0.01) for _ in iter(int, 1)])
    log_write_thread.daemon = True
    log_write_thread.start()

    log_monitor_thread = threading.Thread(target=monitora_log_web)
    log_monitor_thread.daemon = True
    log_monitor_thread.start()

    block_manager_thread = threading.Thread(target=lambda: [gerencia_bloqueios() or time.sleep(1) for _ in iter(int, 1)])
    block_manager_thread.daemon = True
    block_manager_thread.start()

    report_generator_thread = threading.Thread(target=lambda: [gerar_relatorio_json() or gerar_relatorio_html() or time.sleep(REPORT_INTERVAL) for _ in iter(int, 1)])
    report_generator_thread.daemon = True
    report_generator_thread.start()

    dashboard_emitter_thread = threading.Thread(target=emit_dashboard_data)
    dashboard_emitter_thread.daemon = True
    dashboard_emitter_thread.start()

    try:
        socketio.run(app, debug=False, allow_unsafe_werkzeug=True, port=5000, host='0.0.0.0')
    except KeyboardInterrupt:
        print("\nMonitoramento encerrado.")
    finally:
        print("Gerando relatório final...")
        gerar_relatorio_json()
        gerar_relatorio_html()

        print("Tentando desbloquear IPs restantes...")
        for ip in list(bloqueados.keys()):
            unblock_ip_firewall(ip)
        print("Limpeza final de regras de firewall concluída.")


if __name__ == "__main__":
    print("AVISO: Este script precisa de permissões de administrador no Windows ou root no Linux.")
    print("Execute o prompt de comando/PowerShell como administrador (Windows) ou com 'sudo python3 seu_script.py' (Linux).\n")
    main()
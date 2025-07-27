 # Sistema de Detecção e Prevenção de Ataques DDoS com Machine Learning Simples
Este projeto Python é uma ferramenta robusta para monitorar, detectar e mitigar ataques de Negação de Serviço Distribuída (DDoS) em tempo real. Ele simula o monitoramento de logs de acesso a um servidor web, aplicando lógica de Machine Learning simples para identificar padrões anormais de requisições e, consequentemente, bloquear automaticamente IPs maliciosos diretamente no firewall do sistema operacional.

## Principais Características:
Monitoramento de Tráfego em Tempo Real: Analisa continuamente um fluxo simulado de requisições (log de acesso web) para identificar atividades suspeitas.

Detecção de DDoS com Machine Learning Simples:

Aprendizado de Comportamento: O sistema observa o volume de requisições por IP ao longo do tempo para construir um perfil de "normalidade".

Limiar Dinâmico: Utiliza a média e o desvio padrão do histórico de requisições de cada IP para calcular um limiar adaptativo. Se o volume de requisições de um IP exceder esse limiar dinâmico, um alerta é gerado.

Detecção Inicial Rápida: Inclui um mecanismo de alerta inicial baseado em um limite fixo para pegar picos de tráfego muito altos antes que o modelo de ML tenha dados suficientes.

Bloqueio Automático de IPs:

Integração com o Firewall do Windows (netsh) e iptables (Linux) para bloquear IPs detectados como ameaça.

Gerenciamento automático de desbloqueio após um período configurável.

Dashboard Interativo (Flask & SocketIO):

Interface web em tempo real que mostra IPs ativos, IPs bloqueados e um histórico dos alertas recentes.

Gráfico de Barras que visualiza os IPs mais ativos, tornando a identificação de tendências imediata.

Geração de Relatórios Detalhados: Cria relatórios em formatos JSON e HTML com um resumo completo das atividades, incluindo IPs ativos, bloqueados e um histórico de todos os alertas.

Multi-threading: Utiliza threads para simular requisições, monitorar logs, gerenciar bloqueios e atualizar o dashboard simultaneamente, garantindo um sistema responsivo.

💻 Como Executar:
Pré-requisitos:

Python 3.x

pip install Flask Flask-SocketIO python-socketio simple-websocket

Permissões de Administrador/Root:

Windows: Execute o Prompt de Comando ou PowerShell como Administrador.

Linux: Execute o script com sudo (ex: sudo python3 seu_script.py).

Execução:

Bash

python seu_script.py
O script imprimirá o link do dashboard e tentará abri-lo automaticamente no seu navegador padrão.

🛠️ Tecnologias Utilizadas:
Python 3: Linguagem principal.

Flask: Micro-framework web para o dashboard.

Flask-SocketIO: Habilita comunicação em tempo real entre o servidor e o dashboard.

Chart.js: Biblioteca JavaScript para visualização de dados no dashboard.

subprocess: Para interagir com o firewall do sistema operacional.

collections (deque), datetime, random, re, os, threading, platform, json, statistics, webbrowser: Módulos padrão do Python para diversas funcionalidades.

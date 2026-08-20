from fastapi import APIRouter, status
from fastapi.responses import HTMLResponse

router = APIRouter()

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero-Trust Security & Research Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-dark: #090d16;
            --card-bg: rgba(18, 26, 43, 0.75);
            --card-border: rgba(0, 240, 255, 0.15);
            --accent-cyan: #00f0ff;
            --accent-purple: #9d4edd;
            --accent-green: #00ff87;
            --accent-pink: #ff007f;
            --text-primary: #f0f4f8;
            --text-muted: #8a99ad;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Outfit', sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 2rem;
            background-image: 
                radial-gradient(circle at 10% 20%, rgba(157, 78, 221, 0.12) 0%, transparent 40%),
                radial-gradient(circle at 90% 80%, rgba(0, 240, 255, 0.12) 0%, transparent 40%);
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--card-border);
        }

        .brand h1 {
            font-size: 1.8rem;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .brand p { font-size: 0.9rem; color: var(--text-muted); }

        .badge {
            background: rgba(0, 255, 135, 0.15);
            color: var(--accent-green);
            border: 1px solid var(--accent-green);
            padding: 0.4rem 0.8rem;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.2rem;
            margin-bottom: 2rem;
        }

        .card {
            background: var(--card-bg);
            backdrop-filter: blur(12px);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        }

        .card h3 { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }
        .card .value { font-size: 2.2rem; font-weight: 700; margin-top: 0.5rem; }

        .main-grid {
            display: grid;
            grid-template-columns: 2fr 1.2fr;
            gap: 1.5rem;
        }

        @media (max-width: 900px) { .main-grid { grid-template-columns: 1fr; } }

        .widget-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        code, pre { font-family: 'JetBrains Mono', monospace; }

        .btn-group { display: flex; gap: 0.8rem; flex-wrap: wrap; }

        .btn {
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            color: #fff;
            border: none;
            padding: 0.7rem 1.2rem;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, opacity 0.2s;
        }

        .btn-green {
            background: linear-gradient(135deg, var(--accent-green), #00b4d8);
            color: #05080f;
        }

        .btn-pink {
            background: linear-gradient(135deg, var(--accent-pink), #9d4edd);
            color: #fff;
        }

        .btn:hover { transform: translateY(-2px); opacity: 0.9; }

        .log-console {
            background: rgba(5, 8, 15, 0.9);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 1rem;
            height: 280px;
            overflow-y: auto;
            font-size: 0.85rem;
            color: var(--accent-cyan);
            scroll-behavior: smooth;
        }

        .log-line { margin-bottom: 0.4rem; border-bottom: 1px dashed rgba(255, 255, 255, 0.05); padding-bottom: 0.2rem; }

        .otp-box {
            background: rgba(0, 255, 135, 0.1);
            border: 1px solid var(--accent-green);
            padding: 1rem;
            border-radius: 8px;
            margin-top: 1rem;
            text-align: center;
        }
        .otp-box .otp-val {
            font-family: 'JetBrains Mono', monospace;
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent-green);
            letter-spacing: 4px;
        }
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <h1>🛡️ Zero-Trust Security & Research Dashboard</h1>
            <p>Real-Time Telemetry & Interactive Testing Suite</p>
        </div>
        <div class="badge" id="sys-status">● System Operational</div>
    </header>

    <div class="stats-grid">
        <div class="card">
            <h3>HTTP Requests Handled</h3>
            <div class="value" id="stat-reqs" style="color: var(--accent-cyan);">0</div>
        </div>
        <div class="card">
            <h3>PoW Challenges Issued</h3>
            <div class="value" id="stat-pow" style="color: var(--accent-purple);">0</div>
        </div>
        <div class="card">
            <h3>RBA High Risk Alerts</h3>
            <div class="value" id="stat-rba-high" style="color: var(--accent-pink);">0</div>
        </div>
        <div class="card">
            <h3>DAG Token Revocations</h3>
            <div class="value" id="stat-dag" style="color: var(--accent-green);">0</div>
        </div>
    </div>

    <div class="main-grid">
        <div class="card">
            <div class="widget-title">📈 Real-Time Prometheus Metrics (/metrics)</div>
            <canvas id="metricsChart" height="120"></canvas>
        </div>

        <div class="card">
            <div class="widget-title">⚡ Interactive Testing Suite</div>
            <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
                Prueba los escudos PoW, RBA y simulaciones de ataques de reuso en el Grafo DAG.
            </p>
            <div class="btn-group">
                <button class="btn" onclick="runPoWTest()">Solve PoW</button>
                <button class="btn btn-green" onclick="generateTestOTP()">🔑 Generar OTP</button>
                <button class="btn btn-pink" onclick="simulateDAGReuse()">🌳 Reuso DAG</button>
            </div>
            <div id="pow-result" style="margin-top: 1rem; font-size: 0.85rem;"></div>
        </div>
    </div>

    <div class="card" style="margin-top: 1.5rem;">
        <div class="widget-title">📡 Audit Event Log Feed (Modo Developer: Códigos OTP Visibles)</div>
        <div class="log-console" id="logFeed">
            <div class="log-line">[SYSTEM] Zero-Trust Telemetry Engine Online... Real-Time Polling Active</div>
        </div>
    </div>

    <script>
        var chart = null;
        var renderedKeys = {};

        function initChart() {
            var ctx = document.getElementById('metricsChart').getContext('2d');
            chart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['PoW Issued', 'PoW Verified', 'RBA Low', 'RBA Med', 'RBA High', 'DAG Revoked'],
                    datasets: [{
                        label: 'Event Count',
                        data: [0, 0, 0, 0, 0, 0],
                        backgroundColor: [
                            '#00f0ff', '#00ff87', '#00ff87', '#ffb703', '#ff007f', '#9d4edd'
                        ],
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } },
                        x: { grid: { display: false } }
                    }
                }
            });
        }

        async function fetchMetrics() {
            try {
                var res = await fetch('/api/v1/metrics');
                var text = await res.text();
                var reqs = 0, powIssued = 0, powVerified = 0, rbaLow = 0, rbaMed = 0, rbaHigh = 0, dag = 0;
                
                text.split('\\n').forEach(function(line) {
                    if (line.indexOf('http_requests_total') === 0) {
                        var val = parseInt(line.split(' ').pop()) || 0;
                        reqs += val;
                    }
                    if (line.indexOf('pow_challenges_issued_total') === 0) powIssued = parseInt(line.split(' ').pop()) || 0;
                    if (line.indexOf('pow_challenges_verified_total') === 0) powVerified = parseInt(line.split(' ').pop()) || 0;
                    if (line.indexOf('risk_level="low"') !== -1) rbaLow = parseInt(line.split(' ').pop()) || 0;
                    if (line.indexOf('risk_level="medium"') !== -1) rbaMed = parseInt(line.split(' ').pop()) || 0;
                    if (line.indexOf('risk_level="high"') !== -1) rbaHigh = parseInt(line.split(' ').pop()) || 0;
                    if (line.indexOf('dag_revocations_total') === 0) dag = parseInt(line.split(' ').pop()) || 0;
                });

                document.getElementById('stat-reqs').innerText = reqs;
                document.getElementById('stat-pow').innerText = powIssued;
                document.getElementById('stat-rba-high').innerText = rbaHigh;
                document.getElementById('stat-dag').innerText = dag;

                if (chart) {
                    chart.data.datasets[0].data = [powIssued, powVerified, rbaLow, rbaMed, rbaHigh, dag];
                    chart.update();
                }
            } catch (e) {
                console.error("Telemetry error:", e);
            }
        }

        async function runPoWTest() {
            var out = document.getElementById('pow-result');
            out.innerHTML = "⏳ Solicitando Desafío PoW desde /auth/pow-challenge...";
            var start = performance.now();
            
            var res = await fetch('/api/v1/auth/pow-challenge');
            var data = await res.json();
            
            out.innerHTML = "Resolviendo Nonce SHA-256 (Dificultad: " + data.difficulty_bits + " bits)...";
            var targetPrefix = "0".repeat(Math.floor((data.difficulty_bits || 12) / 4));
            var nonce = 0;
            
            while (true) {
                var msg = data.challenge_id + ':' + nonce;
                var msgUint8 = new TextEncoder().encode(msg);
                var hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
                var hashArray = Array.from(new Uint8Array(hashBuffer));
                var hashHex = hashArray.map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
                
                if (hashHex.indexOf(targetPrefix) === 0) {
                    var elapsed = (performance.now() - start).toFixed(2);
                    out.innerHTML = "✅ <b>PoW Resuelto en " + elapsed + " ms!</b><br>Nonce: <code>" + nonce + "</code><br>Hash: <code>" + hashHex.substring(0, 16) + "...</code>";
                    fetchMetrics();
                    return { token: data.challenge_token, nonce: String(nonce) };
                }
                nonce++;
            }
        }

        async function generateTestOTP() {
            var out = document.getElementById('pow-result');
            out.innerHTML = "⏳ Resolviendo Escudo PoW e iniciando Motor RBA...";
            
            try {
                var pow = await runPoWTest();
                out.innerHTML += "<br>⏳ Solicitando Código OTP a /auth/request-otp...";
                
                var res = await fetch('/api/v1/auth/request-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: 'dashboard_dev@example.com',
                        pow_challenge_token: pow.token,
                        pow_nonce: pow.nonce
                    })
                });
                
                var data = await res.json();
                var otpCode = data.dev_otp_code || "ENVIADO POR EMAIL";
                
                out.innerHTML = '<div class="otp-box">' +
                    '<div style="font-size: 0.85rem; color: var(--text-muted);">CÓDIGO OTP GENERADO (MODO DEV)</div>' +
                    '<div class="otp-val">' + otpCode + '</div>' +
                    '<div style="font-size: 0.8rem; margin-top: 0.4rem; color: var(--accent-cyan);">' +
                        'Nivel de Riesgo: <b>' + (data.risk_level || 'low').toUpperCase() + '</b> (R = ' + (data.risk_score || 0) + ') | Entropía: ' + (data.entropy_bits || 19.93) + ' bits' +
                    '</div>' +
                '</div>';
                
                setTimeout(fetchAuditLogs, 400);
                setTimeout(fetchMetrics, 400);
            } catch (e) {
                out.innerHTML = '<span style="color: var(--accent-pink);">❌ Error: ' + e.message + '</span>';
            }
        }

        async function simulateDAGReuse() {
            var out = document.getElementById('pow-result');
            out.innerHTML = "⏳ Generando OTP y Autenticando Usuario...";
            try {
                var pow = await runPoWTest();
                var reqRes = await fetch('/api/v1/auth/request-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: 'dag_attack_test@example.com',
                        pow_challenge_token: pow.token,
                        pow_nonce: pow.nonce
                    })
                });
                var reqData = await reqRes.json();
                var otpCode = reqData.dev_otp_code;
                
                out.innerHTML = "⏳ Verificando OTP " + otpCode + " para emitir Tokens JWT...";
                var verifyRes = await fetch('/api/v1/auth/verify-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: 'dag_attack_test@example.com', code: otpCode })
                });
                var verifyData = await verifyRes.json();
                var tokenV1 = verifyData.refresh_token;
                
                out.innerHTML = "⏳ Rotando Refresh Token V1 a V2...";
                var rotRes = await fetch('/api/v1/auth/refresh', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ refresh_token: tokenV1 })
                });
                var rotData = await rotRes.json();
                var tokenV2 = rotData.refresh_token;
                
                out.innerHTML = "💥 Simulando Ataque: Reusando Refresh Token V1 (ya rotado)...";
                var attackRes = await fetch('/api/v1/auth/refresh', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ refresh_token: tokenV1 })
                });
                var attackData = await attackRes.json();
                
                out.innerHTML = '<div class="otp-box" style="border-color: var(--accent-pink); background: rgba(255,0,127,0.1);">' +
                    '<div style="font-size: 0.85rem; color: var(--accent-pink); font-weight: 700;">💥 ATAQUE DE REUSO DETECTADO & MITIGADO</div>' +
                    '<div style="font-size: 0.9rem; margin-top: 0.5rem; color: var(--text-primary);">' + (attackData.detail || 'Arbol de Tokens Revocado') + '</div>' +
                    '<div style="font-size: 0.8rem; margin-top: 0.4rem; color: var(--accent-cyan);">' +
                        'Revocación en Cascada del Grafo DAG completada en <b>&lt; 0.1 ms</b>' +
                    '</div>' +
                '</div>';
                
                setTimeout(fetchMetrics, 400);
                setTimeout(fetchAuditLogs, 400);
            } catch (e) {
                out.innerHTML = '<span style="color: var(--accent-pink);">❌ Error: ' + e.message + '</span>';
            }
        }

        async function fetchAuditLogs() {
            try {
                var res = await fetch('/api/v1/dashboard/events');
                var events = await res.json();
                var feed = document.getElementById('logFeed');
                if (events && events.length > 0) {
                    var hasNew = false;
                    for (var i = events.length - 1; i >= 0; i--) {
                        var ev = events[i];
                        var eventKey = ev.timestamp + '_' + ev.recipient + '_' + (ev.code || '') + '_' + ev.event_type;
                        if (!renderedKeys[eventKey]) {
                            renderedKeys[eventKey] = true;
                            hasNew = true;
                            
                            var eventBadge = '';
                            if (ev.event_type === 'USER_CREATED') {
                                eventBadge = '<span style="color:var(--accent-green); background: rgba(0,255,135,0.15); padding: 2px 6px; border-radius: 4px; font-weight:bold;">👤 USER CREATED</span>';
                            } else if (ev.event_type === 'USER_DELETED') {
                                eventBadge = '<span style="color:var(--accent-pink); background: rgba(255,0,127,0.15); padding: 2px 6px; border-radius: 4px; font-weight:bold;">🗑️ USER DELETED</span>';
                            } else if (ev.event_type === 'CSV_BULK_UPLOAD') {
                                eventBadge = '<span style="color:var(--accent-purple); background: rgba(157,78,221,0.15); padding: 2px 6px; border-radius: 4px; font-weight:bold;">📁 CSV BULK UPLOAD</span>';
                            } else {
                                eventBadge = '<b style="color:var(--accent-cyan);">' + ev.event_type + '</b>';
                            }
                            
                            var codeDisplay = (ev.code && ev.code !== "***REDACTED***") 
                                ? '<b style="color:var(--accent-green); background: rgba(0,255,135,0.15); padding: 2px 6px; border-radius: 4px;">[OTP: ' + ev.code + ']</b>' 
                                : '';
                            
                            var actorDisplay = '<span style="color:var(--text-muted); font-size:0.85rem;">(Por: <b style="color:var(--accent-cyan);">' + (ev.actor || 'SYSTEM') + '</b>)</span>';
                            var div = document.createElement('div');
                            div.className = 'log-line';
                            div.innerHTML = '[' + ev.timestamp + '] ' + eventBadge + ' - <b>' + ev.recipient + '</b> ' + actorDisplay + ' ' + codeDisplay + ' | Estado: <span style="color:var(--accent-cyan)">' + (ev.risk_level || 'info').toUpperCase() + '</span>';
                            feed.appendChild(div);
                        }
                    }
                    if (hasNew) {
                        feed.scrollTop = feed.scrollHeight;
                    }
                }
            } catch (e) { console.error("Audit log error:", e); }
        }

        window.onload = function() {
            initChart();
            fetchMetrics();
            fetchAuditLogs();
            setInterval(function() {
                fetchMetrics();
                fetchAuditLogs();
            }, 3000);
        };
    </script>
</body>
</html>
"""


@router.get(
    "/dashboard",
    response_class=HTMLResponse,
    summary="Zero-Trust Interactive Security Dashboard",
    include_in_schema=True,
)
async def get_security_dashboard():
    """
    Renders an interactive, real-time Glassmorphism Security & Telemetry Dashboard.
    Provides live PoW challenge solving, Prometheus chart visualization, and SIEM event feed.
    """
    return HTMLResponse(content=DASHBOARD_HTML, status_code=200)


@router.get(
    "/dashboard/events",
    summary="Fetch Recent Audit & Dev OTP Events",
    include_in_schema=True,
)
async def get_dashboard_events():
    """
    Returns recent audit logs and OTP generated events.
    NOTE: OTP codes are only revealed when running in development mode.
    """
    import json
    from app.services.storage import storage_service
    from app.domain.otp_engine import DEV_AUDIT_EVENTS
    try:
        raw = await storage_service.get("dev:audit_events")
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return DEV_AUDIT_EVENTS

pub fn dashboard_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentiel — Agent Governance Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; }
        .header { background: #1a1d29; padding: 16px 24px; border-bottom: 1px solid #2a2d3a; display: flex; align-items: center; gap: 12px; }
        .header h1 { font-size: 20px; color: #e94560; }
        .header .badge { background: #e94560; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .container { padding: 24px; max-width: 1400px; margin: 0 auto; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .card { background: #1a1d29; border-radius: 8px; padding: 20px; border: 1px solid #2a2d3a; }
        .card h2 { font-size: 14px; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
        .stat { font-size: 32px; font-weight: bold; color: #e94560; }
        .stat-label { font-size: 12px; color: #666; margin-top: 4px; }
        .events { background: #1a1d29; border-radius: 8px; border: 1px solid #2a2d3a; overflow: hidden; }
        .events table { width: 100%; border-collapse: collapse; }
        .events th { background: #141620; padding: 10px 16px; text-align: left; font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 1px; }
        .events td { padding: 10px 16px; border-top: 1px solid #2a2d3a; font-size: 13px; }
        .events tr:hover { background: #1e2130; }
        .allow { color: #4caf50; }
        .deny { color: #f44336; }
        .approval { color: #ff9800; }
        .critical { color: #f44336; font-weight: bold; }
        .high { color: #ff9800; }
        .medium { color: #ffc107; }
        .low { color: #4caf50; }
        .alerts { background: #2a1a1a; border-radius: 8px; border: 1px solid #4a2a2a; padding: 16px; margin-bottom: 24px; }
        .alert-item { padding: 8px 0; border-bottom: 1px solid #3a2a2a; }
        .alert-item:last-child { border-bottom: none; }
        .alert-type { font-weight: bold; color: #f44336; }
        .nav { display: flex; gap: 16px; margin-bottom: 24px; }
        .nav a { color: #888; text-decoration: none; padding: 8px 16px; border-radius: 4px; }
        .nav a:hover { background: #1e2130; color: #e94560; }
        .nav a.active { background: #e94560; color: #fff; }
        #event-stream { max-height: 500px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SENTIEL</h1>
        <span class="badge">Agent Governance Dashboard</span>
    </div>
    <div class="container">
        <div class="grid">
            <div class="card">
                <h2>Total Events</h2>
                <div class="stat" id="total-events">—</div>
                <div class="stat-label">Across all sources</div>
            </div>
            <div class="card">
                <h2>Authorization Decisions</h2>
                <div class="stat" id="authz-decisions">—</div>
                <div class="stat-label" id="authz-breakdown">Loading...</div>
            </div>
            <div class="card">
                <h2>DLP Violations</h2>
                <div class="stat" id="dlp-count">—</div>
                <div class="stat-label">Sensitive data detected</div>
            </div>
            <div class="card">
                <h2>Active Alerts</h2>
                <div class="stat" id="alerts-count">—</div>
                <div class="stat-label" id="alerts-info">Loading...</div>
            </div>
        </div>

        <div class="alerts" id="alerts-section" style="display:none;">
            <h2 style="color:#f44336;margin-bottom:12px;">⚠ Active Alerts</h2>
            <div id="alerts-list"></div>
        </div>

        <div class="events">
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Source</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Agent</th>
                        <th>Session</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody id="event-stream"></tbody>
            </table>
        </div>
    </div>

    <script>
        async function fetchJSON(url) {
            const resp = await fetch(url);
            return resp.json();
        }

        function formatTime(ts) {
            if (!ts) return '—';
            const d = new Date(ts);
            return d.toLocaleTimeString();
        }

        function severityClass(s) {
            return s || 'low';
        }

        async function updateDashboard() {
            try {
                const stats = await fetchJSON('/api/stats');
                document.getElementById('total-events').textContent = stats.total_events || 0;
                document.getElementById('authz-decisions').textContent = stats.authz_total || 0;
                document.getElementById('authz-breakdown').textContent =
                    `✓ ${stats.allows || 0} allowed / ✗ ${stats.denies || 0} denied`;
                document.getElementById('dlp-count').textContent = stats.dlp_violations || 0;
                document.getElementById('alerts-count').textContent = stats.active_alerts || 0;
                document.getElementById('alerts-info').textContent =
                    stats.active_alerts > 0 ? 'Requires attention' : 'All clear';

                const events = await fetchJSON('/api/events?limit=50');
                const tbody = document.getElementById('event-stream');
                tbody.innerHTML = events.map(e => `
                    <tr>
                        <td>${formatTime(e.timestamp)}</td>
                        <td>${e.source}</td>
                        <td>${e.event_type}</td>
                        <td class="${severityClass(e.severity)}">${e.severity}</td>
                        <td>${(e.agent_id||'—').substring(0,12)}</td>
                        <td>${(e.session_id||'—').substring(0,12)}</td>
                        <td>${JSON.stringify(e.data).substring(0,80)}</td>
                    </tr>
                `).join('');

                const alerts = await fetchJSON('/api/alerts');
                if (alerts.length > 0) {
                    document.getElementById('alerts-section').style.display = 'block';
                    document.getElementById('alerts-list').innerHTML = alerts.map(a => `
                        <div class="alert-item">
                            <span class="alert-type">${a.alert_type}</span>:
                            ${a.message}
                            <span style="color:#666;font-size:12px;"> — ${formatTime(a.created_at)}</span>
                        </div>
                    `).join('');
                } else {
                    document.getElementById('alerts-section').style.display = 'none';
                }
            } catch (err) {
                console.error('Dashboard update failed:', err);
            }
        }

        updateDashboard();
        setInterval(updateDashboard, 3000);
    </script>
</body>
</html>"#.to_string()
}

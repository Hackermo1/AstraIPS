#!/usr/bin/env python3
"""
AstraIPS Web Dashboard Generator
Generates an interactive HTML dashboard with Chart.js graphs
"""

import os
import sys
import sqlite3
import json
from datetime import datetime
from pathlib import Path

class DashboardGenerator:
    def __init__(self, db_path):
        self.db_path = db_path
        self.session_dir = os.path.dirname(db_path)
        self.dashboard_dir = os.path.join(self.session_dir, "dashboard")
        os.makedirs(self.dashboard_dir, exist_ok=True)
        
    def _query_db(self, query, params=None):
        """Execute query and return results"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            results = cursor.fetchall()
            conn.close()
            return results
        except Exception as e:
            print(f"   ⚠️ Query error: {e}")
            return []
    
    def _get_summary_stats(self):
        """Get summary statistics"""
        stats = {}
        
        # Total devices
        result = self._query_db("SELECT COUNT(DISTINCT COALESCE(source_mac, source_ip)) FROM mqtt_traffic")
        stats['total_devices'] = result[0][0] if result else 0
        
        # Total alerts
        result = self._query_db("SELECT COUNT(*) FROM snort_alerts")
        stats['total_alerts'] = result[0][0] if result else 0
        
        # Blocked
        result = self._query_db("SELECT COUNT(*) FROM snort_alerts WHERE ai_flag = 'BLOCK'")
        stats['blocked'] = result[0][0] if result else 0
        
        # MQTT packets
        result = self._query_db("SELECT COUNT(*) FROM mqtt_traffic")
        stats['mqtt_packets'] = result[0][0] if result else 0
        
        # Heuristic flags
        result = self._query_db("SELECT COUNT(*) FROM snort_alerts WHERE heuristic_flag = 'MAL'")
        stats['heuristic_flags'] = result[0][0] if result else 0
        
        # AI blocks
        result = self._query_db("SELECT COUNT(*) FROM ai_analysis WHERE verdict = 'BLOCK'")
        stats['ai_blocks'] = result[0][0] if result else 0
        
        # Confirmed malicious (both flagged)
        result = self._query_db("SELECT COUNT(*) FROM snort_alerts WHERE ai_flag = 'BLOCK' AND heuristic_flag = 'MAL'")
        stats['confirmed_malicious'] = result[0][0] if result else 0
        
        # Critical alerts
        result = self._query_db("SELECT COUNT(*) FROM snort_alerts WHERE priority = 1")
        stats['critical_alerts'] = result[0][0] if result else 0
        
        # High alerts
        result = self._query_db("SELECT COUNT(*) FROM snort_alerts WHERE priority = 2")
        stats['high_alerts'] = result[0][0] if result else 0
        
        # Medium alerts
        result = self._query_db("SELECT COUNT(*) FROM snort_alerts WHERE priority = 3")
        stats['medium_alerts'] = result[0][0] if result else 0
        
        # Low alerts
        result = self._query_db("SELECT COUNT(*) FROM snort_alerts WHERE priority = 4")
        stats['low_alerts'] = result[0][0] if result else 0
        
        return stats
    
    def _get_alert_priority_data(self):
        """Get alert distribution by priority"""
        results = self._query_db("""
            SELECT 
                CASE priority 
                    WHEN 1 THEN 'Critical'
                    WHEN 2 THEN 'High'
                    WHEN 3 THEN 'Medium'
                    ELSE 'Low'
                END as priority_name,
                COUNT(*) as count
            FROM snort_alerts
            GROUP BY priority
            ORDER BY priority
        """)
        
        labels = []
        data = []
        colors = []
        color_map = {'Critical': '#dc3545', 'High': '#fd7e14', 'Medium': '#ffc107', 'Low': '#28a745'}
        
        for row in results:
            labels.append(row[0])
            data.append(row[1])
            colors.append(color_map.get(row[0], '#6c757d'))
        
        return {'labels': labels, 'data': data, 'colors': colors}
    
    def _get_detection_stages_data(self):
        """Get devices by detection stage"""
        results = self._query_db("""
            SELECT stage, COUNT(*) as count
            FROM device_detection_state
            GROUP BY stage
            ORDER BY stage
        """)
        
        # Initialize all stages
        stages = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
        for row in results:
            if row[0] in stages:
                stages[row[0]] = row[1]
        
        return {
            'labels': ['Stage 0\n(New)', 'Stage 1\n(Warning)', 'Stage 2\n(Alert)', 'Stage 3\n(Block)', 'Stage 4\n(Banned)'],
            'data': list(stages.values()),
            'colors': ['#28a745', '#17a2b8', '#ffc107', '#fd7e14', '#dc3545']
        }
    
    def _get_timeline_data(self):
        """Get alerts over time"""
        results = self._query_db("""
            SELECT 
                strftime('%H:%M', timestamp) as time_bucket,
                COUNT(*) as total,
                SUM(CASE WHEN priority = 1 THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN priority = 2 THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN ai_flag = 'BLOCK' THEN 1 ELSE 0 END) as blocked
            FROM snort_alerts
            WHERE timestamp IS NOT NULL
            GROUP BY time_bucket
            ORDER BY timestamp
            LIMIT 50
        """)
        
        labels = []
        total_data = []
        critical_data = []
        blocked_data = []
        
        for row in results:
            labels.append(row[0])
            total_data.append(row[1])
            critical_data.append(row[2])
            blocked_data.append(row[4])
        
        return {
            'labels': labels,
            'total': total_data,
            'critical': critical_data,
            'blocked': blocked_data
        }
    
    def _get_top_threats(self):
        """Get top threat commands"""
        results = self._query_db("""
            SELECT 
                command,
                COUNT(*) as occurrences,
                SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as mal_count,
                SUM(CASE WHEN verdict = 'BLOCK' THEN 1 ELSE 0 END) as block_count
            FROM ai_analysis
            GROUP BY command
            ORDER BY occurrences DESC
            LIMIT 10
        """)
        
        threats = []
        for row in results:
            threats.append({
                'command': row[0][:60] if row[0] else 'Unknown',
                'occurrences': row[1],
                'malicious': row[2] or 0,
                'blocked': row[3] or 0
            })
        
        return threats
    
    def _get_devices_table(self):
        """Get device summary"""
        results = self._query_db("""
            SELECT 
                mac_address,
                device_ip,
                stage,
                detection_count,
                last_command,
                last_threat_level
            FROM device_detection_state
            ORDER BY stage DESC, detection_count DESC
            LIMIT 20
        """)
        
        devices = []
        for row in results:
            devices.append({
                'mac': row[0] or 'Unknown',
                'ip': row[1] or 'Unknown',
                'stage': row[2] or 0,
                'detections': row[3] or 0,
                'last_command': (row[4][:40] + '...') if row[4] and len(row[4]) > 40 else (row[4] or '-'),
                'threat': row[5] or 'LOW'
            })
        
        return devices
    
    def generate(self):
        """Generate the HTML dashboard"""
        print("📊 Generating web dashboard...")
        
        # Gather data
        stats = self._get_summary_stats()
        priority_data = self._get_alert_priority_data()
        stages_data = self._get_detection_stages_data()
        timeline_data = self._get_timeline_data()
        top_threats = self._get_top_threats()
        devices = self._get_devices_table()
        
        # Generate HTML
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AstraIPS Session Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            min-height: 100vh;
            padding: 20px;
        }}
        .header {{
            text-align: center;
            padding: 30px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-size: 2.5em;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}
        .header p {{ color: #888; font-size: 1.1em; }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 40px rgba(0,212,255,0.2);
        }}
        .stat-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-card .label {{ color: #888; font-size: 0.9em; text-transform: uppercase; }}
        .stat-card.critical .value {{ color: #dc3545; }}
        .stat-card.warning .value {{ color: #ffc107; }}
        .stat-card.success .value {{ color: #28a745; }}
        .stat-card.info .value {{ color: #00d4ff; }}
        
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }}
        .chart-card {{
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        .chart-card h3 {{
            margin-bottom: 20px;
            color: #00d4ff;
            font-size: 1.2em;
        }}
        .chart-container {{ position: relative; height: 300px; }}
        
        .table-card {{
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid rgba(255,255,255,0.1);
            margin-bottom: 30px;
            overflow-x: auto;
        }}
        .table-card h3 {{
            margin-bottom: 20px;
            color: #00d4ff;
            font-size: 1.2em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        th {{
            background: rgba(0,212,255,0.1);
            color: #00d4ff;
            font-weight: 600;
        }}
        tr:hover {{ background: rgba(255,255,255,0.05); }}
        
        .stage-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .stage-0 {{ background: #28a745; color: white; }}
        .stage-1 {{ background: #17a2b8; color: white; }}
        .stage-2 {{ background: #ffc107; color: black; }}
        .stage-3 {{ background: #fd7e14; color: white; }}
        .stage-4 {{ background: #dc3545; color: white; }}
        
        .threat-high {{ color: #dc3545; }}
        .threat-medium {{ color: #ffc107; }}
        .threat-low {{ color: #28a745; }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ AstraIPS Dashboard</h1>
        <p>Session Summary • Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <!-- Summary Stats -->
    <div class="stats-grid">
        <div class="stat-card info">
            <div class="value">{stats['total_devices']}</div>
            <div class="label">Total Devices</div>
        </div>
        <div class="stat-card info">
            <div class="value">{stats['mqtt_packets']}</div>
            <div class="label">MQTT Packets</div>
        </div>
        <div class="stat-card warning">
            <div class="value">{stats['total_alerts']}</div>
            <div class="label">Total Alerts</div>
        </div>
        <div class="stat-card critical">
            <div class="value">{stats['blocked']}</div>
            <div class="label">Blocked</div>
        </div>
        <div class="stat-card warning">
            <div class="value">{stats['heuristic_flags']}</div>
            <div class="label">Heuristic Flags</div>
        </div>
        <div class="stat-card critical">
            <div class="value">{stats['ai_blocks']}</div>
            <div class="label">AI Blocks</div>
        </div>
        <div class="stat-card critical">
            <div class="value">{stats['confirmed_malicious']}</div>
            <div class="label">Confirmed Malicious</div>
        </div>
        <div class="stat-card critical">
            <div class="value">{stats['critical_alerts']}</div>
            <div class="label">Critical Alerts</div>
        </div>
    </div>
    
    <!-- Charts -->
    <div class="charts-grid">
        <div class="chart-card">
            <h3>📊 Alert Priority Distribution</h3>
            <div class="chart-container">
                <canvas id="priorityChart"></canvas>
            </div>
        </div>
        <div class="chart-card">
            <h3>🎯 Device Detection Stages</h3>
            <div class="chart-container">
                <canvas id="stagesChart"></canvas>
            </div>
        </div>
        <div class="chart-card" style="grid-column: span 2;">
            <h3>📈 Alert Timeline</h3>
            <div class="chart-container">
                <canvas id="timelineChart"></canvas>
            </div>
        </div>
    </div>
    
    <!-- Top Threats Table -->
    <div class="table-card">
        <h3>🚨 Top Threat Commands</h3>
        <table>
            <thead>
                <tr>
                    <th>Command</th>
                    <th>Occurrences</th>
                    <th>Malicious</th>
                    <th>Blocked</th>
                </tr>
            </thead>
            <tbody>
                {''.join(f"""<tr>
                    <td><code>{t['command']}</code></td>
                    <td>{t['occurrences']}</td>
                    <td class="threat-high">{t['malicious']}</td>
                    <td class="threat-high">{t['blocked']}</td>
                </tr>""" for t in top_threats) if top_threats else '<tr><td colspan="4" style="text-align:center;color:#666;">No threat data</td></tr>'}
            </tbody>
        </table>
    </div>
    
    <!-- Devices Table -->
    <div class="table-card">
        <h3>📱 Device Summary</h3>
        <table>
            <thead>
                <tr>
                    <th>MAC Address</th>
                    <th>IP Address</th>
                    <th>Stage</th>
                    <th>Detections</th>
                    <th>Last Command</th>
                    <th>Threat Level</th>
                </tr>
            </thead>
            <tbody>
                {''.join(f"""<tr>
                    <td><code>{d['mac']}</code></td>
                    <td>{d['ip']}</td>
                    <td><span class="stage-badge stage-{d['stage']}">Stage {d['stage']}</span></td>
                    <td>{d['detections']}</td>
                    <td><code>{d['last_command']}</code></td>
                    <td class="threat-{d['threat'].lower()}">{d['threat']}</td>
                </tr>""" for d in devices) if devices else '<tr><td colspan="6" style="text-align:center;color:#666;">No device data</td></tr>'}
            </tbody>
        </table>
    </div>
    
    <div class="footer">
        <p>AstraIPS - AI-Driven Intrusion Prevention System</p>
    </div>
    
    <script>
        // Priority Chart
        new Chart(document.getElementById('priorityChart'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(priority_data['labels'])},
                datasets: [{{
                    data: {json.dumps(priority_data['data'])},
                    backgroundColor: {json.dumps(priority_data['colors'])},
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{ color: '#eee' }}
                    }}
                }}
            }}
        }});
        
        // Stages Chart
        new Chart(document.getElementById('stagesChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(stages_data['labels'])},
                datasets: [{{
                    label: 'Devices',
                    data: {json.dumps(stages_data['data'])},
                    backgroundColor: {json.dumps(stages_data['colors'])},
                    borderRadius: 8
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        grid: {{ color: 'rgba(255,255,255,0.1)' }},
                        ticks: {{ color: '#888' }}
                    }},
                    x: {{
                        grid: {{ display: false }},
                        ticks: {{ color: '#888' }}
                    }}
                }}
            }}
        }});
        
        // Timeline Chart
        new Chart(document.getElementById('timelineChart'), {{
            type: 'line',
            data: {{
                labels: {json.dumps(timeline_data['labels'])},
                datasets: [
                    {{
                        label: 'Total Alerts',
                        data: {json.dumps(timeline_data['total'])},
                        borderColor: '#00d4ff',
                        backgroundColor: 'rgba(0,212,255,0.1)',
                        fill: true,
                        tension: 0.4
                    }},
                    {{
                        label: 'Critical',
                        data: {json.dumps(timeline_data['critical'])},
                        borderColor: '#dc3545',
                        backgroundColor: 'rgba(220,53,69,0.1)',
                        fill: true,
                        tension: 0.4
                    }},
                    {{
                        label: 'Blocked',
                        data: {json.dumps(timeline_data['blocked'])},
                        borderColor: '#fd7e14',
                        backgroundColor: 'rgba(253,126,20,0.1)',
                        fill: true,
                        tension: 0.4
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        labels: {{ color: '#eee' }}
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        grid: {{ color: 'rgba(255,255,255,0.1)' }},
                        ticks: {{ color: '#888' }}
                    }},
                    x: {{
                        grid: {{ color: 'rgba(255,255,255,0.05)' }},
                        ticks: {{ color: '#888', maxRotation: 45 }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>'''
        
        # Write HTML
        output_path = os.path.join(self.dashboard_dir, "session_dashboard.html")
        with open(output_path, 'w') as f:
            f.write(html)
        
        print(f"✅ Dashboard generated: {output_path}")
        return output_path


def main():
    if len(sys.argv) < 2:
        # Find latest session
        logs_dir = "logs"
        if os.path.exists(logs_dir):
            db_path = os.path.join(logs_dir, "session.db")
            if not os.path.exists(db_path):
                print("❌ No session.db found in logs/")
                print("Usage: python3 generate_dashboard.py <path_to_session.db>")
                return 1
        else:
            print("Usage: python3 generate_dashboard.py <path_to_session.db>")
            return 1
    else:
        db_path = sys.argv[1]
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return 1
    
    generator = DashboardGenerator(db_path)
    output = generator.generate()
    
    print(f"\n🌐 Open in browser:")
    print(f"   firefox {output}")
    print(f"   # or")
    print(f"   xdg-open {output}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

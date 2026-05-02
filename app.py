#!/usr/bin/env python3
"""
IDS/IPS System - Main Application Entry Point
Hệ thống Phát hiện và Ngăn chặn Xâm nhập
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import json
import os
from datetime import datetime

from core.ids_engine import IDSEngine
from core.data_store import DataStore

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-ips-secret-key-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize core components
data_store = DataStore()
ids_engine = IDSEngine(data_store, socketio)

# ─────────────────────────── ROUTES ───────────────────────────

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/monitor')
def monitor():
    return render_template('monitor.html')

@app.route('/threats')
def threats():
    return render_template('threats.html')

@app.route('/logs')
def logs():
    return render_template('logs.html')

@app.route('/blocked')
def blocked():
    return render_template('blocked.html')

@app.route('/rules')
def rules():
    return render_template('rules.html')

@app.route('/about')
def about():
    return render_template('about.html')

# ─────────────────────────── API ───────────────────────────

@app.route('/api/stats')
def api_stats():
    return jsonify(data_store.get_stats())

@app.route('/api/alerts')
def api_alerts():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(data_store.get_alerts(limit))

@app.route('/api/traffic')
def api_traffic():
    return jsonify(data_store.get_traffic_data())

@app.route('/api/blocked-ips')
def api_blocked_ips():
    return jsonify(data_store.get_blocked_ips())

@app.route('/api/rules')
def api_rules():
    return jsonify(data_store.get_rules())

@app.route('/api/rules/toggle', methods=['POST'])
def api_toggle_rule():
    data = request.json
    rule_id = data.get('rule_id')
    result = data_store.toggle_rule(rule_id)
    return jsonify(result)

@app.route('/api/block-ip', methods=['POST'])
def api_block_ip():
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason', 'Manual block')
    result = ids_engine.block_ip(ip, reason)
    return jsonify(result)

@app.route('/api/unblock-ip', methods=['POST'])
def api_unblock_ip():
    data = request.json
    ip = data.get('ip')
    result = ids_engine.unblock_ip(ip)
    return jsonify(result)

@app.route('/api/engine/start', methods=['POST'])
def api_start_engine():
    ids_engine.start()
    return jsonify({'status': 'started', 'message': 'IDS/IPS Engine đã khởi động'})

@app.route('/api/engine/stop', methods=['POST'])
def api_stop_engine():
    ids_engine.stop()
    return jsonify({'status': 'stopped', 'message': 'IDS/IPS Engine đã dừng'})

@app.route('/api/engine/status')
def api_engine_status():
    return jsonify({'running': ids_engine.running, 'mode': ids_engine.mode})

@app.route('/api/top-threats')
def api_top_threats():
    return jsonify(data_store.get_top_threats())

@app.route('/api/geo-data')
def api_geo_data():
    return jsonify(data_store.get_geo_data())

@app.route('/api/protocol-stats')
def api_protocol_stats():
    return jsonify(data_store.get_protocol_stats())

@app.route('/api/hourly-traffic')
def api_hourly_traffic():
    return jsonify(data_store.get_hourly_traffic())

@app.route('/api/clear-alerts', methods=['POST'])
def api_clear_alerts():
    data_store.clear_alerts()
    return jsonify({'status': 'ok', 'message': 'Đã xóa tất cả cảnh báo'})

# ─────────────────────────── SOCKETIO EVENTS ───────────────────────────

@socketio.on('connect')
def handle_connect():
    print(f'[+] Client connected: {request.sid}')
    emit('status', {'connected': True, 'engine': ids_engine.running})

@socketio.on('disconnect')
def handle_disconnect():
    print(f'[-] Client disconnected: {request.sid}')

@socketio.on('request_stats')
def handle_request_stats():
    emit('stats_update', data_store.get_stats())

# ─────────────────────────── MAIN ───────────────────────────

if __name__ == '__main__':
    print("=" * 54)
    print("  IDS/IPS SECURITY MONITORING SYSTEM  ")
    print("  He thong Phat hien & Ngan chan Xam nhap")
    print("=" * 54)
    print("[*] Starting server at http://localhost:5000")
    print(f"[*] Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Auto-start the IDS engine in simulation mode
    ids_engine.start()
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)

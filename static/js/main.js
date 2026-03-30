/* ─── Main JS global utilities for IDS/IPS ─── */

// Socket.IO Connection
const socket = io();
let engineRunning = true;

// ─── Socket Events ───
socket.on('connect', () => {
    console.log('[+] Connected to IDS/IPS Server');
    updateConnectionStatus(true);
});
socket.on('disconnect', () => {
    console.log('[-] Disconnected');
    updateConnectionStatus(false);
});

socket.on('stats_update', (data) => {
    updateGlobalStats(data);
    updateThreatIndicator(data.threat_level);
    if (window.onStatsUpdate) window.onStatsUpdate(data);
});

socket.on('new_alert', (alert) => {
    showAlertToast(alert);
    showAlertPopup(alert);
    if (window.onNewAlert) window.onNewAlert(alert);
    // Update badge
    const badge = document.getElementById('badge-alerts');
    if (badge) {
        let count = parseInt(badge.dataset.count || '0') + 1;
        badge.dataset.count = count;
        badge.textContent = count > 99 ? '99+' : count;
        badge.classList.add('visible');
    }
});

socket.on('status', (data) => {
    engineRunning = data.engine;
    updateEngineStatus(engineRunning);
});

// ─── Time ───
function updateClock() {
    const el = document.getElementById('currentTime');
    if (el) {
        const now = new Date();
        el.textContent = now.toLocaleTimeString('vi-VN', { hour12: false });
    }
}
setInterval(updateClock, 1000);
updateClock();

// ─── Engine Control ───
async function controlEngine(action) {
    try {
        const res = await fetch(`/api/engine/${action}`, { method: 'POST' });
        const data = await res.json();
        engineRunning = (action === 'start');
        updateEngineStatus(engineRunning);
        showToast(data.message, 'info');
    } catch (e) {
        showToast('Lỗi kết nối server', 'error');
    }
}

function updateEngineStatus(running) {
    const dot = document.getElementById('engineDot');
    const text = document.getElementById('engineStatusText');
    if (dot) dot.className = 'engine-dot' + (running ? '' : ' stopped');
    if (text) text.textContent = running ? 'Engine đang chạy' : 'Engine đã dừng';
}

function updateConnectionStatus(connected) {
    // Visual feedback
}

// ─── Threat Indicator ───
function updateThreatIndicator(level) {
    const el = document.getElementById('threatIndicator');
    const text = document.getElementById('threatLevelText');
    if (!el || !text) return;
    
    const levels = {
        'CRITICAL': { cls: 'threat-critical', label: 'Nguy hiểm cực cao' },
        'HIGH': { cls: 'threat-high', label: 'Mối đe dọa cao' },
        'MEDIUM': { cls: 'threat-medium', label: 'Cảnh báo trung bình' },
        'LOW': { cls: '', label: 'Hệ thống an toàn' },
    };
    const info = levels[level] || levels['LOW'];
    el.className = 'threat-indicator ' + info.cls;
    text.textContent = info.label;
}

function updateGlobalStats(stats) {
    // Engine status
    updateEngineStatus(stats.uptime_seconds > 0);
}

// ─── Sidebar Toggle ───
function toggleSidebar() {
    document.body.classList.toggle('sidebar-collapsed');
}

// ─── Toast System ───
function showToast(message, type = 'info', title = '') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    
    const icons = {
        critical: '<i class="fas fa-circle-exclamation text-critical"></i>',
        high: '<i class="fas fa-triangle-exclamation text-high"></i>',
        medium: '<i class="fas fa-bell text-medium"></i>',
        info: '<i class="fas fa-circle-info text-accent"></i>',
        error: '<i class="fas fa-circle-xmark text-critical"></i>',
        success: '<i class="fas fa-circle-check" style="color:var(--accent-green)"></i>',
    };
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type.toLowerCase()}`;
    toast.innerHTML = `
        ${icons[type.toLowerCase()] || icons.info}
        <div class="toast-body">
            ${title ? `<div class="toast-title">${title}</div>` : ''}
            <div class="toast-msg">${message}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <i class="fas fa-xmark"></i>
        </button>
    `;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function showAlertToast(alert) {
    const sevMap = {
        'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'info'
    };
    showToast(
        `${alert.src_ip} → ${alert.dst_ip}:${alert.dst_port}`,
        sevMap[alert.severity] || 'info',
        alert.type
    );
}

// ─── Alert Popup ───
let popupTimeout;
function showAlertPopup(alert) {
    const popup = document.getElementById('alertPopup');
    const body = document.getElementById('alertPopupBody');
    if (!popup || !body) return;
    
    const sevColors = {
        'CRITICAL': 'var(--severity-critical)',
        'HIGH': 'var(--severity-high)',
        'MEDIUM': 'var(--severity-medium)',
        'LOW': 'var(--severity-low)',
    };
    
    body.innerHTML = `
        <div class="pop-row">
            <span class="pop-label">Loại tấn công</span>
            <span class="pop-value" style="color:${sevColors[alert.severity]}">${alert.type}</span>
        </div>
        <div class="pop-row">
            <span class="pop-label">IP nguồn</span>
            <span class="pop-value">${alert.src_ip}</span>
        </div>
        <div class="pop-row">
            <span class="pop-label">IP đích</span>
            <span class="pop-value">${alert.dst_ip}:${alert.dst_port}</span>
        </div>
        <div class="pop-row">
            <span class="pop-label">Mức độ</span>
            <span class="pop-value" style="color:${sevColors[alert.severity]}">${alert.severity}</span>
        </div>
        <div class="pop-row">
            <span class="pop-label">Hành động</span>
            <span class="pop-value">${alert.action}</span>
        </div>
    `;
    
    popup.style.display = 'block';
    clearTimeout(popupTimeout);
    popupTimeout = setTimeout(closePopup, 8000);
}

function closePopup() {
    const popup = document.getElementById('alertPopup');
    if (popup) popup.style.display = 'none';
}

// ─── Number Formatting ───
function formatNumber(n) {
    if (n >= 1000000) return (n/1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n/1000).toFixed(1) + 'K';
    return n?.toString() || '0';
}

function formatBytes(bytes) {
    if (bytes >= 1073741824) return (bytes/1073741824).toFixed(1) + ' GB';
    if (bytes >= 1048576) return (bytes/1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes/1024).toFixed(1) + ' KB';
    return bytes + ' B';
}

// ─── Severity Color ───
function getSevColor(sev) {
    const map = {
        'CRITICAL': '#ff3d3d',
        'HIGH': '#ff8c00',
        'MEDIUM': '#ffd700',
        'LOW': '#00ff88',
        'INFO': '#00d4ff',
    };
    return map[sev] || '#8899aa';
}

function getSevClass(sev) {
    const map = {
        'CRITICAL': 'badge-critical',
        'HIGH': 'badge-high',
        'MEDIUM': 'badge-medium',
        'LOW': 'badge-low',
        'INFO': 'badge-info',
    };
    return map[sev] || 'badge-info';
}

function getActionClass(action) {
    return action === 'BLOCKED' ? 'badge-blocked' : 'badge-alert';
}

// ─── Animated Counter ───
function animateCount(el, target, duration = 800) {
    const start = parseInt(el.textContent.replace(/\D/g, '')) || 0;
    const diff = target - start;
    const steps = 30;
    let step = 0;
    const timer = setInterval(() => {
        step++;
        const progress = step / steps;
        const ease = 1 - Math.pow(1 - progress, 3);
        el.textContent = formatNumber(Math.round(start + diff * ease));
        if (step >= steps) {
            clearInterval(timer);
            el.textContent = formatNumber(target);
        }
    }, duration / steps);
}

// ─── Default Chart Config ───
function defaultChartOptions(options = {}) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: { color: '#8899aa', font: { family: 'Inter', size: 11 } }
            },
            tooltip: {
                backgroundColor: '#111a2e',
                borderColor: 'rgba(0,212,255,0.2)',
                borderWidth: 1,
                titleColor: '#e2e8f0',
                bodyColor: '#8899aa',
                padding: 10,
            },
        },
        scales: {
            x: {
                ticks: { color: '#4a5568', font: { size: 10 } },
                grid: { color: 'rgba(255,255,255,0.04)' },
            },
            y: {
                ticks: { color: '#4a5568', font: { size: 10 } },
                grid: { color: 'rgba(255,255,255,0.04)' },
            }
        },
        ...options
    };
}

// ─── Fetch Helper ───
async function fetchAPI(url) {
    try {
        const res = await fetch(url);
        return await res.json();
    } catch (e) {
        console.error('API error:', url, e);
        return null;
    }
}

// ─── Table Filter ───
function filterTable(inputId, tableId) {
    const input = document.getElementById(inputId);
    const table = document.getElementById(tableId);
    if (!input || !table) return;
    
    input.addEventListener('input', () => {
        const query = input.value.toLowerCase();
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach(row => {
            row.style.display = row.textContent.toLowerCase().includes(query) ? '' : 'none';
        });
    });
}

// ─── Init on load ───
document.addEventListener('DOMContentLoaded', () => {
    updateClock();
    // Check engine status
    fetchAPI('/api/engine/status').then(data => {
        if (data) {
            engineRunning = data.running;
            updateEngineStatus(engineRunning);
        }
    });
});

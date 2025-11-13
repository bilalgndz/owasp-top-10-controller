// API Base URL
const API_BASE = '';

// Sayfa yüklendiğinde
document.addEventListener('DOMContentLoaded', () => {
    loadConfigs();
    loadLatestReport();
});

// Konfigürasyon dosyalarını yükle
async function loadConfigs() {
    try {
        const response = await fetch(`${API_BASE}/api/configs`);
        const data = await response.json();
        
        const select = document.getElementById('config-select');
        select.innerHTML = '';
        
        if (data.configs.length === 0) {
            select.innerHTML = '<option value="">Konfigürasyon dosyası bulunamadı</option>';
            return;
        }
        
        data.configs.forEach(config => {
            const option = document.createElement('option');
            option.value = config.path;
            option.textContent = config.name;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Konfigürasyonlar yüklenirken hata:', error);
        showStatus('error', 'Konfigürasyonlar yüklenirken hata oluştu: ' + error.message);
    }
}

// Tarama başlat
async function startScan() {
    const configSelect = document.getElementById('config-select');
    const configPath = configSelect.value;
    
    if (!configPath) {
        showStatus('error', 'Lütfen bir konfigürasyon dosyası seçin');
        return;
    }
    
    const btn = document.getElementById('start-scan-btn');
    btn.disabled = true;
    btn.textContent = '⏳ Tarama başlatılıyor...';
    
    showStatus('info', 'Tarama başlatılıyor, lütfen bekleyin...');
    
    try {
        const response = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ config_path: configPath })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showStatus('success', `Tarama tamamlandı! ${data.findings_count} bulgu bulundu.`);
            updateStats(data.summary);
            await loadReport(data.report_id);
        } else {
            showStatus('error', 'Tarama hatası: ' + (data.error || 'Bilinmeyen hata'));
        }
    } catch (error) {
        showStatus('error', 'Tarama başlatılırken hata: ' + error.message);
    } finally {
        btn.disabled = false;
        btn.textContent = '🚀 Taramayı Başlat';
    }
}

// Son raporu yükle
async function loadLatestReport() {
    try {
        const response = await fetch(`${API_BASE}/api/reports`);
        const data = await response.json();
        
        if (data.reports && data.reports.length > 0) {
            const latestReport = data.reports[0];
            await loadReport(latestReport.id);
        } else {
            document.getElementById('findings-list').innerHTML = 
                '<p class="empty-message">Henüz rapor bulunmuyor. Bir tarama başlatın.</p>';
        }
    } catch (error) {
        console.error('Raporlar yüklenirken hata:', error);
    }
}

// Belirli bir raporu yükle
async function loadReport(reportId) {
    const findingsList = document.getElementById('findings-list');
    findingsList.innerHTML = '<div class="loading"><div class="spinner"></div>Rapor yükleniyor...</div>';
    
    try {
        const response = await fetch(`${API_BASE}/api/reports/${reportId}`);
        const data = await response.json();
        
        if (response.ok) {
            updateStats(data.summary);
            displayFindings(data.findings);
        } else {
            findingsList.innerHTML = `<p class="empty-message">Rapor yüklenemedi: ${data.error}</p>`;
        }
    } catch (error) {
        findingsList.innerHTML = `<p class="empty-message">Rapor yüklenirken hata: ${error.message}</p>`;
    }
}

// İstatistikleri güncelle
function updateStats(summary) {
    if (!summary || !summary.stats) return;
    
    document.getElementById('stat-critical').textContent = summary.stats.critical || 0;
    document.getElementById('stat-high').textContent = summary.stats.high || 0;
    document.getElementById('stat-medium').textContent = summary.stats.medium || 0;
    document.getElementById('stat-low').textContent = summary.stats.low || 0;
    document.getElementById('stat-info').textContent = summary.stats.info || 0;
}

// Bulguları göster
function displayFindings(findings) {
    const findingsList = document.getElementById('findings-list');
    
    if (!findings || findings.length === 0) {
        findingsList.innerHTML = '<p class="empty-message">✅ Bulgu bulunamadı. Hedef uygulama güvenli görünüyor!</p>';
        return;
    }
    
    // Severity sırasına göre sırala
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort((a, b) => {
        return (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99);
    });
    
    findingsList.innerHTML = findings.map(finding => `
        <div class="finding-card ${finding.severity}">
            <div class="finding-header">
                <span class="finding-severity ${finding.severity}">${finding.severity.toUpperCase()}</span>
                <span class="finding-check-id">${finding.check_id}</span>
            </div>
            <div class="finding-endpoint">${escapeHtml(finding.endpoint)}</div>
            <div class="finding-summary">${escapeHtml(finding.summary)}</div>
            <div class="finding-description">${escapeHtml(finding.description)}</div>
            ${finding.evidence ? `
                <div class="finding-evidence">
                    <strong>Delil:</strong>
                    <pre>${JSON.stringify(finding.evidence, null, 2)}</pre>
                </div>
            ` : ''}
            ${finding.remediation ? `
                <div class="finding-remediation">
                    <strong>🔧 Çözüm Önerisi:</strong><br>
                    ${escapeHtml(finding.remediation)}
                </div>
            ` : ''}
        </div>
    `).join('');
}

// Raporları yenile
async function refreshReports() {
    await loadLatestReport();
    showStatus('info', 'Raporlar yenilendi');
}

// Durum mesajı göster
function showStatus(type, message) {
    const statusDiv = document.getElementById('scan-status');
    statusDiv.className = `status-message ${type}`;
    statusDiv.textContent = message;
    statusDiv.style.display = 'block';
    
    if (type === 'success' || type === 'info') {
        setTimeout(() => {
            statusDiv.style.display = 'none';
        }, 5000);
    }
}

// HTML escape
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}


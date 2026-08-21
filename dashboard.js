async function fetchFindings() {
    try {
        const response = await fetch('/api/findings');
        const findings = await response.json();

        const container = document.getElementById('findingsList');

        if (!findings || findings.length === 0) {
            container.innerHTML = '<div class="empty-state">No findings yet...</div>';
            return;
        }

        container.innerHTML = findings.map(finding => `
            <div class="finding-item">
                <div class="finding-header">
                    <span class="finding-value">${finding.MaskedValue || 'N/A'}</span>
                </div>
                <div class="finding-details">
                    <div class="finding-reason">${finding.DetectionReason || 'Unknown'}</div>
                </div>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to fetch findings:', error);
    }
}

async function fetchStats() {
    try {
        const response = await fetch('/api/statistics');
        const stats = await response.json();

        document.getElementById('totalFindings').textContent = stats.TotalFindings || 0;
        document.getElementById('highEntropy').textContent = stats.HighEntropy || 0;
        document.getElementById('keywords').textContent = stats.Keywords || 0;
        document.getElementById('tokens').textContent = stats.Tokens || 0;
    } catch (error) {
        console.error('Failed to fetch stats:', error);
    }
}

fetchFindings();
fetchStats();
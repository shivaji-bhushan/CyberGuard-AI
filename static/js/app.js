/**
 * CyberGuard AI — Editorial Enterprise Security Platform Controller
 * "One AI Brain. Multiple Specialized Defenses."
 */

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initModeSwitcher();
  initSampleChips();
  initScenarioTriggers();
  initFormSubmissions();
  initIncidentTable();
  initKeyboardShortcuts();
  fetchPlatformTelemetry();

  // Quick Demo button in empty state
  const btnQuickDemo = document.getElementById('btnQuickDemo');
  if (btnQuickDemo) {
    btnQuickDemo.addEventListener('click', () => {
      triggerScenario('electricity_scam');
    });
  }

  // Refresh overview button
  const btnRefreshOverview = document.getElementById('btnRefreshOverview');
  if (btnRefreshOverview) {
    btnRefreshOverview.addEventListener('click', () => {
      fetchPlatformTelemetry();
      fetchIncidents();
    });
  }
});

let currentRiskScore = 0;
let cachedIncidents = [];
let activeIncidentFilter = 'all';

/* ==========================================================================
   Navigation & Smooth Scrolling
   ========================================================================== */
function initNavigation() {
  const navLinks = document.querySelectorAll('.nav-item');
  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      navLinks.forEach(l => l.classList.remove('active'));
      link.classList.add('active');
    });
  });
}

/* ==========================================================================
   Investigation Mode Switcher (Tabs)
   ========================================================================== */
function initModeSwitcher() {
  const tabs = document.querySelectorAll('.mode-tab');
  const panes = document.querySelectorAll('.workspace-pane');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.getAttribute('data-tab');
      tabs.forEach(t => t.classList.remove('active'));
      panes.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const pane = document.getElementById(
        target === 'unified' ? 'paneUnified' :
        target === 'phish' ? 'panePhish' :
        target === 'upi' ? 'paneUpi' : 'paneNet'
      );
      if (pane) pane.classList.add('active');
    });
  });

  const btnReset = document.getElementById('btnResetUnified');
  if (btnReset) {
    btnReset.addEventListener('click', () => {
      document.getElementById('inputPhishUrl').value = '';
      document.getElementById('inputPhishText').value = '';
      document.getElementById('inputUpiVpa').value = '';
      document.getElementById('inputUpiAmount').value = '';
      document.getElementById('inputUpiContext').value = '';
      document.getElementById('inputNetIp').value = '';
      document.getElementById('inputNetPort').value = '';
      document.getElementById('inputNetBeacons').value = '';
      document.getElementById('inputNetDns').value = '';
    });
  }
}

/* ==========================================================================
   Quick Sample Fill Chips
   ========================================================================== */
function initSampleChips() {
  const sampleBtns = document.querySelectorAll('.sample-btn');
  sampleBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const fill = btn.getAttribute('data-fill');

      if (fill === 'phish-power') {
        document.getElementById('inputPhishUrl').value = 'http://power-bill-update.xyz/pay-online';
        document.getElementById('inputPhishText').value = 'Dear customer your electricity power will be disconnected tonight 9:30 PM due to unpaid bill. Call 9876543210 or pay immediately at http://power-bill-update.xyz';
      } else if (fill === 'phish-sbi') {
        document.getElementById('inputPhishUrl').value = 'http://sbi-kyc-verify.top/netbanking-login';
        document.getElementById('inputPhishText').value = 'URGENT: Your SBI NetBanking account is BLOCKED due to expired PAN KYC. Update immediately to prevent permanent deactivation: http://sbi-kyc-verify.top';
      } else if (fill === 'phish-safe') {
        document.getElementById('inputPhishUrl').value = 'https://mail.google.com/mail/u/0/#inbox';
        document.getElementById('inputPhishText').value = 'Hi Shiva, the design review meeting is scheduled for 3:00 PM today.';
      } else if (fill === 'upi-power') {
        document.getElementById('inputUpiVpa').value = 'mahadiscom.billdesk@paytm';
        document.getElementById('inputUpiAmount').value = '1480.00';
        document.getElementById('inputUpiContext').value = 'URGENT: Enter your UPI PIN to verify transaction and receive electricity subsidy refund';
      } else if (fill === 'upi-sbi') {
        document.getElementById('inputUpiVpa').value = 'sbi.fraudulent.collect@okaxis';
        document.getElementById('inputUpiAmount').value = '500.00';
        document.getElementById('inputUpiContext').value = 'Enter secret 6-digit UPI PIN to claim ₹500 KYC verification refund bonus';
      } else if (fill === 'upi-safe') {
        document.getElementById('inputUpiVpa').value = 'starbucks.coffee@icici';
        document.getElementById('inputUpiAmount').value = '340.00';
        document.getElementById('inputUpiContext').value = 'Payment for Cafe Latte';
      } else if (fill === 'net-c2') {
        document.getElementById('inputNetIp').value = '185.220.101.5';
        document.getElementById('inputNetPort').value = '4444';
        document.getElementById('inputNetBeacons').value = '5.01, 4.99, 5.02, 5.00, 4.98, 5.01';
        document.getElementById('inputNetDns').value = 'c2.power-bill-update.xyz';
      } else if (fill === 'net-tunnel') {
        document.getElementById('inputNetIp').value = '193.36.119.12';
        document.getElementById('inputNetPort').value = '31337';
        document.getElementById('inputNetBeacons').value = '3.01, 2.99, 3.00, 3.02, 2.98';
        document.getElementById('inputNetDns').value = '7a8b9c1d2e3f405162738495a6b7c8d9e0f1.exfil.darknet.cc';
      } else if (fill === 'net-safe') {
        document.getElementById('inputNetIp').value = '142.250.190.46';
        document.getElementById('inputNetPort').value = '443';
        document.getElementById('inputNetBeacons').value = '1.2, 8.4, 0.4, 15.6, 3.1';
        document.getElementById('inputNetDns').value = 'google.com';
      }
    });
  });
}

/* ==========================================================================
   Scenario Simulation Handlers
   ========================================================================== */
function initScenarioTriggers() {
  const scenarioBtns = document.querySelectorAll('.btn-scenario');
  scenarioBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const scenarioKey = btn.getAttribute('data-scenario');
      triggerScenario(scenarioKey);
    });
  });

  const featuredCard = document.querySelector('.scenario-featured');
  if (featuredCard) {
    featuredCard.addEventListener('click', () => {
      triggerScenario('electricity_scam');
    });
  }

  const rowCards = document.querySelectorAll('.scenario-row-card');
  rowCards.forEach(card => {
    card.addEventListener('click', () => {
      const key = card.getAttribute('data-scenario');
      triggerScenario(key);
    });
  });
}

async function triggerScenario(scenarioKey) {
  // Populate form inputs
  populateScenarioInputs(scenarioKey);

  // Switch to Unified tab
  const unifiedTab = document.querySelector('.mode-tab[data-tab="unified"]');
  if (unifiedTab) unifiedTab.click();

  try {
    const response = await fetch('/api/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: scenarioKey })
    });
    const data = await response.json();
    renderInvestigationResults(data);
    fetchIncidents();

    // Smooth scroll down to results section
    const resultsSection = document.getElementById('results');
    if (resultsSection) {
      resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
  } catch (err) {
    console.error('Scenario simulation error:', err);
  }
}

function populateScenarioInputs(key) {
  if (key === 'electricity_scam') {
    document.getElementById('inputPhishUrl').value = 'http://power-bill-update.xyz/pay-online';
    document.getElementById('inputPhishText').value = 'Dear customer your electricity power will be disconnected tonight 9:30 PM due to unpaid bill. Call 9876543210 or pay immediately at http://power-bill-update.xyz';
    document.getElementById('inputUpiVpa').value = 'mahadiscom.billdesk@paytm';
    document.getElementById('inputUpiAmount').value = '1480.00';
    document.getElementById('inputUpiContext').value = 'URGENT: Enter your UPI PIN to verify transaction and receive electricity subsidy refund';
    document.getElementById('inputNetIp').value = '185.220.101.5';
    document.getElementById('inputNetPort').value = '4444';
    document.getElementById('inputNetBeacons').value = '5.01, 4.99, 5.02, 5.00, 4.98, 5.01';
    document.getElementById('inputNetDns').value = 'c2.power-bill-update.xyz';
  } else if (key === 'bank_kyc_trap') {
    document.getElementById('inputPhishUrl').value = 'http://sbi-kyc-verify.top/netbanking-login';
    document.getElementById('inputPhishText').value = 'URGENT: Your SBI NetBanking account is BLOCKED due to expired PAN KYC. Update immediately to prevent permanent deactivation: http://sbi-kyc-verify.top';
    document.getElementById('inputUpiVpa').value = 'sbi.fraudulent.collect@okaxis';
    document.getElementById('inputUpiAmount').value = '500.00';
    document.getElementById('inputUpiContext').value = 'Enter secret 6-digit UPI PIN to claim ₹500 KYC verification refund bonus';
    document.getElementById('inputNetIp').value = '45.142.122.99';
    document.getElementById('inputNetPort').value = '1337';
    document.getElementById('inputNetBeacons').value = '10.02, 9.98, 10.01, 10.00, 9.99';
    document.getElementById('inputNetDns').value = 'tunnel.sbi-kyc-verify.top';
  } else if (key === 'crypto_drain') {
    document.getElementById('inputPhishUrl').value = 'http://binance-airdrop-claim.live/connect-wallet';
    document.getElementById('inputPhishText').value = 'CONGRATULATIONS: You won 1.50 ETH ($4,200). Claim within 10 minutes at http://binance-airdrop-claim.live or forfeits.';
    document.getElementById('inputUpiVpa').value = 'crypto.liquidity.pool@ybl';
    document.getElementById('inputUpiAmount').value = '25000.00';
    document.getElementById('inputUpiContext').value = 'Scan QR & enter secret UPI PIN to release token liquidity into your bank account';
    document.getElementById('inputNetIp').value = '193.36.119.12';
    document.getElementById('inputNetPort').value = '31337';
    document.getElementById('inputNetBeacons').value = '3.01, 2.99, 3.00, 3.02, 2.98';
    document.getElementById('inputNetDns').value = '7a8b9c1d2e3f405162738495a6b7c8d9e0f1.exfil.darknet.cc';
  } else if (key === 'safe_baseline') {
    document.getElementById('inputPhishUrl').value = 'https://mail.google.com/mail/u/0/#inbox';
    document.getElementById('inputPhishText').value = 'Hi Shiva, the project review meeting is confirmed for 3:00 PM in Conference Room B.';
    document.getElementById('inputUpiVpa').value = 'starbucks.coffee@icici';
    document.getElementById('inputUpiAmount').value = '340.00';
    document.getElementById('inputUpiContext').value = 'Payment for Cafe Latte';
    document.getElementById('inputNetIp').value = '142.250.190.46';
    document.getElementById('inputNetPort').value = '443';
    document.getElementById('inputNetBeacons').value = '1.2, 8.4, 0.4, 15.6, 3.1';
    document.getElementById('inputNetDns').value = 'google.com';
  }
}

/* ==========================================================================
   Form Submissions (Unified & Specialist)
   ========================================================================== */
function initFormSubmissions() {
  const formUnified = document.getElementById('formUnifiedInvestigation');
  if (formUnified) {
    formUnified.addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = document.getElementById('btnSubmitUnified');
      const originalBtnContent = submitBtn.innerHTML;

      submitBtn.disabled = true;
      submitBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> <span>Analyzing telemetry...</span>`;

      const payload = {
        phish: {
          url: document.getElementById('inputPhishUrl').value.trim(),
          text: document.getElementById('inputPhishText').value.trim()
        },
        upi: {
          vpa: document.getElementById('inputUpiVpa').value.trim(),
          amount: parseFloat(document.getElementById('inputUpiAmount').value) || 0,
          context: document.getElementById('inputUpiContext').value.trim()
        },
        network: {
          ip: document.getElementById('inputNetIp').value.trim(),
          port: parseInt(document.getElementById('inputNetPort').value) || 0,
          protocol: document.getElementById('inputNetProtocol').value,
          beacon_intervals: document.getElementById('inputNetBeacons').value.trim(),
          dns_query: document.getElementById('inputNetDns').value.trim()
        },
        title: 'Unified Multi-Vector Assessment'
      };

      try {
        const res = await fetch('/api/scan/unified', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        renderInvestigationResults(data);
        fetchIncidents();

        const resultsSection = document.getElementById('results');
        if (resultsSection) {
          resultsSection.scrollIntoView({ behavior: 'smooth' });
        }
      } catch (err) {
        console.error('Scan submission error:', err);
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnContent;
      }
    });
  }

  // Phish-only specialist form
  const formPhish = document.getElementById('formSpecialistPhish');
  if (formPhish) {
    formPhish.addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = document.getElementById('sPhishUrl').value.trim();
      const text = document.getElementById('sPhishText').value.trim();
      const res = await fetch('/api/scan/phish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, text })
      });
      const data = await res.json();
      renderSpecialistResult('phish', data);
    });
  }

  // UPI-only specialist form
  const formUpi = document.getElementById('formSpecialistUpi');
  if (formUpi) {
    formUpi.addEventListener('submit', async (e) => {
      e.preventDefault();
      const res = await fetch('/api/scan/upi', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vpa: document.getElementById('sUpiVpa').value.trim(),
          amount: parseFloat(document.getElementById('sUpiAmount').value) || 0,
          context: document.getElementById('sUpiContext').value.trim(),
          qr_payload: document.getElementById('sUpiQr').value.trim()
        })
      });
      const data = await res.json();
      renderSpecialistResult('upi', data);
    });
  }

  // Net-only specialist form
  const formNet = document.getElementById('formSpecialistNet');
  if (formNet) {
    formNet.addEventListener('submit', async (e) => {
      e.preventDefault();
      const res = await fetch('/api/scan/network', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: document.getElementById('sNetIp').value.trim(),
          port: parseInt(document.getElementById('sNetPort').value) || 0,
          protocol: document.getElementById('sNetProtocol').value,
          beacon_intervals: document.getElementById('sNetBeacons').value.trim(),
          dns_query: document.getElementById('sNetDns').value.trim()
        })
      });
      const data = await res.json();
      renderSpecialistResult('net', data);
    });
  }
}

function initKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      const activeSubmit = document.querySelector('.workspace-pane.active form button[type="submit"]');
      if (activeSubmit) activeSubmit.click();
    }
  });
}

/* ==========================================================================
   Results Renderer (Editorial & Clean)
   ========================================================================== */
function renderInvestigationResults(data) {
  // Hide empty state, reveal active content
  document.getElementById('resultsEmptyState').style.display = 'none';
  document.getElementById('resultsActiveContent').style.display = 'flex';

  const risk = data.risk || {};
  const score = risk.composite_score || 0;
  const decision = risk.decision || 'SAFE';
  const threatLevel = risk.threat_level || 'LOW';

  // 1. Incident reference ID
  document.getElementById('resultIncidentId').textContent = data.incident_id || 'CG-ACTIVE';

  // 2. Decision Banner
  const banner = document.getElementById('decisionBanner');
  const icon = document.getElementById('decisionIcon');
  const kicker = document.getElementById('decisionKicker');
  const title = document.getElementById('decisionTitle');
  const pill = document.getElementById('decisionSeverityPill');

  banner.className = 'decision-banner';
  pill.textContent = `${threatLevel} SEVERITY`;

  if (decision === 'ISOLATE') {
    banner.classList.add('state-isolate');
    icon.className = 'fa-solid fa-triangle-exclamation';
    kicker.textContent = 'AUTOMATED CONTAINMENT ENFORCED';
    title.textContent = 'PROTOCOL LOCKDOWN: HOST ISOLATED';
  } else if (decision === 'BLOCK') {
    banner.classList.add('state-block');
    icon.className = 'fa-solid fa-ban';
    kicker.textContent = 'PERIMETER INTERCEPT ACTIVE';
    title.textContent = 'HIGH SEVERITY THREAT BLOCKED';
  } else if (decision === 'WARN') {
    banner.classList.add('state-warn');
    icon.className = 'fa-solid fa-bell';
    kicker.textContent = 'ADVISORY ALERT DISPATCHED';
    title.textContent = 'SUSPICIOUS ANOMALY DETECTED';
  } else {
    banner.classList.add('state-safe');
    icon.className = 'fa-solid fa-shield-check';
    kicker.textContent = 'SECURITY BASELINE VERIFIED';
    title.textContent = 'EVENT ASSESSED AS BENIGN';
  }

  // 3. AI Diagnosis Summary
  document.getElementById('diagnosisSummaryText').textContent = data.ai_diagnosis || risk.explanation || '';

  // 4. Horizontal Risk Index Meter
  renderRiskMeter(score);
  document.getElementById('statBaselineAvg').textContent = (risk.baseline_score || 0).toFixed(1);
  document.getElementById('statCorrelationBoost').textContent = `+${risk.correlation_boost || 0} pts`;
  document.getElementById('statActionCode').textContent = risk.action_code || 'ALLOW';

  // 5. Correlated Evidence Anchors
  const evidenceContainer = document.getElementById('evidenceItemsContainer');
  const countBadge = document.getElementById('correlationsCountBadge');
  const correlations = data.correlations || [];

  if (correlations.length > 0) {
    countBadge.textContent = `${correlations.length} Link${correlations.length > 1 ? 's' : ''} Correlated`;
    evidenceContainer.innerHTML = correlations.map(c => `
      <div class="evidence-entry">
        <div class="evidence-type"><i class="fa-solid fa-link"></i> ${c.type} &bull; ${c.confidence} Confidence</div>
        <div class="evidence-desc">${c.details}</div>
      </div>
    `).join('');
  } else {
    countBadge.textContent = '0 Links Found';
    evidenceContainer.innerHTML = `<p class="text-muted" style="font-size: 13px;">No multi-vector correlation anchors identified across submitted signals.</p>`;
  }

  // 6. Automated Containment Actions Checklist
  const actionsContainer = document.getElementById('enforcedActionsList');
  const actions = risk.enforced_actions || [];
  if (actions.length > 0) {
    actionsContainer.innerHTML = actions.map(act => `
      <div class="action-item">
        <i class="fa-solid fa-circle-check text-rose"></i>
        <span>${act}</span>
      </div>
    `).join('');
  } else {
    actionsContainer.innerHTML = `<div class="action-item"><i class="fa-solid fa-check text-emerald"></i><span>Standard logging: Event permitted under normal policy.</span></div>`;
  }

  // 7. Specialist Engines Breakdown
  const modules = data.modules || {};
  renderSpecialistCard('Phish', modules.phish_shield);
  renderSpecialistCard('Upi', modules.upi_shield);
  renderSpecialistCard('Net', modules.net_sentinel);

  // 8. Attack Chain Timeline
  renderAttackChainTimeline(data);
}

function renderRiskMeter(score) {
  const scoreDisplay = document.getElementById('compositeScoreNumber');
  const fillBar = document.getElementById('riskMeterFill');

  fillBar.style.width = `${Math.min(100, Math.max(0, score))}%`;

  if (score >= 85) {
    fillBar.style.background = 'var(--color-danger)';
  } else if (score >= 65) {
    fillBar.style.background = '#dc2626';
  } else if (score >= 35) {
    fillBar.style.background = 'var(--color-warning)';
  } else {
    fillBar.style.background = 'var(--color-safe)';
  }

  // Counting animation
  const duration = 500;
  const start = currentRiskScore;
  const startTime = performance.now();

  function updateCount(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const ease = 1 - Math.pow(1 - progress, 3);
    const val = Math.round(start + (score - start) * ease);
    scoreDisplay.textContent = val;

    if (progress < 1) {
      requestAnimationFrame(updateCount);
    } else {
      currentRiskScore = score;
    }
  }

  requestAnimationFrame(updateCount);
}

function renderSpecialistCard(prefix, modData) {
  const scoreEl = document.getElementById(`spec${prefix}Score`);
  const verdictEl = document.getElementById(`spec${prefix}Verdict`);
  const flagsEl = document.getElementById(`spec${prefix}Flags`);

  if (!modData) {
    scoreEl.textContent = '--';
    verdictEl.textContent = 'Not Evaluated';
    verdictEl.style.color = 'var(--text-muted)';
    flagsEl.innerHTML = '';
    return;
  }

  const score = modData.risk_score || 0;
  scoreEl.textContent = `${score}/100`;
  verdictEl.textContent = modData.verdict || 'ANALYZED';

  if (score >= 65) verdictEl.style.color = 'var(--color-danger)';
  else if (score >= 35) verdictEl.style.color = 'var(--color-warning)';
  else verdictEl.style.color = 'var(--color-safe)';

  const allFlags = [];
  if (modData.details) {
    Object.values(modData.details).forEach(sub => {
      if (sub && Array.isArray(sub.flags)) allFlags.push(...sub.flags);
    });
  }

  flagsEl.innerHTML = allFlags.slice(0, 3).map(f => `
    <li title="${f}">&bull; ${f}</li>
  `).join('');
}

function renderSpecialistResult(type, data) {
  document.getElementById('resultsEmptyState').style.display = 'none';
  document.getElementById('resultsActiveContent').style.display = 'flex';

  const score = data.risk_score || 0;
  let dec = score >= 65 ? 'BLOCK' : score >= 35 ? 'WARN' : 'SAFE';
  let level = score >= 65 ? 'HIGH' : score >= 35 ? 'MEDIUM' : 'LOW';

  const banner = document.getElementById('decisionBanner');
  banner.className = `decision-banner state-${dec.toLowerCase()}`;
  document.getElementById('decisionKicker').textContent = `${type.toUpperCase()} VECTOR INSPECTION`;
  document.getElementById('decisionTitle').textContent = `${data.verdict || dec}`;
  document.getElementById('decisionSeverityPill').textContent = `${level} SEVERITY`;

  document.getElementById('diagnosisSummaryText').textContent = `${type.toUpperCase()} inspection completed. Calculated Risk Index: ${score}/100 with verdict ${data.verdict}.`;

  renderRiskMeter(score);
  document.getElementById('statBaselineAvg').textContent = score.toFixed(1);
  document.getElementById('statCorrelationBoost').textContent = '+0 pts';
  document.getElementById('statActionCode').textContent = dec;

  document.getElementById('correlationsCountBadge').textContent = 'Single Vector Scan';
  document.getElementById('evidenceItemsContainer').innerHTML = `<p class="text-muted" style="font-size: 13px;">Single module analysis. Cross-threat correlation is executed during Unified Scans.</p>`;

  renderSpecialistCard('Phish', type === 'phish' ? data : null);
  renderSpecialistCard('Upi', type === 'upi' ? data : null);
  renderSpecialistCard('Net', type === 'net' ? data : null);

  const resultsSection = document.getElementById('results');
  if (resultsSection) {
    resultsSection.scrollIntoView({ behavior: 'smooth' });
  }
}

/* ==========================================================================
   Attack Chain Timeline Flow
   ========================================================================== */
function renderAttackChainTimeline(data) {
  const container = document.getElementById('chainTimeline');
  const modules = data.modules || {};
  const correlations = data.correlations || [];
  const risk = data.risk || {};

  const steps = [];

  if (modules.phish_shield) {
    const pScore = modules.phish_shield.risk_score || 0;
    steps.push({
      title: 'Phishing Entry Hook',
      desc: pScore >= 45 ? 'Urgency Lure Detected' : 'Benign Message Profile',
      icon: 'fa-envelope-open-text',
      status: pScore >= 45 ? 'threat' : 'safe'
    });
  }

  if (modules.upi_shield) {
    const uScore = modules.upi_shield.risk_score || 0;
    steps.push({
      title: 'Payment Channel',
      desc: uScore >= 45 ? 'Reverse PIN Trap' : 'Verified Merchant VPA',
      icon: 'fa-indian-rupee-sign',
      status: uScore >= 45 ? 'threat' : 'safe'
    });
  }

  if (modules.net_sentinel) {
    const nScore = modules.net_sentinel.risk_score || 0;
    steps.push({
      title: 'Network Telemetry',
      desc: nScore >= 45 ? 'Active C2 Socket / Tunnel' : 'Standard Web Traffic',
      icon: 'fa-network-wired',
      status: nScore >= 45 ? 'threat' : 'safe'
    });
  }

  // Final containment node
  steps.push({
    title: 'CyberGuard Brain',
    desc: `Enforced: ${risk.decision || 'SAFE'}`,
    icon: 'fa-shield-halved',
    status: risk.decision === 'ISOLATE' || risk.decision === 'BLOCK' ? 'threat' : 'safe'
  });

  let html = '';
  steps.forEach((st, idx) => {
    const isThreat = st.status === 'threat';
    html += `
      <div class="chain-node">
        <div class="node-icon-circle" style="border-color: ${isThreat ? 'var(--color-danger)' : 'var(--color-safe)'}; color: ${isThreat ? 'var(--color-danger)' : 'var(--color-safe)'};">
          <i class="fa-solid ${st.icon}"></i>
        </div>
        <span class="node-title">${st.title}</span>
        <span class="node-desc">${st.desc}</span>
      </div>
    `;

    if (idx < steps.length - 1) {
      html += `<div class="chain-connector ${correlations.length > 0 ? 'active' : ''}"></div>`;
    }
  });

  container.innerHTML = html;
}

/* ==========================================================================
   Incident Table Management & Filtering
   ========================================================================== */
function initIncidentTable() {
  fetchIncidents();

  const filterBtns = document.querySelectorAll('.filter-btn');
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeIncidentFilter = btn.getAttribute('data-filter');
      renderIncidentTable();
    });
  });
}

async function fetchIncidents() {
  try {
    const res = await fetch('/api/incidents');
    const data = await res.json();
    cachedIncidents = data.incidents || [];
    renderIncidentTable();
    updateExecutiveMetrics();
  } catch (err) {
    console.error('Fetch incidents error:', err);
  }
}

function renderIncidentTable() {
  const tbody = document.getElementById('incidentTableBody');
  if (!tbody) return;

  let filtered = cachedIncidents;
  if (activeIncidentFilter === 'threats') {
    filtered = cachedIncidents.filter(inc => inc.decision === 'ISOLATE' || inc.decision === 'BLOCK');
  } else if (activeIncidentFilter === 'safe') {
    filtered = cachedIncidents.filter(inc => inc.decision === 'SAFE');
  }

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-table-row">
        <td colspan="6">
          <div class="table-empty-message">
            <i class="fa-regular fa-clipboard"></i>
            <span>No incidents matching "${activeIncidentFilter}" filter.</span>
          </div>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map((inc, i) => {
    let badgeClass = 'badge-safe';
    if (inc.decision === 'ISOLATE' || inc.decision === 'BLOCK') badgeClass = 'badge-danger';
    else if (inc.decision === 'WARN') badgeClass = 'badge-warning';

    return `
      <tr>
        <td class="cell-id">${inc.incident_id || 'CG-LOG'}</td>
        <td class="cell-title">${inc.title}</td>
        <td class="cell-score">${inc.composite_score}</td>
        <td><span class="badge ${badgeClass}">${inc.decision}</span></td>
        <td class="cell-time">${inc.timestamp || 'Just now'}</td>
        <td style="text-align: right;">
          <button class="btn btn-outline btn-xs" onclick="inspectHistoricIncident(${i})">
            <span>Inspect</span>
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

// Make accessible for inline onclick
window.inspectHistoricIncident = function(index) {
  const inc = cachedIncidents[index];
  if (!inc) return;

  // Render synthesized incident view
  const mockData = {
    incident_id: inc.incident_id,
    timestamp: inc.timestamp,
    incident_title: inc.title,
    risk: {
      composite_score: inc.composite_score,
      threat_level: inc.threat_level,
      decision: inc.decision,
      baseline_score: inc.composite_score,
      correlation_boost: inc.correlations_count > 0 ? 18 : 0,
      action_code: inc.decision === 'ISOLATE' ? 'QUARANTINE_AND_ISOLATE' : (inc.decision === 'BLOCK' ? 'BLOCK_THREAT' : 'ALLOW_EVENT'),
      explanation: `Historical logged assessment: ${inc.title}. Policy decision: ${inc.decision}.`,
      enforced_actions: inc.decision === 'ISOLATE' ? [
        "Terminated active socket connection on remote endpoint",
        "Dispatched domain IOC to perimeter DNS sinkhole",
        "Blacklisted fraudulent VPA handle at payment gateway level"
      ] : (inc.decision === 'BLOCK' ? [
        "Blocked outbound HTTP request to destination",
        "Rejected digital payment collect request"
      ] : [
        "Logged benign telemetry event under standard protocol"
      ])
    },
    modules: {},
    correlations: inc.correlations_count > 0 ? [
      {
        type: "HISTORIC_RECORDED_LINK",
        confidence: "VERIFIED",
        details: `Correlated multi-vector threat indicators recorded under incident ${inc.incident_id}.`
      }
    ] : [],
    ai_diagnosis: `Incident ${inc.incident_id} (${inc.title}) resulted in a composite risk score of ${inc.composite_score}/100 with policy enforcement: ${inc.decision}.`
  };

  renderInvestigationResults(mockData);

  const resultsSection = document.getElementById('results');
  if (resultsSection) {
    resultsSection.scrollIntoView({ behavior: 'smooth' });
  }
};

/* ==========================================================================
   Executive Metrics Update (Uses REAL Application Data)
   ========================================================================== */
function updateExecutiveMetrics() {
  const totalEvents = cachedIncidents.length;
  const activeThreats = cachedIncidents.filter(inc => inc.decision === 'ISOLATE' || inc.decision === 'BLOCK').length;
  const flaggedCount = cachedIncidents.filter(inc => inc.decision !== 'SAFE').length;

  const statEvents = document.getElementById('statEventsCount');
  const statThreats = document.getElementById('statThreatsCount');
  const statFlagged = document.getElementById('statFlaggedCount');
  const statPosture = document.getElementById('statPostureText');
  const statPostureDesc = document.getElementById('statPostureDesc');

  if (statEvents) statEvents.textContent = totalEvents;
  if (statThreats) statThreats.textContent = activeThreats;
  if (statFlagged) statFlagged.textContent = flaggedCount;

  if (statPosture && statPostureDesc) {
    if (activeThreats > 0) {
      statPosture.textContent = 'Threat Active';
      statPosture.className = 'metric-value text-rose';
      statPostureDesc.textContent = `${activeThreats} critical or high severity threats isolated.`;
    } else if (flaggedCount > 0) {
      statPosture.textContent = 'Heightened Alert';
      statPosture.className = 'metric-value text-amber';
      statPostureDesc.textContent = 'Suspicious anomalies detected; review recommended.';
    } else {
      statPosture.textContent = 'Optimal';
      statPosture.className = 'metric-value text-emerald';
      statPostureDesc.textContent = 'All systems conforming to verified safety baseline.';
    }
  }
}

async function fetchPlatformTelemetry() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    console.log('Platform status:', data.status, '| Brain Version:', data.brain_version);
  } catch (err) {
    console.error('Status fetch error:', err);
  }
}

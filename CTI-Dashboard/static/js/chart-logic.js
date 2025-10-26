

// --- Multi-Line Chart for Threats Over Time ---
async function renderThreatsChart() {
  const canvas = document.getElementById('threatsChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  // Prepare last 7 days labels
  const days = [];
  const today = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    days.push(d);
  }
  const labels = days.map(d => d.toLocaleDateString(undefined, {month:'short', day:'numeric'}));

  // Initialize counts
  const totalCounts = new Array(7).fill(0);
  const highCounts = new Array(7).fill(0);

  try {
    const res = await fetch('/api/iocs');
    if (!res.ok) throw new Error('Failed to fetch IOCs');
    const iocs = await res.json();

    iocs.forEach(ioc => {
      const ts = ioc.timestamp || ioc.time || ioc.created_at;
      if (!ts) return;
      const d = new Date(ts);
      if (isNaN(d)) return;
      // find index in last 7 days
      for (let idx = 0; idx < days.length; idx++) {
        const day = days[idx];
        if (d.getFullYear() === day.getFullYear() && d.getMonth() === day.getMonth() && d.getDate() === day.getDate()) {
          totalCounts[idx] += 1;
          // Determine high-risk
          const vt = ioc.virustotal && ioc.virustotal.data ? ioc.virustotal.data : ioc.virustotal || {};
          const abuse = ioc.abuseipdb && ioc.abuseipdb.data ? ioc.abuseipdb.data : ioc.abuseipdb || {};
          const otx = ioc.otx || {};
          const vtStats = (vt && vt.attributes && vt.attributes.last_analysis_stats) ? vt.attributes.last_analysis_stats : (vt.last_analysis_stats || {});
          const malicious = vtStats.malicious || 0;
          const abuseScore = abuse.abuseConfidenceScore || 0;
          const otxPulse = otx.pulse_info && otx.pulse_info.count ? otx.pulse_info.count : 0;
          if (malicious > 0 || abuseScore > 50 || otxPulse > 0) highCounts[idx] += 1;
          break;
        }
      }
    });
  } catch (err) {
    console.warn('Could not fetch IOCs for threats chart, using sample data.', err);
    // Fallback static sample
    return new Chart(ctx, {
      type: 'line',
      data: {
        labels: ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'],
        datasets: [
          {label:'Total IOCs', data:[4,6,3,5,2,7,4], borderColor:'#3b82f6', backgroundColor:'rgba(59,130,246,0.08)', fill:true, tension:0.4, pointRadius:4},
          {label:'High-risk', data:[1,2,0,1,0,3,1], borderColor:'#f8576c', backgroundColor:'rgba(248,87,108,0.08)', fill:true, tension:0.4, pointRadius:4}
        ]
      },
      options: {
        plugins: {legend: {labels:{color:'#e0e6f3'}}},
        scales: {x: {ticks:{color:'#e0e6f3'}}, y: {ticks:{color:'#e0e6f3'}}}
      }
    });
  }

  // Create chart with aggregated data
  new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {label:'Total IOCs', data: totalCounts, borderColor:'#3b82f6', backgroundColor:'rgba(59,130,246,0.08)', fill:true, tension:0.4, pointRadius:4},
        {label:'High-risk', data: highCounts, borderColor:'#f8576c', backgroundColor:'rgba(248,87,108,0.08)', fill:true, tension:0.4, pointRadius:4}
      ]
    },
    options: {
      plugins: {legend: {labels:{color:'#e0e6f3'}}},
      scales: {x: {ticks:{color:'#e0e6f3'}}, y: {ticks:{color:'#e0e6f3'}}}
    }
  });
}

// --- Circular Progress for Security Score ---
function renderScoreChart(score = 72, info = {}) {
  const scoreContainer = document.querySelector('.dashboard-score');
  if (!scoreContainer) return;
  scoreContainer.innerHTML = '';
  // Create SVG for circular progress bar (compact size)
  const size = 140; // smaller to fit the compact widget
  const strokeWidth = 12;
  const radius = (size/2) - strokeWidth;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.max(0, Math.min(score, 100));
  const offset = circumference * (1 - progress / 100);
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.innerHTML = `
    <circle cx="${size/2}" cy="${size/2}" r="${radius}" stroke="#22305a" stroke-width="${strokeWidth}" fill="none" />
    <circle cx="${size/2}" cy="${size/2}" r="${radius}" stroke="#3b82f6" stroke-width="${strokeWidth}" fill="none" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" stroke-linecap="round" />
    <text x="50%" y="50%" text-anchor="middle" dy=".3em" font-size="1.6em" font-family="Segoe UI,Roboto,Arial,sans-serif" font-weight="700" fill="#3b82f6">${score}%</text>
  `;
  scoreContainer.appendChild(svg);
  // Add a useful label and short description beneath the circular bar
  let labelText = 'Low';
  let descText = 'No significant issues detected.';
  if (score >= 70) { labelText = 'High'; descText = 'High risk — investigate immediately.'; }
  else if (score >= 40) { labelText = 'Medium'; descText = 'Some suspicious activity — review and monitor.'; }

  const labelDiv = document.createElement('div');
  labelDiv.className = 'dashboard-score-label';
  labelDiv.textContent = labelText;
  // small description
  const descDiv = document.createElement('div');
  descDiv.style.cssText = 'font-size:0.95em;color:#b0b8c9;margin-top:8px;text-align:center;max-width:160px;';
  descDiv.textContent = descText;
  scoreContainer.appendChild(labelDiv);
  scoreContainer.appendChild(descDiv);
  // Populate the collapsible details panel (separate container)
  const details = document.getElementById('scoreDetails');
  if (details) {
    details.innerHTML = '';
    // IP / country / isp / reputation block
    if (info && (info.ip || info.country || info.isp || info.reputation)) {
      const infoDiv = document.createElement('div');
      infoDiv.className = 'dashboard-score-info';
      if (info.ip) infoDiv.innerHTML += `<div style="font-weight:600;color:#fff;text-align:center;">${info.ip}</div>`;
      if (info.country) infoDiv.innerHTML += `<div style="font-size:0.95em;color:#b0b8c9;text-align:center;">Country: ${info.country}</div>`;
      if (info.isp) infoDiv.innerHTML += `<div style="font-size:0.95em;color:#b0b8c9;text-align:center;">ISP: ${info.isp}</div>`;
      if (info.reputation) infoDiv.innerHTML += `<div style="font-size:0.9em;color:#9fb0d9;margin-top:6px;text-align:center;">Reputation: ${info.reputation}</div>`;
      details.appendChild(infoDiv);
    }

    // Technical summary
    if (info && (info.vt || info.abuse || info.otx || info.level || info.summary)) {
      const techDiv = document.createElement('div');
      techDiv.className = 'dashboard-score-tech';
      if (info.vt) {
        techDiv.innerHTML += `<div><b>VT:</b> Malicious: ${info.vt.malicious||0}, Harmless: ${info.vt.harmless||0}, Suspicious: ${info.vt.suspicious||0}, Undetected: ${info.vt.undetected||0}</div>`;
      }
      if (info.abuse) {
        techDiv.innerHTML += `<div><b>AbuseIPDB:</b> Score: ${info.abuse.score||0}, Reports: ${info.abuse.reports||'-'}</div>`;
      }
      if (info.otx) {
        techDiv.innerHTML += `<div><b>OTX:</b> Pulses: ${info.otx.pulses||0}</div>`;
      }
      if (info.level) {
        techDiv.innerHTML += `<div style="margin-top:6px;color:#3b82f6;"><b>Level:</b> ${info.level}</div>`;
      }
      if (info.summary) {
        techDiv.innerHTML += `<div style="margin-top:6px;color:#b0b8c9;font-size:0.9em">${info.summary}</div>`;
      }
      details.appendChild(techDiv);
    }
  // keep collapsed by default when rendering from startup
  details.classList.remove('expanded');
  details.classList.add('collapsed');
  details.setAttribute('aria-hidden', 'true');
  }
}

// --- Donut Chart for Top Risk Categories ---
function renderRiskChart() {
  const ctx = document.getElementById('riskChart').getContext('2d');
  const data = {
    labels: ['Search Engine','Direct','Email','Video Ads'],
    datasets: [{
      data: [2234,243,641,1554],
      backgroundColor: ['#3b82f6','#8e24aa','#00e6e6','#43a047'],
      borderWidth: 0
    }]
  };
  new Chart(ctx, {
    type: 'doughnut',
    data,
    options: {
      cutout: '70%',
      plugins: {legend: {display: false}},
      responsive: false
    }
  });
  // Legend
  const legend = document.getElementById('riskLegend');
  legend.innerHTML = '';
  data.labels.forEach((label, i) => {
    legend.innerHTML += `<div class="dashboard-legend-item"><span class="dashboard-legend-color" style="background:${data.datasets[0].backgroundColor[i]}"></span> ${label} <span style="margin-left:auto;">${data.datasets[0].data[i]}</span></div>`;
  });
}

// --- Donut Chart for Top Vendors ---
function renderVendorChart() {
  const ctx = document.getElementById('vendorChart').getContext('2d');
  const data = {
    labels: ['Search Engine','Direct','Email','Video Ads'],
    datasets: [{
      data: [2234,243,641,1554],
      backgroundColor: ['#f8576c','#fbc02d','#00e6e6','#43e97b'],
      borderWidth: 0
    }]
  };
  new Chart(ctx, {
    type: 'doughnut',
    data,
    options: {
      cutout: '70%',
      plugins: {legend: {display: false}},
      responsive: false
    }
  });
  // Legend
  const legend = document.getElementById('vendorLegend');
  legend.innerHTML = '';
  data.labels.forEach((label, i) => {
    legend.innerHTML += `<div class="dashboard-legend-item"><span class="dashboard-legend-color" style="background:${data.datasets[0].backgroundColor[i]}"></span> ${label} <span style="margin-left:auto;">${data.datasets[0].data[i]}</span></div>`;
  });
}

// Render all widgets on load

// Render all widgets on load
document.addEventListener('DOMContentLoaded', function() {
  renderThreatsChart();
  renderScoreChart();
  if (document.getElementById('riskChart')) renderRiskChart();
  if (document.getElementById('vendorChart')) renderVendorChart();

  // Fetch and render Recent IOCs from backend
  fetch('/api/iocs')
    .then(res => res.json())
    .then(iocs => {
      const list = document.getElementById('recentIocList');
      if (!list) return;
      list.innerHTML = '';
      if (!iocs.length) {
        list.innerHTML = '<li style="color:#b0b8c9;">No recent IOCs found.</li>';
        return;
      }
      iocs.forEach(ioc => {
        // Determine label and tag
          let label = ioc.ip || ioc.domain || ioc.query || 'Unknown';
          // Default to Low
          let tag = 'low';
          let tagText = 'Low';
          // High priority if VT reports malicious
          if (ioc.virustotal && ioc.virustotal.malicious > 0) {
            tag = 'high'; tagText = 'High';
          // Medium if AbuseIPDB confidence or OTX pulses indicate suspicious activity
          } else if ((ioc.abuseipdb && ioc.abuseipdb.abuseConfidenceScore > 50) || (ioc.otx && ioc.otx.pulse_info && ioc.otx.pulse_info.count > 0)) {
            tag = 'medium'; tagText = 'Medium';
          // Keep specific labels for malware/backdoor when those indicators appear
          } else if (ioc.virustotal && ioc.virustotal.suspicious > 0) {
            tag = 'malware'; tagText = 'Malware';
          } else if (ioc.virustotal && ioc.virustotal.undetected > 0) {
            tag = 'backdoor'; tagText = 'Backdoor';
          }
          list.innerHTML += `<li><span>${label}</span> <span class="activity-tag ${tag}">${tagText}</span></li>`;
      });
    })
    .catch(() => {
      const list = document.getElementById('recentIocList');
      if (list) list.innerHTML = '<li style="color:#b0b8c9;">Failed to load IOCs.</li>';
    });

  // score details are controlled programmatically on lookup (auto-expand)
});

// --- Donut Chart for Recent IOCs ---
function renderRecentIocDonut() {
  const ctx = document.getElementById('recentIocDonut').getContext('2d');
  // Example data: High, Medium, Low
  const data = {
    labels: ['High','Medium','Low'],
    datasets: [{
      data: [4, 8, 12],
      backgroundColor: ['#e53935','#fbc02d','#43a047'],
      borderWidth: 0
    }]
  };
  new Chart(ctx, {
    type: 'doughnut',
    data,
    options: {
      cutout: '70%',
      plugins: {legend: {display: true, labels:{color:'#e0e6f3'}}},
      responsive: false
    }
  });
  // Points display
  document.getElementById('recentIocPoints').textContent = `Total IOCs: ${data.datasets[0].data.reduce((a,b)=>a+b,0)}`;
}

// --- Donut Chart for IOC Score ---
function renderIocScoreDonut() {
  const ctx = document.getElementById('iocScoreDonut').getContext('2d');
  // Example: Score out of 100
  const score = 72;
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Score','Remainder'],
      datasets: [{
        data: [score, 100-score],
        backgroundColor: ['#3b82f6','#22305a'],
        borderWidth: 0
      }]
    },
    options: {
      cutout: '80%',
      plugins: {legend: {display: false}},
      rotation: -90,
      circumference: 180,
      responsive: false
    }
  });
  document.getElementById('iocScoreValue').textContent = `${score}%`;
}

// Render new widgets

// Removed calls to donut charts since their canvases are no longer present

// Lookup button event: show result in right panel and circular progress in left panel
document.getElementById('lookupBtn').addEventListener('click', async ()=>{
  try {
    const q = document.getElementById('queryInput').value.trim();
    if(!q) {
      alert('Enter IP or domain');
      console.warn('No query entered');
      return;
    }
    const res = await fetch('/api/lookup', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({query: q})
    });
    if (!res.ok) {
      alert('Lookup request failed: ' + res.status);
      console.error('Lookup request failed:', res.status, res.statusText);
      return;
    }
    const j = await res.json();
    const resultDiv = document.getElementById('resultPre');
    const progressDiv = document.getElementById('progressCol');
    // Improved display
    if(j.data && j.data.query) {
      const vt = j.data.virustotal && j.data.virustotal.data ? j.data.virustotal.data : {};
      const abuse = j.data.abuseipdb && j.data.abuseipdb.data ? j.data.abuseipdb.data : {};
      const otx = j.data.otx ? j.data.otx : {};
      let vtStats = vt.last_analysis_stats || {};
      let vtMalicious = vtStats.malicious || 0;
      let vtHarmless = vtStats.harmless || 0;
      let vtSuspicious = vtStats.suspicious || 0;
      let vtUndetected = vtStats.undetected || 0;
      let vtTotal = vtMalicious + vtHarmless + vtSuspicious + vtUndetected;
      let abuseScore = abuse.abuseConfidenceScore || 0;
      let abuseReports = abuse.totalReports || '-';
      let otxPulse = otx.pulse_info && otx.pulse_info.count ? otx.pulse_info.count : 0;
      let reputation = vt.reputation || otx.reputation || '-';
      let country = abuse.countryCode || otx.country_code || vt.country || '-';
      let isp = abuse.isp || (vt.attributes ? vt.attributes.as_owner : '-');
      let level = 'Low';
      if (vtMalicious > 0) level = 'High';
      else if (abuseScore > 50 || otxPulse > 0) level = 'Medium';
      // Calculate threat percent for progress bar
      let threatPercent = 0;
      if (level === 'High') threatPercent = 90;
      else if (level === 'Medium') threatPercent = 60;
      else threatPercent = 20;
      // Render circular progress bar in Security Score widget with full info
      renderScoreChart(threatPercent, {
        ip: j.data.query,
        country: country,
        isp: isp,
        reputation: reputation,
        vt: {malicious: vtMalicious, harmless: vtHarmless, suspicious: vtSuspicious, undetected: vtUndetected, total: vtTotal},
        abuse: {score: abuseScore, reports: abuseReports},
        otx: {pulses: otxPulse},
        level: level,
        summary: (level==='High' ? 'This IP/domain is flagged as HIGH risk. Immediate investigation recommended.' :
                 level==='Medium' ? 'This IP/domain shows signs of suspicious or abusive activity.' :
                 'No significant threat detected. Routine monitoring advised.')
      });

      // Auto-expand the score details container when a lookup completes
      const scoreDetailsElem = document.getElementById('scoreDetails');
      if (scoreDetailsElem) {
        scoreDetailsElem.classList.remove('collapsed');
        scoreDetailsElem.classList.add('expanded');
        scoreDetailsElem.setAttribute('aria-hidden', 'false');
      }

      // Clear bottom result panel (we now show details in the Security Score widget)
      if (resultDiv) resultDiv.innerHTML = '';
    } else {
  if (resultDiv) resultDiv.innerHTML = '<div class="alert alert-warning">No data found for this query.</div>';
      alert('No data found for this query.');
      console.warn('No data in response:', j);
    }
  } catch (err) {
    alert('Error during lookup: ' + err);
    console.error('Error during lookup:', err);
  }
});

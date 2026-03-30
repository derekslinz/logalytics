let allSessions = [];
let filteredSessions = [];
let allNotable = [];
let map, markers = [];
let statusChart, volumeChart, typeChart;
let currentFilter = 'all';
let isPlaying = false;
let playInterval;
const BLOCKED_COUNTRIES = (window.APP_CONFIG && window.APP_CONFIG.BLOCKED_COUNTRIES) 
    ? window.APP_CONFIG.BLOCKED_COUNTRIES 
    : ['RU', 'BY', 'KZ', 'BR', 'IN', 'CN', 'PH', 'ID', 'IR', 'KP', 'VN', 'NG'];

async function init() {
    if (typeof ChartDataLabels !== 'undefined') {
        Chart.register(ChartDataLabels);
    }
    
    try {
        const response = await fetch('data.json');
        if (!response.ok) throw new Error("Fetch failed: " + response.status);
        const data = await response.json();
        const IGNORE_IPS = ['::1', '127.0.0.1', '0.0.0.0'];
        allSessions = (data.sessions || []).filter(s => !IGNORE_IPS.includes(s.origin_ip));
        const summary = data.summary || {};
        
        if (allSessions.length === 0) {
            setupMap();
            return;
        }

        // Sort by last seen
        allSessions.sort((a, b) => new Date(a.last_seen_iso) - new Date(b.last_seen_iso));
        
        document.getElementById('timeline-slider').value = 100;

        setupMap();
        setupCharts();
        setupEvents();
        updateDashboard();
        allNotable = data.notable || [];
        updateNotableDomains(allNotable);
    } catch (e) {
        console.error("Dashboard initialization error:", e);
    }
}

function setupMap() {
    map = L.map('map', {
        zoomControl: false,
        attributionControl: false
    }).setView([20, 0], 2);

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 19
    }).addTo(map);

    // Blocked Country Shading
    fetch('countries.geojson')
        .then(res => res.json())
        .then(geoData => {
            L.geoJson(geoData, {
                style: function(feature) {
                    const code = (feature.properties.iso_a2 || feature.properties.ISO_A2 || '').toUpperCase();
                    if (BLOCKED_COUNTRIES.includes(code)) {
                        return {
                            fillColor: '#f43f5e',
                            weight: 1,
                            opacity: 1,
                            color: '#f43f5e',
                            fillOpacity: 0.3
                        };
                    }
                    return { opacity: 0, fillOpacity: 0 };
                },
                onEachFeature: function(feature, layer) {
                    const code = (feature.properties.iso_a2 || feature.properties.ISO_A2 || '').toUpperCase();
                    if (BLOCKED_COUNTRIES.includes(code)) {
                        layer.bindTooltip("BLOCKED", { permanent: true, direction: "center", className: "blocked-label" });
                    }
                }
            }).addTo(map);
        });
}

function setupCharts() {
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { display: false },
            datalabels: {
                color: '#fff',
                formatter: (value, ctx) => {
                    const sum = ctx.dataset.data.reduce((a, b) => a + b, 0);
                    if (sum === 0) return '';
                    const percentage = (value * 100 / sum).toFixed(0) + "%";
                    return value > 0 ? `${ctx.chart.data.labels[ctx.dataIndex]}\n${percentage}` : '';
                },
                font: { weight: 'bold', size: 10 },
                textAlign: 'center'
            }
        },
        cutout: '60%'
    };

    const ctxStatus = document.getElementById('statusChart').getContext('2d');
    statusChart = new Chart(ctxStatus, {
        type: 'doughnut',
        data: {
            labels: ['2xx', '3xx', '4xx', '5xx'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#00f2ff', '#ffaa00', '#f43f5e', '#8b5cf6'],
                borderWidth: 0,
                spacing: 4
            }]
        },
        options: chartOptions
    });

    const ctxType = document.getElementById('typeChart').getContext('2d');
    typeChart = new Chart(ctxType, {
        type: 'doughnut',
        data: {
            labels: ['Legit', 'Bots', 'Malicious'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#00f2ff', '#ffaa00', '#f43f5e'],
                borderWidth: 0,
                spacing: 4
            }]
        },
        options: chartOptions
    });

    const ctxVolume = document.getElementById('volumeChart').getContext('2d');
    volumeChart = new Chart(ctxVolume, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Requests',
                data: [],
                backgroundColor: 'rgba(0, 242, 255, 0.4)',
                borderColor: '#00f2ff',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false }, datalabels: { display: false } },
            scales: { x: { display: false }, y: { display: false } }
        }
    });
}

function updateDashboard() {
    const sliderVal = document.getElementById('timeline-slider').value;
    const total = allSessions.length;
    if (total === 0) return;
    
    const maxIdx = Math.floor((total - 1) * (sliderVal / 100));
    
    filteredSessions = allSessions.slice(0, maxIdx + 1).filter(s => {
        if (currentFilter === 'legitimate') return !s.geo.is_bot && !s.is_malicious && !s.geo.is_cloud && !s.geo.is_hosting;
        if (currentFilter === 'cloud') return s.geo.is_cloud && !s.is_bot && !s.is_malicious;
        if (currentFilter === 'hosting') return s.geo.is_hosting && !s.is_bot && !s.is_malicious;
        if (currentFilter === 'bots') return s.geo.is_bot;
        if (currentFilter === 'malicious') return s.is_malicious;
        return true;
    });

    document.getElementById('total-req').innerText = filteredSessions.reduce((acc, s) => acc + s.req_count, 0).toLocaleString();
    const uniqueIPs = new Set(filteredSessions.map(s => s.origin_ip)).size;
    document.getElementById('unique-ips').innerText = uniqueIPs.toLocaleString();

    if (total > 0 && allSessions[0] && allSessions[maxIdx]) {
        document.getElementById('start-time').innerText = formatDate(new Date(allSessions[0].first_seen_iso));
        document.getElementById('current-time').innerText = formatDate(new Date(allSessions[maxIdx].last_seen_iso));
        document.getElementById('end-time').innerText = formatDate(new Date(allSessions[allSessions.length - 1].last_seen_iso));
    }

    updateMarkers();
    updateChartsData();
    updateLogFeed();
    updateCountryReport();
    updateTopPaths();
}

function updateMarkers() {
    markers.forEach(m => map.removeLayer(m));
    markers = [];

    filteredSessions.filter(s => s.geo && s.geo.lat).slice(-150).forEach(s => {
        const ttype = getTrafficType(s);
        const color = TRAFFIC_COLORS[ttype];
        const isBlocked = BLOCKED_COUNTRIES.includes(s.geo.country_code);
        const blockedBadge = isBlocked ? '<span style="background: #f43f5e; color: #fff; padding: 1px 5px; border-radius: 3px; font-size: 0.65rem; font-weight: 700; letter-spacing: 0.05em; margin-left: 4px;">BLOCKED</span>' : '';

        const popupContent = `
            <div style="font-family: inherit; font-size: 0.8rem;">
                <b style="color: var(--accent-color)">${s.origin_ip}</b>${blockedBadge}<br>
                <span style="font-size: 0.7rem; opacity: 0.7;">Edge: ${s.edge_ip}</span><br>
                <b>${s.geo.hostname || 'No RDNS'}</b><br>
                ${s.geo.asn_name || ('AS' + (s.geo.asn || '?'))}<br>
                ${s.geo.city || 'Unknown'}, ${s.geo.country}<br>
                <div style="margin-top: 5px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 5px;">
                    Intent: <span style="color: ${color}">${s.intent}</span><br>
                    Hits: ${s.req_count} | Rate: ${s.req_rate} RPS
                </div>
            </div>
        `;

        const marker = L.circleMarker([s.geo.lat, s.geo.lon], {
            radius: Math.min(20, 5 + Math.sqrt(s.req_count)),
            fillColor: color, color: color, weight: 1,
            opacity: 0.8, fillOpacity: 0.4
        }).bindPopup(popupContent);
        
        marker.addTo(map);
        markers.push(marker);
    });
}

function updateChartsData() {
    const legit = filteredSessions.filter(s => !s.geo.is_bot && !s.is_malicious && !s.geo.is_cloud && !s.geo.is_hosting).length;
    const cloud = filteredSessions.filter(s => s.geo.is_cloud && !s.geo.is_bot && !s.geo.is_malicious).length;
    const hosting = filteredSessions.filter(s => s.geo.is_hosting && !s.geo.is_bot && !s.geo.is_malicious).length;
    const bots = filteredSessions.filter(s => s.geo.is_bot).length;
    const malicious = filteredSessions.filter(s => s.is_malicious).length;
    
    // Update Labels as well in case they changed
    typeChart.data.labels = ['Legit', 'Cloud', 'Hosting', 'Bots', 'Malicious'];
    typeChart.data.datasets[0].data = [legit, cloud, hosting, bots, malicious];
    typeChart.data.datasets[0].backgroundColor = ['#00f2ff', '#a855f7', '#22c55e', '#ffaa00', '#f43f5e'];
    typeChart.update();

    const volumeData = new Array(30).fill(0);
    const bucketSize = Math.max(1, Math.floor(allSessions.length / 30));
    filteredSessions.forEach((s, i) => {
        const bucketIdx = Math.floor(i / bucketSize);
        if (bucketIdx < 30) volumeData[bucketIdx] += s.req_count;
    });
    volumeChart.data.labels = volumeData.map((_, i) => i);
    volumeChart.data.datasets[0].data = volumeData;
    volumeChart.update();
}

const IGNORED_RDNS = ['censys-scanner.com', 'internet-measurement.com'];

const CLOUD_PROVIDERS = {
    'Amazon':      ['AS14618', 'AS16509'],
    'Google':      ['AS396982', 'AS15169'],
    'Microsoft':   ['AS8075'],
    'Cloudflare':  ['AS13335', 'AS132892'],
    'DigitalOcean':['AS14061'],
    'Akamai':      ['AS63949'],
    'OVH':         ['AS16276'],
    'Hetzner':     ['AS24940'],
    'Contabo':     ['AS141995', 'AS51167', 'AS40021'],
    'Alibaba':     ['AS37963']
};

function getASN(label) {
    const m = label.match(/AS(\d+)/);
    return m ? 'AS' + m[1] : null;
}

function categorizeNotable(notable) {
    const rdns = [], majorCloud = {}, otherHosting = [];

    notable.forEach(n => {
        if (n.label.startsWith('Verified')) return;
        if (n.label.startsWith('RDNS:')) {
            if (IGNORED_RDNS.some(d => n.label.includes(d))) return;
            rdns.push(n);
            return;
        }
        if (!n.label.startsWith('ASN:')) return;

        const asn = getASN(n.label);
        let matched = false;
        for (const [provider, asns] of Object.entries(CLOUD_PROVIDERS)) {
            if (asns.includes(asn)) {
                if (!majorCloud[provider]) majorCloud[provider] = { label: provider, ips: [], count: 0 };
                majorCloud[provider].ips.push(...n.ips);
                majorCloud[provider].count += n.count;
                matched = true;
                break;
            }
        }
        if (!matched) otherHosting.push(n);
    });

    const cloud = Object.values(majorCloud).sort((a, b) => b.count - a.count);
    return { rdns, cloud, otherHosting };
}

const TRAFFIC_COLORS = {
    malicious: '#f43f5e',
    bot: '#ffaa00',
    cloud: '#a855f7',
    hosting: '#22c55e',
    legit: '#00f2ff'
};

const MALICIOUS_PATHS = [
    /\/wp-admin/i, /\/wp-login/i, /\/wp-content/i, /\/wp-json/i, /\/wp-config/i, /\/xmlrpc\.php/i,
    /\/wordpress\//i,
    /\/\.env/i, /\/\.git\//i, /\/\.streamlit\//i,
    /\/cgi-bin\//i, /\/HNAP/i, /\/SDK\//i, /\/sdk$/i,
    /\/admin\.php/i, /\/login$/i, /\/admin$/i, /\/dashboard$/i, /\/hudson$/i, /\/user$/i,
    /\/swagger\.json/i, /\/api\/v\d+\/config/i, /\/api\/v\d+\/\.env/i,
    /\/evox\//i, /\/nmaplowercheck/i,
    /\/fetch\.php/i, /\/sw\.php/i, /\/cnusw\.php/i, /\/ass\.php/i, /\/cabs\.php/i,
    /\/x1da\.php/i, /\/aa2\.php/i, /\/fffff\.php/i, /\/jp\.php/i, /\/19\.php/i,
    /\/100\.php/i, /\/xwx1\.php/i,
    /\/developmentserver\//i, /\/luci\//i,
    /^http:/i, /^\*$/
];

function isScannerTraffic(session) {
    return session.path_summary && session.path_summary.some(p =>
        MALICIOUS_PATHS.some(rx => rx.test(p))
    );
}

function getTrafficType(session) {
    if (session.is_malicious || isScannerTraffic(session)) return 'malicious';
    if (session.geo.is_bot) return 'bot';
    if (session.geo.is_cloud) return 'cloud';
    if (session.geo.is_hosting) return 'hosting';
    return 'legit';
}

function buildIpTypeMap() {
    const ipMap = {};
    allSessions.forEach(s => {
        ipMap[s.origin_ip] = getTrafficType(s);
    });
    return ipMap;
}

function getDominantType(ips, ipMap) {
    const counts = {};
    ips.forEach(ip => {
        const t = ipMap[ip] || 'legit';
        counts[t] = (counts[t] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
}

function buildIpGeoMap() {
    const geoMap = {};
    allSessions.forEach(s => {
        const g = s.geo;
        const parts = [];
        if (g.city) parts.push(g.city);
        if (g.country_code) parts.push(g.country_code);
        geoMap[s.origin_ip] = parts.join(', ') || null;
    });
    return geoMap;
}

function getTopLocations(ips, geoMap, max) {
    const counts = {};
    ips.forEach(ip => {
        const loc = geoMap[ip];
        if (loc) counts[loc] = (counts[loc] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, max).map(e => e[0]);
}

function getSearchQuery(notable) {
    if (notable.label.startsWith('RDNS:')) {
        return notable.ips[0];
    }
    const m = notable.label.match(/AS\d+/);
    return m ? m[0] : notable.label;
}

function renderNotableList(items, limit) {
    const ipMap = buildIpTypeMap();
    const geoMap = buildIpGeoMap();
    const list = limit ? items.slice(0, limit) : items;
    const isModal = !limit;
    return list.map(n => {
        const shortLabel = n.label.replace(/^(RDNS|ASN): /, '').replace(/ \(unverified\)/, '').replace(/ \| Actor: unknown/, '').replace(/ \| Confidence: /, ' | ');
        const dominant = getDominantType(n.ips, ipMap);
        const color = TRAFFIC_COLORS[dominant];
        if (!isModal) {
            return `<div style="margin-bottom: 0.75rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem;">
                <div style="display: flex; justify-content: space-between; font-size: 0.75rem;">
                    <span title="${n.label}" style="color: ${color}; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 180px;">${shortLabel}</span>
                    <span style="color: ${color}; white-space: nowrap; margin-left: 8px;">${n.count} IPs</span>
                </div>
            </div>`;
        }
        const locations = getTopLocations(n.ips, geoMap, 3);
        const locStr = locations.length ? locations.join(' / ') : 'Unknown';
        const query = encodeURIComponent(getSearchQuery(n));
        const ipsAttr = n.ips.map(ip => ip).join(',');
        return `<div class="notable-row" data-ips="${ipsAttr}" style="margin-bottom: 0.75rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem; cursor: pointer;">
            <div style="display: flex; justify-content: space-between; align-items: baseline; font-size: 0.8rem;">
                <div style="min-width: 0; flex: 1;">
                    <a href="https://www.google.com/search?q=${query}" target="_blank" rel="noopener" style="color: ${color}; text-decoration: none; border-bottom: 1px dashed rgba(255,255,255,0.15);" title="Search Google for ${query}" onclick="event.stopPropagation();">${shortLabel}</a>
                    <i data-lucide="chevron-down" style="width: 12px; height: 12px; display: inline-block; vertical-align: -2px; opacity: 0.4; margin-left: 4px;"></i>
                    <div style="font-size: 0.7rem; color: var(--text-secondary); margin-top: 2px;">
                        <i data-lucide="map-pin" style="width: 10px; height: 10px; display: inline-block; vertical-align: -1px;"></i> ${locStr}
                    </div>
                </div>
                <span style="color: ${color}; white-space: nowrap; margin-left: 12px; font-weight: 600;">${n.count} IPs</span>
            </div>
            <div class="notable-detail" style="display: none; margin-top: 0.5rem;"></div>
        </div>`;
    }).join('');
}

function renderIpDetailTable(ipList) {
    const sessionsByIp = {};
    filteredSessions.forEach(s => {
        if (!ipList.includes(s.origin_ip)) return;
        if (!sessionsByIp[s.origin_ip]) {
            sessionsByIp[s.origin_ip] = { ip: s.origin_ip, reqs: 0, hostname: s.geo.hostname || '', city: s.geo.city || '', cc: s.geo.country_code || '', type: getTrafficType(s), firstSeen: s.first_seen_iso, lastSeen: s.last_seen_iso, paths: new Set() };
        }
        sessionsByIp[s.origin_ip].reqs += s.req_count;
        if (s.last_seen_iso > sessionsByIp[s.origin_ip].lastSeen) sessionsByIp[s.origin_ip].lastSeen = s.last_seen_iso;
        if (s.first_seen_iso < sessionsByIp[s.origin_ip].firstSeen) sessionsByIp[s.origin_ip].firstSeen = s.first_seen_iso;
        s.path_summary.forEach(p => sessionsByIp[s.origin_ip].paths.add(p));
    });
    const ips = Object.values(sessionsByIp).sort((a, b) => b.reqs - a.reqs);
    if (!ips.length) return '<div style="font-size: 0.7rem; color: var(--text-secondary); padding: 8px 0;">No sessions in current filter</div>';
    return `<table style="width: 100%; font-size: 0.7rem;">
        <thead><tr>
            <th style="text-align: left; padding: 4px 6px; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);">IP</th>
            <th style="text-align: left; padding: 4px 6px; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);">Type</th>
            <th style="text-align: right; padding: 4px 6px; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);">Reqs</th>
            <th style="text-align: left; padding: 4px 6px; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);">Last Seen</th>
            <th style="text-align: left; padding: 4px 6px; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);">Paths</th>
        </tr></thead>
        <tbody>${ips.map(ip => {
            const color = TRAFFIC_COLORS[ip.type];
            const isBlocked = BLOCKED_COUNTRIES.includes(ip.cc) || ip.type === 'malicious';
            const blk = isBlocked ? ' <span style="background: #f43f5e; color: #fff; padding: 0 2px; border-radius: 2px; font-size: 0.55rem; font-weight: 700;">BLK</span>' : '';
            const pathList = [...ip.paths].slice(0, 3).join(', ') + (ip.paths.size > 3 ? ' (+' + (ip.paths.size - 3) + ')' : '');
            const ts = ip.lastSeen.replace('T', ' ').split('.')[0];
            return `<tr>
                <td style="padding: 4px 6px; border-bottom: 1px solid rgba(255,255,255,0.03);">
                    <a href="https://ipinfo.io/${ip.ip}" target="_blank" style="color: ${color}; text-decoration: none;">${ip.ip}</a>${blk}
                    ${ip.hostname ? '<div style="color: var(--text-secondary); font-size: 0.65rem;">' + ip.hostname + '</div>' : ''}
                    ${ip.city ? '<div style="color: var(--text-secondary); font-size: 0.65rem;">' + ip.city + '</div>' : ''}
                </td>
                <td style="padding: 4px 6px; border-bottom: 1px solid rgba(255,255,255,0.03); color: ${color};">${ip.type}</td>
                <td style="padding: 4px 6px; border-bottom: 1px solid rgba(255,255,255,0.03); text-align: right;">${ip.reqs}</td>
                <td style="padding: 4px 6px; border-bottom: 1px solid rgba(255,255,255,0.03); white-space: nowrap;">${ts}</td>
                <td style="padding: 4px 6px; border-bottom: 1px solid rgba(255,255,255,0.03); color: var(--text-secondary);" title="${[...ip.paths].join(', ')}">${pathList}</td>
            </tr>`;
        }).join('')}</tbody>
    </table>`;
}

function attachDrillDown(container) {
    container.querySelectorAll('.notable-row').forEach(row => {
        row.addEventListener('click', (e) => {
            if (e.target.closest('a')) return;
            const detail = row.querySelector('.notable-detail');
            if (detail.style.display !== 'none') {
                detail.style.display = 'none';
                return;
            }
            const ips = row.dataset.ips.split(',').filter(Boolean);
            detail.innerHTML = renderIpDetailTable(ips);
            detail.style.display = 'block';
        });
    });
}

function renderSectionHeader(label, count, color) {
    return `<div style="font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.05em; color: ${color}; margin: 0.5rem 0; font-weight: 600;">${label} (${count})</div>`;
}

function updateNotableDomains(notable) {
    const sidebarContainer = document.getElementById('notable-domains');
    if (!sidebarContainer || !notable) return;

    const { rdns, cloud, otherHosting } = categorizeNotable(notable);
    let html = '';
    if (rdns.length) {
        html += renderSectionHeader('rDNS', rdns.length, 'var(--accent-color)');
        html += renderNotableList(rdns, 4);
    }
    if (cloud.length) {
        html += renderSectionHeader('Cloud Providers', cloud.length, '#a855f7');
        html += renderNotableList(cloud, 4);
    }
    if (otherHosting.length) {
        html += renderSectionHeader('Other Hosting', otherHosting.length, '#22c55e');
        html += renderNotableList(otherHosting, 3);
    }
    sidebarContainer.innerHTML = html;
}

function updateLogFeed() {
    const feed = document.getElementById('log-feed');
    if (!feed) return;
    feed.innerHTML = '';
    filteredSessions.slice(-30).reverse().forEach(s => {
        const tr = document.createElement('tr');
        const ttype = getTrafficType(s);
        const color = TRAFFIC_COLORS[ttype];
        const isCountryBlocked = BLOCKED_COUNTRIES.includes(s.geo.country_code);
        const isMalBlocked = ttype === 'malicious';
        const isBlocked = isCountryBlocked || isMalBlocked;
        const blockedTag = isBlocked
            ? ` <span style="background: #f43f5e; color: #fff; padding: 0 3px; border-radius: 2px; font-size: 0.6rem; font-weight: 700; letter-spacing: 0.05em;">${isCountryBlocked ? 'GEO-BLK' : 'IP-BLK'}</span>`
            : '';

        tr.innerHTML = `
            <td>
                <div style="font-weight: 600; color: ${color}">
                    <a href="https://ipinfo.io/${s.origin_ip}" target="_blank" style="color: inherit; text-decoration: none;">${s.origin_ip}</a>
                    <span style="font-weight: 400; font-size: 0.7rem; opacity: 0.6; color: var(--text-primary)">[${s.geo.country_code || '??'}]</span>${blockedTag}
                </div>
                <div style="font-size: 0.7rem; color: var(--text-secondary)">${s.intent} | RPS: ${s.req_rate}</div>
            </td>
            <td><span class="badge" style="background: rgba(255,255,255,0.05)">Cluster</span></td>
            <td title="${s.path_summary.join(', ')}">${s.path_summary[0] || '/'} ${s.path_summary.length > 1 ? '(+'+(s.path_summary.length-1)+')' : ''}</td>
            <td><span style="color: ${ttype === 'malicious' ? '#f43f5e' : '#10b981'}">${s.req_count} reqs</span></td>
            <td style="color: var(--text-secondary); white-space: nowrap;">${s.last_seen_iso.replace('T', ' ').split('.')[0]}</td>
        `;
        feed.appendChild(tr);
    });
}

function updateCountryReport() {
    const sidebarContainer = document.getElementById('country-report');
    if (!sidebarContainer) return;

    const countries = {};
    filteredSessions.forEach(s => {
        const c = s.geo.country_code || '??';
        if (!countries[c]) {
            countries[c] = { name: s.geo.country || 'Unknown', total: 0, mal: 0, ips: new Set(), blockedIps: new Set() };
        }
        countries[c].total += s.req_count;
        if (s.is_malicious || isScannerTraffic(s)) countries[c].mal += s.req_count;
        countries[c].ips.add(s.origin_ip);
        if (BLOCKED_COUNTRIES.includes(c) || s.is_malicious || isScannerTraffic(s)) {
            countries[c].blockedIps.add(s.origin_ip);
        }
    });

    const entries = Object.entries(countries).map(([code, d]) => ({
        code, name: d.name, total: d.total, mal: d.mal,
        ipCount: d.ips.size, blockedCount: d.blockedIps.size
    })).sort((a, b) => b.total - a.total);

    sidebarContainer.innerHTML = entries.slice(0, 10).map(e => {
        const isBlocked = BLOCKED_COUNTRIES.includes(e.code);
        const blkBadge = isBlocked ? ' <span style="background: #f43f5e; color: #fff; padding: 0 3px; border-radius: 2px; font-size: 0.6rem; font-weight: 700;">BLK</span>' : '';
        const blockedLabel = e.blockedCount > 0 ? `<span style="color: #f43f5e;">${e.blockedCount} blk</span> / ` : '';
        return `<div style="margin-bottom: 1rem;">
            <div style="display: flex; justify-content: space-between; font-size: 0.75rem; margin-bottom: 2px;">
                <span><b>${e.code}</b> ${e.name}${blkBadge}</span>
                <span>${e.total} reqs</span>
            </div>
            <div style="font-size: 0.65rem; color: var(--text-secondary); margin-bottom: 3px;">${blockedLabel}${e.ipCount} IPs</div>
            <div style="display: flex; height: 6px; border-radius: 3px; overflow: hidden; background: rgba(255,255,255,0.05);">
                <div style="width: ${((e.total - e.mal)/e.total*100)}%; background: #00f2ff;"></div>
                <div style="width: ${(e.mal/e.total*100)}%; background: #f43f5e;"></div>
            </div>
        </div>`;
    }).join('');
}

function updateTopPaths() {
    const tableDiv = document.getElementById('top-paths');
    if (!tableDiv) return;

    const pathCounts = {};
    filteredSessions.forEach(s => {
        const ttype = getTrafficType(s);
        // Look at paths hit by malicious actors or suspected scanner bots
        if (ttype === 'malicious' || ttype === 'bot' || isScannerTraffic(s)) {
            (s.path_summary || []).forEach(p => {
                pathCounts[p] = (pathCounts[p] || 0) + s.req_count;
            });
        }
    });

    const entries = Object.entries(pathCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 50);

    let html = '<table style="width: 100%; border-collapse: collapse;">';
    entries.forEach(([path, count]) => {
        html += `
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td title="${path}" style="padding: 4px 0; font-size: 0.75rem; word-break: break-all; color: var(--text-primary); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${path}</td>
                <td style="padding: 4px 0; font-size: 0.75rem; text-align: right; color: var(--accent-color); font-weight: 500;">${count}</td>
            </tr>
        `;
    });
    html += '</table>';
    
    if (entries.length === 0) {
        html = '<div style="font-size: 0.75rem; color: var(--text-secondary); text-align: center; padding: 1rem 0;">No scanner paths found</div>';
    }
    
    tableDiv.innerHTML = html;
}

function setupEvents() {
    document.getElementById('timeline-slider').addEventListener('input', updateDashboard);
    document.querySelectorAll('.toggle-btn').forEach(btn => {
        if (btn.id.startsWith('btn-')) {
            btn.addEventListener('click', (e) => {
                currentFilter = btn.id.replace('btn-', '');
                document.querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                updateDashboard();
            });
        }
    });
    document.getElementById('btn-play').addEventListener('click', togglePlay);
    document.getElementById('toggle-feed').addEventListener('click', () => document.getElementById('live-panel').classList.add('open'));
    document.getElementById('close-feed').addEventListener('click', () => document.getElementById('live-panel').classList.remove('open'));

    document.getElementById('open-notable-modal').addEventListener('click', () => {
        const modal = document.getElementById('notable-modal');
        const body = document.getElementById('notable-modal-body');
        const { rdns, cloud, otherHosting } = categorizeNotable(allNotable);
        let html = '';
        if (rdns.length) {
            html += `<div style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--accent-color); margin: 1rem 0 0.75rem; font-weight: 700;">rDNS-Based (${rdns.length})</div>`;
            html += renderNotableList(rdns);
        }
        if (cloud.length) {
            html += `<div style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: #a855f7; margin: 1rem 0 0.75rem; font-weight: 700;">Cloud Providers (${cloud.length})</div>`;
            html += renderNotableList(cloud);
        }
        if (otherHosting.length) {
            html += `<div style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: #22c55e; margin: 1rem 0 0.75rem; font-weight: 700;">Other Hosting (${otherHosting.length})</div>`;
            html += renderNotableList(otherHosting);
        }
        body.innerHTML = html;
        attachDrillDown(body);
        modal.classList.add('open');
        lucide.createIcons();
    });

    document.getElementById('close-notable-modal').addEventListener('click', () => {
        document.getElementById('notable-modal').classList.remove('open');
    });

    document.getElementById('open-country-modal').addEventListener('click', () => {
        const modal = document.getElementById('country-modal');
        const body = document.getElementById('country-modal-body');
        const countries = {};
        filteredSessions.forEach(s => {
            const c = s.geo.country_code || '??';
            if (!countries[c]) countries[c] = { name: s.geo.country || 'Unknown', total: 0, legit: 0, cloud: 0, hosting: 0, bot: 0, mal: 0, ips: new Set(), blockedIps: new Set() };
            countries[c].total += s.req_count;
            countries[c].ips.add(s.origin_ip);
            const ttype = getTrafficType(s);
            if (ttype === 'malicious') countries[c].mal += s.req_count;
            else if (ttype === 'bot') countries[c].bot += s.req_count;
            else if (ttype === 'cloud') countries[c].cloud += s.req_count;
            else if (ttype === 'hosting') countries[c].hosting += s.req_count;
            else countries[c].legit += s.req_count;
            if (BLOCKED_COUNTRIES.includes(c) || ttype === 'malicious') {
                countries[c].blockedIps.add(s.origin_ip);
            }
        });
        const entries = Object.entries(countries).map(([code, d]) => ({
            code, name: d.name, total: d.total, legit: d.legit, cloud: d.cloud,
            hosting: d.hosting, bot: d.bot, mal: d.mal,
            ipCount: d.ips.size, blockedCount: d.blockedIps.size
        })).sort((a, b) => b.total - a.total);
        body.innerHTML = entries.map(e => {
            const isBlocked = BLOCKED_COUNTRIES.includes(e.code);
            const blkBadge = isBlocked ? ' <span style="background: #f43f5e; color: #fff; padding: 0 3px; border-radius: 2px; font-size: 0.6rem; font-weight: 700;">BLK</span>' : '';
            const blockedLabel = e.blockedCount > 0 ? `<span style="color: #f43f5e;">${e.blockedCount} blk</span> / ` : '';
            return `<div class="country-row" data-code="${e.code}" style="margin-bottom: 1rem; cursor: pointer;">
                <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 2px;">
                    <span><b>${e.code}</b> ${e.name}${blkBadge} <i data-lucide="chevron-down" style="width: 12px; height: 12px; display: inline-block; vertical-align: -2px; opacity: 0.4;"></i></span>
                    <span>${e.total} reqs</span>
                </div>
                <div style="font-size: 0.7rem; color: var(--text-secondary); margin-bottom: 3px;">${blockedLabel}${e.ipCount} IPs</div>
                <div style="display: flex; height: 6px; border-radius: 3px; overflow: hidden; background: rgba(255,255,255,0.05);">
                    <div style="width: ${(e.legit/e.total*100)}%; background: #00f2ff;"></div>
                    <div style="width: ${(e.cloud/e.total*100)}%; background: #a855f7;"></div>
                    <div style="width: ${(e.hosting/e.total*100)}%; background: #22c55e;"></div>
                    <div style="width: ${(e.bot/e.total*100)}%; background: #ffaa00;"></div>
                    <div style="width: ${(e.mal/e.total*100)}%; background: #f43f5e;"></div>
                </div>
                <div class="country-detail" style="display: none; margin-top: 0.5rem;"></div>
            </div>`;
        }).join('');

        body.querySelectorAll('.country-row').forEach(row => {
            row.addEventListener('click', () => {
                const detail = row.querySelector('.country-detail');
                if (detail.style.display !== 'none') {
                    detail.style.display = 'none';
                    return;
                }
                const code = row.dataset.code;
                const countryIps = [...new Set(filteredSessions.filter(s => (s.geo.country_code || '??') === code).map(s => s.origin_ip))];
                detail.innerHTML = renderIpDetailTable(countryIps);
                detail.style.display = 'block';
            });
        });

        modal.classList.add('open');
        lucide.createIcons();
    });

    document.getElementById('close-country-modal').addEventListener('click', () => {
        document.getElementById('country-modal').classList.remove('open');
    });

    document.querySelectorAll('.modal-overlay').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.classList.remove('open');
        });
    });
}

function togglePlay() {
    isPlaying = !isPlaying;
    if (isPlaying) {
        document.getElementById('btn-play').innerHTML = '<i data-lucide="pause" style="width: 14px; height: 14px;"></i>';
        playInterval = setInterval(() => {
            const slider = document.getElementById('timeline-slider');
            slider.value = (parseInt(slider.value) + 1) % 101;
            updateDashboard();
        }, 200);
    } else {
        document.getElementById('btn-play').innerHTML = '<i data-lucide="play" style="width: 14px; height: 14px;"></i>';
        clearInterval(playInterval);
    }
    lucide.createIcons();
}

function formatDate(date) {
    if (isNaN(date.getTime())) return "---";
    return date.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

document.addEventListener('DOMContentLoaded', init);

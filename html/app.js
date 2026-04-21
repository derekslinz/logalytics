let allSessions = [];
let filteredSessions = [];
let allNotable = [];
let map, markers = [];
let statusChart, volumeChart, typeChart;
let currentFilter = 'all';
let isPlaying = false;
let playInterval;
const PANEL_SIZE_STORAGE_KEY = 'logalytics-panel-sizes-v1';
const PANEL_SIZE_LIMITS = {
    leftMin: 260,
    leftMax: 700,
    rightMin: 420,
    rightMax: 1400,
    timelineMin: 110,
    timelineMax: 500
};
const BLOCKED_COUNTRIES = (window.APP_CONFIG && window.APP_CONFIG.BLOCKED_COUNTRIES) 
    ? window.APP_CONFIG.BLOCKED_COUNTRIES 
    : ['RU', 'BY', 'KZ', 'BR', 'IN', 'CN', 'PH', 'ID', 'IR', 'KP', 'VN', 'NG'];

function getSessionTimestamp(session, kind = 'last') {
    const numericKey = kind === 'first' ? 'first_seen' : 'last_seen';
    const isoKey = kind === 'first' ? 'first_seen_iso' : 'last_seen_iso';

    const numeric = Number(session?.[numericKey]);
    if (Number.isFinite(numeric) && numeric > 0) {
        return numeric * 1000;
    }

    const parsed = Date.parse(session?.[isoKey]);
    if (Number.isFinite(parsed)) {
        return parsed;
    }

    return 0;
}

async function init() {
    if (typeof ChartDataLabels !== 'undefined') {
        Chart.register(ChartDataLabels);
    }
    
    try {
        const dataUrl = `data.json?v=${Date.now()}`;
        const response = await fetch(dataUrl, { cache: 'no-store' });
        if (!response.ok) throw new Error("Fetch failed: " + response.status);
        const data = await response.json();
        const IGNORE_IPS = ['::1', '127.0.0.1', '0.0.0.0'];
        allSessions = (data.sessions || []).filter(s => !IGNORE_IPS.includes(s.origin_ip));
        const summary = data.summary || {};
        
        if (allSessions.length === 0) {
            setupMap();
            return;
        }

        // Sort by last seen (numeric timestamp preferred for stability)
        allSessions.sort((a, b) => getSessionTimestamp(a, 'last') - getSessionTimestamp(b, 'last'));
        
        document.getElementById('timeline-slider').value = 100;

        setupMap();
        setupCharts();
        setupEvents();
        setupPanelResizers();
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

    // Custom pane to isolate country polygons and prevent them from intercepting clicks
    map.createPane('countryPane');
    map.getPane('countryPane').style.zIndex = 300; // Place behind markers (which default to 400)
    map.getPane('countryPane').style.pointerEvents = 'none'; // Completely disable mouse interactions

    // Blocked Country Shading
    fetch('countries.geojson')
        .then(res => res.json())
        .then(geoData => {
            L.geoJson(geoData, {
                pane: 'countryPane',
                interactive: false,
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
            datasets: [
                {
                    type: 'bar',
                    label: 'Requests',
                    data: [],
                    yAxisID: 'yRequests',
                    backgroundColor: 'rgba(0, 242, 255, 0.35)',
                    borderColor: '#00f2ff',
                    borderWidth: 1
                },
                {
                    type: 'line',
                    label: 'Unique IPs',
                    data: [],
                    yAxisID: 'yIps',
                    borderColor: '#a855f7',
                    backgroundColor: 'rgba(168, 85, 247, 0.2)',
                    borderWidth: 2,
                    pointRadius: 2,
                    pointHoverRadius: 4,
                    tension: 0.3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    labels: {
                        color: '#94a3b8',
                        boxWidth: 10,
                        usePointStyle: true
                    }
                },
                datalabels: { display: false },
                tooltip: {
                    callbacks: {
                        label: (ctx) => `${ctx.dataset.label}: ${Number(ctx.parsed.y || 0).toLocaleString()}`
                    }
                }
            },
            scales: {
                x: {
                    display: true,
                    grid: { color: 'rgba(255, 255, 255, 0.05)', drawBorder: false },
                    ticks: {
                        color: '#94a3b8',
                        maxTicksLimit: 8,
                        autoSkip: true,
                        maxRotation: 0
                    },
                    title: {
                        display: true,
                        text: 'Time',
                        color: '#94a3b8',
                        font: { size: 10, weight: '600' }
                    }
                },
                yRequests: {
                    display: true,
                    beginAtZero: true,
                    position: 'left',
                    ticks: {
                        color: '#94a3b8',
                        maxTicksLimit: 4,
                        callback: (value) => Number(value).toLocaleString()
                    },
                    title: {
                        display: true,
                        text: 'Requests',
                        color: '#94a3b8',
                        font: { size: 10, weight: '600' }
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.08)',
                        drawBorder: false
                    }
                },
                yIps: {
                    display: true,
                    beginAtZero: true,
                    position: 'right',
                    ticks: {
                        color: '#b794f4',
                        maxTicksLimit: 4,
                        callback: (value) => Number(value).toLocaleString()
                    },
                    title: {
                        display: true,
                        text: 'Unique IPs',
                        color: '#b794f4',
                        font: { size: 10, weight: '600' }
                    },
                    grid: {
                        drawOnChartArea: false,
                        drawBorder: false
                    }
                }
            }
        }
    });
}

function sessionMatchesCurrentFilter(s) {
    if (currentFilter === 'legitimate') return !s.geo.is_bot && !s.is_malicious && !s.geo.is_cloud && !s.geo.is_hosting;
    if (currentFilter === 'cloud') return s.geo.is_cloud && !s.is_bot && !s.is_malicious;
    if (currentFilter === 'hosting') return s.geo.is_hosting && !s.is_bot && !s.is_malicious;
    if (currentFilter === 'bots') return s.geo.is_bot;
    if (currentFilter === 'malicious') return s.is_malicious;
    return true;
}

function formatBucketLabel(ts) {
    if (!ts || !Number.isFinite(ts)) return '';
    return new Date(ts).toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function updateDashboard() {
    const sliderVal = document.getElementById('timeline-slider').value;
    const total = allSessions.length;
    if (total === 0) return;
    
    const maxIdx = Math.floor((total - 1) * (sliderVal / 100));
    
    filteredSessions = allSessions.slice(0, maxIdx + 1).filter(sessionMatchesCurrentFilter);

    document.getElementById('total-req').innerText = filteredSessions.reduce((acc, s) => acc + s.req_count, 0).toLocaleString();
    const uniqueIPs = new Set(filteredSessions.map(s => s.origin_ip)).size;
    document.getElementById('unique-ips').innerText = uniqueIPs.toLocaleString();

    if (total > 0 && allSessions[0] && allSessions[maxIdx]) {
        const startTs = Math.min(...allSessions.map(s => getSessionTimestamp(s, 'first')).filter(ts => ts > 0));
        const endTs = Math.max(...allSessions.map(s => getSessionTimestamp(s, 'last')).filter(ts => ts > 0));
        const currentTs = Math.max(...allSessions.slice(0, maxIdx + 1).map(s => getSessionTimestamp(s, 'last')).filter(ts => ts > 0));

        document.getElementById('start-time').innerText = formatDate(new Date(startTs));
        document.getElementById('current-time').innerText = formatDate(new Date(currentTs));
        document.getElementById('end-time').innerText = formatDate(new Date(endTs));
    }

    updateMarkers();
    updateChartsData(maxIdx);
    updateLogFeed();
    updateCountryReport();
    updateTopPaths();
    updateNotableDomains(allNotable);
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

function updateChartsData(maxIdx) {
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

    const statusTotals = [0, 0, 0, 0]; // 2xx, 3xx, 4xx, 5xx
    filteredSessions.forEach((s) => {
        if (s.status_counts) {
            statusTotals[0] += Number(s.status_counts['2xx'] || 0);
            statusTotals[1] += Number(s.status_counts['3xx'] || 0);
            statusTotals[2] += Number(s.status_counts['4xx'] || 0);
            statusTotals[3] += Number(s.status_counts['5xx'] || 0);
            return;
        }

        // Legacy fallback: old datasets may not include per-status buckets.
        if (s.is_malicious || isScannerTraffic(s)) {
            statusTotals[2] += Number(s.req_count || 0);
        } else {
            statusTotals[0] += Number(s.req_count || 0);
        }
    });
    statusChart.data.datasets[0].data = statusTotals;
    statusChart.update();

    const totalInWindow = Math.max(1, (typeof maxIdx === 'number' ? maxIdx + 1 : allSessions.length));
    const bucketCount = Math.max(1, Math.min(30, totalInWindow));
    const bucketSize = Math.max(1, Math.ceil(totalInWindow / bucketCount));
    const requestData = new Array(bucketCount).fill(0);
    const ipSets = Array.from({ length: bucketCount }, () => new Set());
    const bucketTimeRanges = Array.from({ length: bucketCount }, () => ({ start: 0, end: 0 }));

    for (let i = 0; i < totalInWindow; i++) {
        const s = allSessions[i];
        const bucketIdx = Math.min(bucketCount - 1, Math.floor(i / bucketSize));
        const ts = getSessionTimestamp(s, 'last');

        if (!bucketTimeRanges[bucketIdx].start || ts < bucketTimeRanges[bucketIdx].start) bucketTimeRanges[bucketIdx].start = ts;
        if (ts > bucketTimeRanges[bucketIdx].end) bucketTimeRanges[bucketIdx].end = ts;

        if (!sessionMatchesCurrentFilter(s)) continue;
        requestData[bucketIdx] += Number(s.req_count || 0);
        ipSets[bucketIdx].add(s.origin_ip);
    }

    const ipLineData = ipSets.map(set => set.size);
    const labels = bucketTimeRanges.map(range => formatBucketLabel(range.end || range.start));

    volumeChart.data.labels = labels;
    volumeChart.data.datasets[0].data = requestData;
    volumeChart.data.datasets[1].data = ipLineData;
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
            sessionsByIp[s.origin_ip] = {
                ip: s.origin_ip,
                reqs: 0,
                hostname: s.geo.hostname || '',
                city: s.geo.city || '',
                cc: s.geo.country_code || '',
                asn: s.geo.asn || '',
                asnName: s.geo.asn_name || '',
                type: getTrafficType(s),
                firstSeen: s.first_seen_iso,
                lastSeen: s.last_seen_iso,
                paths: new Set()
            };
        }
        sessionsByIp[s.origin_ip].reqs += s.req_count;
        if (s.last_seen_iso > sessionsByIp[s.origin_ip].lastSeen) sessionsByIp[s.origin_ip].lastSeen = s.last_seen_iso;
        if (s.first_seen_iso < sessionsByIp[s.origin_ip].firstSeen) sessionsByIp[s.origin_ip].firstSeen = s.first_seen_iso;
        if (!sessionsByIp[s.origin_ip].asn && s.geo.asn) sessionsByIp[s.origin_ip].asn = s.geo.asn;
        if (!sessionsByIp[s.origin_ip].asnName && s.geo.asn_name) sessionsByIp[s.origin_ip].asnName = s.geo.asn_name;
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
            const asnLabel = ip.asn ? `AS${ip.asn}${ip.asnName ? ' · ' + escapeHtml(ip.asnName) : ''}` : (ip.asnName ? escapeHtml(ip.asnName) : 'ASN unknown');
            const firstTs = (ip.firstSeen || '').replace('T', ' ').split('.')[0];
            const firstDate = firstTs.split(' ')[0] || firstTs || 'unknown';
            const lastDate = ts.split(' ')[0] || ts || 'unknown';
            const seenRange = firstDate === lastDate ? firstDate : `${firstDate} → ${lastDate}`;
            return `<tr>
                <td style="padding: 4px 6px; border-bottom: 1px solid rgba(255,255,255,0.03);">
                    <a href="https://ipinfo.io/${ip.ip}" target="_blank" style="color: ${color}; text-decoration: none;">${ip.ip}</a>${blk}
                    ${ip.hostname ? '<div style="color: var(--text-secondary); font-size: 0.65rem;">' + ip.hostname + '</div>' : ''}
                    ${ip.city ? '<div style="color: var(--text-secondary); font-size: 0.65rem;">' + ip.city + '</div>' : ''}
                    <div style="color: var(--text-secondary); font-size: 0.65rem;">${asnLabel}</div>
                    <div style="color: var(--text-secondary); font-size: 0.65rem;">Seen: ${seenRange}</div>
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
        const detail = row.querySelector('.notable-detail');
        const ips = row.dataset.ips.split(',').filter(Boolean);

        const expand = () => {
            if (!detail) return;
            detail.innerHTML = renderIpDetailTable(ips);
            detail.style.display = 'block';
        };

        // Expanded by default so selecting/copying doesn't collapse the detail panel.
        expand();

        row.addEventListener('click', (e) => {
            if (e.target.closest('a')) return;

            // Ignore clicks that are part of text selection/copy interactions.
            const selectedText = window.getSelection ? window.getSelection().toString() : '';
            if (selectedText && selectedText.trim().length > 0) return;

            // Keep expanded by default; only re-open if something hid it.
            if (detail && detail.style.display === 'none') {
                expand();
            }
        });
    });
}

function renderSectionHeader(label, count, color) {
    return `<div style="font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.05em; color: ${color}; margin: 0.5rem 0; font-weight: 600;">${label} (${count})</div>`;
}

function sortNotablesByCount(items) {
    return [...items].sort((a, b) => (b.count || 0) - (a.count || 0));
}

function getVisibleNotables(items) {
    const visibleIps = new Set(filteredSessions.map(s => s.origin_ip));
    return items
        .map(n => {
            const visibleItemIps = (n.ips || []).filter(ip => visibleIps.has(ip));
            return {
                ...n,
                ips: visibleItemIps,
                count: visibleItemIps.length
            };
        })
        .filter(n => n.count > 0);
}

function updateNotableDomains(notable) {
    const sidebarContainer = document.getElementById('notable-domains');
    if (!sidebarContainer || !notable) return;

    const { rdns, cloud, otherHosting } = categorizeNotable(notable);
    const visibleRdns = sortNotablesByCount(getVisibleNotables(rdns));
    const visibleCloud = sortNotablesByCount(getVisibleNotables(cloud));
    const visibleOtherHosting = sortNotablesByCount(getVisibleNotables(otherHosting));
    let html = '';
    if (visibleRdns.length) {
        html += renderSectionHeader('rDNS', visibleRdns.length, 'var(--accent-color)');
        html += renderNotableList(visibleRdns, 4);
    }
    if (visibleCloud.length) {
        html += renderSectionHeader('Cloud Providers', visibleCloud.length, '#a855f7');
        html += renderNotableList(visibleCloud, 4);
    }
    if (visibleOtherHosting.length) {
        html += renderSectionHeader('Other Hosting', visibleOtherHosting.length, '#22c55e');
        html += renderNotableList(visibleOtherHosting, 3);
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

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function getTopPathEntries() {
    const pathMap = {};

    filteredSessions.forEach((s) => {
        const ttype = getTrafficType(s);
        if (!(ttype === 'malicious' || ttype === 'bot' || isScannerTraffic(s))) return;

        const uniquePaths = new Set(s.path_summary || []);
        uniquePaths.forEach((path) => {
            if (!pathMap[path]) {
                pathMap[path] = {
                    path,
                    count: 0,
                    ips: new Set()
                };
            }
            pathMap[path].count += Number(s.req_count || 0);
            pathMap[path].ips.add(s.origin_ip);
        });
    });

    return Object.values(pathMap)
        .map((entry) => ({
            path: entry.path,
            count: entry.count,
            ips: [...entry.ips],
            ipCount: entry.ips.size
        }))
        .sort((a, b) => b.count - a.count);
}

function renderPathIpDetailTable(path) {
    const sessionsByIp = {};

    const windowSeenByIp = {};
    filteredSessions.forEach((s) => {
        if (!windowSeenByIp[s.origin_ip]) {
            windowSeenByIp[s.origin_ip] = {
                firstSeen: s.first_seen_iso,
                lastSeen: s.last_seen_iso
            };
            return;
        }

        if (s.first_seen_iso < windowSeenByIp[s.origin_ip].firstSeen) {
            windowSeenByIp[s.origin_ip].firstSeen = s.first_seen_iso;
        }
        if (s.last_seen_iso > windowSeenByIp[s.origin_ip].lastSeen) {
            windowSeenByIp[s.origin_ip].lastSeen = s.last_seen_iso;
        }
    });

    filteredSessions.forEach((s) => {
        if (!(s.path_summary || []).includes(path)) return;

        if (!sessionsByIp[s.origin_ip]) {
            const seenWindow = windowSeenByIp[s.origin_ip] || { firstSeen: s.first_seen_iso, lastSeen: s.last_seen_iso };
            sessionsByIp[s.origin_ip] = {
                ip: s.origin_ip,
                hits: 0,
                sessions: 0,
                hostname: s.geo.hostname || '',
                city: s.geo.city || '',
                cc: s.geo.country_code || '',
                asn: s.geo.asn || '',
                asnName: s.geo.asn_name || '',
                type: getTrafficType(s),
                firstSeen: seenWindow.firstSeen,
                lastSeen: seenWindow.lastSeen
            };
        }

        sessionsByIp[s.origin_ip].hits += Number(s.req_count || 0);
        sessionsByIp[s.origin_ip].sessions += 1;
        if (!sessionsByIp[s.origin_ip].asn && s.geo.asn) sessionsByIp[s.origin_ip].asn = s.geo.asn;
        if (!sessionsByIp[s.origin_ip].asnName && s.geo.asn_name) sessionsByIp[s.origin_ip].asnName = s.geo.asn_name;
    });

    const ips = Object.values(sessionsByIp).sort((a, b) => b.hits - a.hits);
    if (!ips.length) {
        return '<div style="font-size: 0.7rem; color: var(--text-secondary); padding: 8px 0;">No sessions in current filter</div>';
    }

    return `<table style="width: 100%; font-size: 0.7rem;">
        <thead><tr>
            <th style="text-align: left; padding: 4px 6px; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);">IP</th>
            <th style="text-align: left; padding: 4px 6px; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);">Type</th>
            <th style="text-align: right; padding: 4px 6px; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);">Hits</th>
            <th style="text-align: right; padding: 4px 6px; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);">Sessions</th>
            <th style="text-align: left; padding: 4px 6px; color: var(--text-secondary); border-bottom: 1px solid var(--border-color);">Last Seen</th>
        </tr></thead>
        <tbody>${ips.map(ip => {
            const color = TRAFFIC_COLORS[ip.type];
            const isBlocked = BLOCKED_COUNTRIES.includes(ip.cc) || ip.type === 'malicious';
            const blk = isBlocked ? ' <span style="background: #f43f5e; color: #fff; padding: 0 2px; border-radius: 2px; font-size: 0.55rem; font-weight: 700;">BLK</span>' : '';
            const ts = ip.lastSeen.replace('T', ' ').split('.')[0];
            const asnLabel = ip.asn ? `AS${ip.asn}${ip.asnName ? ' · ' + escapeHtml(ip.asnName) : ''}` : (ip.asnName ? escapeHtml(ip.asnName) : 'ASN unknown');
            const firstTs = (ip.firstSeen || '').replace('T', ' ').split('.')[0];
            const firstDate = firstTs.split(' ')[0] || firstTs || 'unknown';
            const lastDate = ts.split(' ')[0] || ts || 'unknown';
            const seenRange = firstDate === lastDate ? firstDate : `${firstDate} → ${lastDate}`;
            return `<tr>
                <td style="padding: 4px 6px; border-bottom: 1px solid rgba(255,255,255,0.03);">
                    <a href="https://ipinfo.io/${ip.ip}" target="_blank" style="color: ${color}; text-decoration: none;">${ip.ip}</a>${blk}
                    ${ip.hostname ? '<div style="color: var(--text-secondary); font-size: 0.65rem;">' + escapeHtml(ip.hostname) + '</div>' : ''}
                    ${ip.city ? '<div style="color: var(--text-secondary); font-size: 0.65rem;">' + escapeHtml(ip.city) + '</div>' : ''}
                    <div style="color: var(--text-secondary); font-size: 0.65rem;">${asnLabel}</div>
                    <div style="color: var(--text-secondary); font-size: 0.65rem;">Seen: ${seenRange}</div>
                </td>
                <td style="padding: 4px 6px; border-bottom: 1px solid rgba(255,255,255,0.03); color: ${color};">${ip.type}</td>
                <td style="padding: 4px 6px; border-bottom: 1px solid rgba(255,255,255,0.03); text-align: right;">${ip.hits}</td>
                <td style="padding: 4px 6px; border-bottom: 1px solid rgba(255,255,255,0.03); text-align: right;">${ip.sessions}</td>
                <td style="padding: 4px 6px; border-bottom: 1px solid rgba(255,255,255,0.03); white-space: nowrap;">${ts}</td>
            </tr>`;
        }).join('')}</tbody>
    </table>`;
}

function attachPathDrillDown(container) {
    container.querySelectorAll('.path-row').forEach((row) => {
        const detail = row.querySelector('.path-detail');
        if (!detail) return;

        const expand = () => {
            const encodedPath = row.dataset.path || '';
            const path = decodeURIComponent(encodedPath);
            detail.innerHTML = renderPathIpDetailTable(path);
            detail.style.display = 'block';
        };

        // Expanded by default for quick visibility and easier copy/select.
        expand();

        row.addEventListener('click', (e) => {
            if (e.target.closest('a')) return;

            const selectedText = window.getSelection ? window.getSelection().toString() : '';
            if (selectedText && selectedText.trim().length > 0) return;

            // Keep expanded by default; only re-open if something hid it.
            if (detail.style.display === 'none') {
                expand();
            }
        });
    });
}

function updateTopPaths() {
    const tableDiv = document.getElementById('top-paths');
    if (!tableDiv) return;

    const entries = getTopPathEntries().slice(0, 50);

    let html = '<table style="width: 100%; border-collapse: collapse;">';
    entries.forEach(({ path, count, ipCount }) => {
        html += `
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td title="${escapeHtml(path)}" style="padding: 4px 0; font-size: 0.75rem; word-break: break-all; color: var(--text-primary); max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(path)}</td>
                <td style="padding: 4px 0; font-size: 0.75rem; text-align: right; color: var(--text-secondary);">${ipCount} IPs</td>
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
    const livePanel = document.getElementById('live-panel');
    const edgeToggle = document.getElementById('toggle-feed-edge');
    const centerPane = document.querySelector('.center-pane');
    const setLivePanelOpen = (open) => {
        if (!livePanel) return;
        livePanel.classList.toggle('open', open);
        if (edgeToggle) edgeToggle.classList.toggle('hidden', open);
        if (centerPane) centerPane.classList.toggle('with-live-panel-open', open);
        refreshResizableLayout();
    };

    document.getElementById('toggle-feed').addEventListener('click', () => setLivePanelOpen(true));
    if (edgeToggle) {
        edgeToggle.addEventListener('click', () => setLivePanelOpen(true));
    }
    document.getElementById('close-feed').addEventListener('click', () => setLivePanelOpen(false));
    setLivePanelOpen(true);

    document.getElementById('open-notable-modal').addEventListener('click', () => {
        const modal = document.getElementById('notable-modal');
        const body = document.getElementById('notable-modal-body');
        const { rdns, cloud, otherHosting } = categorizeNotable(allNotable);
        const sortedRdns = sortNotablesByCount(getVisibleNotables(rdns));
        const sortedCloud = sortNotablesByCount(getVisibleNotables(cloud));
        const sortedOtherHosting = sortNotablesByCount(getVisibleNotables(otherHosting));
        let html = '';
        if (sortedRdns.length) {
            html += `<div style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--accent-color); margin: 1rem 0 0.75rem; font-weight: 700;">rDNS-Based (${sortedRdns.length})</div>`;
            html += renderNotableList(sortedRdns);
        }
        if (sortedCloud.length) {
            html += `<div style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: #a855f7; margin: 1rem 0 0.75rem; font-weight: 700;">Cloud Providers (${sortedCloud.length})</div>`;
            html += renderNotableList(sortedCloud);
        }
        if (sortedOtherHosting.length) {
            html += `<div style="font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: #22c55e; margin: 1rem 0 0.75rem; font-weight: 700;">Other Hosting (${sortedOtherHosting.length})</div>`;
            html += renderNotableList(sortedOtherHosting);
        }
        body.innerHTML = html;
        attachDrillDown(body);
        modal.classList.add('open');
        lucide.createIcons();
    });

    document.getElementById('close-notable-modal').addEventListener('click', () => {
        document.getElementById('notable-modal').classList.remove('open');
    });

    document.getElementById('open-paths-modal').addEventListener('click', () => {
        const modal = document.getElementById('paths-modal');
        const body = document.getElementById('paths-modal-body');
        const entries = getTopPathEntries();

        if (!entries.length) {
            body.innerHTML = '<div style="font-size: 0.8rem; color: var(--text-secondary); padding: 1rem 0;">No scanner paths found in current filter</div>';
            modal.classList.add('open');
            return;
        }

        body.innerHTML = entries.map(({ path, count, ipCount }) => {
            const encodedPath = encodeURIComponent(path);
            return `<div class="path-row" data-path="${encodedPath}" style="margin-bottom: 0.75rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.5rem; cursor: pointer;">
                <div style="display: flex; justify-content: space-between; align-items: baseline; font-size: 0.8rem; gap: 12px;">
                    <div style="min-width: 0; flex: 1;">
                        <span title="${escapeHtml(path)}" style="color: var(--text-primary); display: inline-block; max-width: 100%; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(path)}</span>
                        <i data-lucide="chevron-down" style="width: 12px; height: 12px; display: inline-block; vertical-align: -2px; opacity: 0.4; margin-left: 4px;"></i>
                    </div>
                    <span style="color: var(--text-secondary); white-space: nowrap;">${ipCount} IPs</span>
                    <span style="color: var(--accent-color); white-space: nowrap; font-weight: 600;">${count} hits</span>
                </div>
                <div class="path-detail" style="display: none; margin-top: 0.5rem;"></div>
            </div>`;
        }).join('');

        attachPathDrillDown(body);
        modal.classList.add('open');
        lucide.createIcons();
    });

    document.getElementById('close-paths-modal').addEventListener('click', () => {
        document.getElementById('paths-modal').classList.remove('open');
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

function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}

function loadPanelSizes() {
    try {
        const raw = localStorage.getItem(PANEL_SIZE_STORAGE_KEY);
        if (!raw) return {};
        const parsed = JSON.parse(raw);
        return {
            left: Number(parsed.left),
            right: Number(parsed.right),
            timeline: Number(parsed.timeline)
        };
    } catch {
        return {};
    }
}

function savePanelSizes(left, right, timeline) {
    try {
        localStorage.setItem(PANEL_SIZE_STORAGE_KEY, JSON.stringify({ left, right, timeline }));
    } catch {
        // no-op
    }
}

function applyPanelSizes(left, right, timeline) {
    const root = document.documentElement;
    if (Number.isFinite(left)) {
        root.style.setProperty('--left-sidebar-width', `${left}px`);
    }
    if (Number.isFinite(right)) {
        root.style.setProperty('--right-panel-width', `${right}px`);
    }
    if (Number.isFinite(timeline)) {
        root.style.setProperty('--timeline-height', `${timeline}px`);
    }
}

function refreshResizableLayout() {
    if (map) {
        setTimeout(() => map.invalidateSize(), 0);
    }
    if (statusChart) statusChart.resize();
    if (typeChart) typeChart.resize();
    if (volumeChart) volumeChart.resize();
}

function setupPanelResizers() {
    const leftHandle = document.getElementById('left-resize-handle');
    const rightHandle = document.getElementById('right-resize-handle');
    const timelineHandle = document.getElementById('timeline-resize-handle');
    const timeline = document.querySelector('.timeline-container');
    const centerPane = document.querySelector('.center-pane');
    const main = document.querySelector('main');

    if (!leftHandle || !rightHandle || !timelineHandle || !timeline || !centerPane || !main) return;

    const loaded = loadPanelSizes();
    const initialLeft = Number.isFinite(loaded.left)
        ? clamp(loaded.left, PANEL_SIZE_LIMITS.leftMin, PANEL_SIZE_LIMITS.leftMax)
        : 350;
    const initialRight = Number.isFinite(loaded.right)
        ? clamp(loaded.right, PANEL_SIZE_LIMITS.rightMin, PANEL_SIZE_LIMITS.rightMax)
        : 900;
    const initialTimeline = Number.isFinite(loaded.timeline)
        ? clamp(loaded.timeline, PANEL_SIZE_LIMITS.timelineMin, PANEL_SIZE_LIMITS.timelineMax)
        : 150;

    applyPanelSizes(initialLeft, initialRight, initialTimeline);

    let active = null;
    let leftWidth = initialLeft;
    let rightWidth = initialRight;
    let timelineHeight = initialTimeline;

    const onPointerMove = (e) => {
        if (!active) return;

        if (active === 'left') {
            const rect = main.getBoundingClientRect();
            leftWidth = clamp(e.clientX - rect.left, PANEL_SIZE_LIMITS.leftMin, PANEL_SIZE_LIMITS.leftMax);
            applyPanelSizes(leftWidth, null);
        } else if (active === 'right') {
            rightWidth = clamp(window.innerWidth - e.clientX, PANEL_SIZE_LIMITS.rightMin, PANEL_SIZE_LIMITS.rightMax);
            applyPanelSizes(null, rightWidth);
        } else if (active === 'timeline') {
            const paneRect = centerPane.getBoundingClientRect();
            const dynamicMax = Math.max(PANEL_SIZE_LIMITS.timelineMin, Math.min(PANEL_SIZE_LIMITS.timelineMax, paneRect.height - 80));
            timelineHeight = clamp(paneRect.bottom - e.clientY, PANEL_SIZE_LIMITS.timelineMin, dynamicMax);
            applyPanelSizes(null, null, timelineHeight);
        }

        refreshResizableLayout();
    };

    const stopResize = () => {
        if (!active) return;
        const wasTimeline = active === 'timeline';
        active = null;
        document.body.classList.remove('is-resizing');
        document.body.classList.remove('is-resizing-row');
        savePanelSizes(leftWidth, rightWidth, timelineHeight);
        refreshResizableLayout();
        if (wasTimeline) updateDashboard();
        window.removeEventListener('pointermove', onPointerMove);
        window.removeEventListener('pointerup', stopResize);
        window.removeEventListener('pointercancel', stopResize);
    };

    const startResize = (side) => (e) => {
        e.preventDefault();
        active = side;
        if (side === 'timeline') {
            document.body.classList.add('is-resizing-row');
        } else {
            document.body.classList.add('is-resizing');
        }
        window.addEventListener('pointermove', onPointerMove);
        window.addEventListener('pointerup', stopResize);
        window.addEventListener('pointercancel', stopResize);
    };

    leftHandle.addEventListener('pointerdown', startResize('left'));
    rightHandle.addEventListener('pointerdown', startResize('right'));
    timelineHandle.addEventListener('pointerdown', startResize('timeline'));

    window.addEventListener('resize', refreshResizableLayout);
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

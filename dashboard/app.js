'use strict';

const API = window.location.origin;
let catalogData = [], machinesData = [], vulnsData = [], licencesData = [], logicielsLicData = [];
let currentSwNom = null, currentScanId = null;
let currentPage = 1, perPage = 100, totalPages = 1, totalItems = 0;
let _catGroupByMetier = false;

async function api(path, options = {}) {
  const ctl = new AbortController();
  const tid = setTimeout(() => ctl.abort(), 30000);
  options.signal = ctl.signal;
  try {
    const r = await fetch(API + path, options);
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  } finally {
    clearTimeout(tid);
  }
}

function esc(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function jesc(str) {
  if (!str) return '';
  return String(str).replace(/\\/g,"\\\\").replace(/'/g,"\\'");
}

function val(v, fallback = 'Non disponible') {
  if (v === null || v === undefined || v === '' || v === 'N/A') return fallback;
  return v;
}

function badge(level) {
  const map = {
    'Critique': 'badge badge-critique',
    'Eleve': 'badge badge-eleve',
    'Moyen': 'badge badge-moyen',
    'Faible': 'badge badge-faible',
    'Élevé': 'badge badge-eleve',
  };
  return `<span class="${map[level] || 'badge badge-faible'}">${esc(level) || '?'}</span>`;
}

function setStatus(online) {
  const el = document.getElementById('server-status');
  el.className = online ? 'online' : 'offline';
  const dot = el.querySelector('.status-dot');
  const txt = el.querySelector('.status-text');
  if (txt) txt.textContent = online ? 'En ligne' : 'Hors ligne';
  else el.textContent = online ? 'En ligne' : 'Hors ligne';
  // Update nav vuln badge when online
  if (online) updateNavBadges();
}

async function updateNavBadges() {
  try {
    const s = await api('/api/stats');
    const badge = document.getElementById('nav-badge-vuln');
    if (badge && (s.critiques || 0) > 0) {
      badge.textContent = s.critiques;
      badge.style.display = '';
    } else if (badge) {
      badge.style.display = 'none';
    }
  } catch(e) {}
}

// Navigation is handled by the inline script in index.html.
// loadTab() below is still called from there.

function loadTab(name) {
  if (name === 'dashboard') loadDashboard();
  else if (name === 'catalogue') loadCatalogue();
  else if (name === 'machines') loadMachines();
  else if (name === 'vulnerabilites') loadVulns();
  else if (name === 'licences') loadLicences();
  else if (name === 'conformite') loadConformite();
  else if (name === 'securite') loadSecurite();

  else if (name === 'historique') loadHistorique();
  else if (name === 'statistiques') loadStatistiques();
  else if (name === 'droits') loadDroits();
  else if (name === 'droits-logiciels') loadDroitsLogiciels();
}

document.querySelectorAll('.inner-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const drawer = tab.dataset.drawer;
    const targetId = tab.dataset.itab;
    document.querySelectorAll(`.inner-tab[data-drawer="${drawer}"]`).forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    const pane = document.getElementById(targetId);
    if (!pane) return;
    pane.parentElement.querySelectorAll('.inner-pane').forEach(p => p.classList.remove('active'));
    pane.classList.add('active');
  });
});

let searchTimer = null;
document.getElementById('global-search').addEventListener('input', e => {
  clearTimeout(searchTimer);
  const q = e.target.value.trim();
  if (q.length < 2) {
    document.getElementById('search-results-dropdown').classList.remove('visible');
    return;
  }
  searchTimer = setTimeout(async () => {
    try {
      const res = await api('/api/search?q=' + encodeURIComponent(q));
      renderSearchDropdown(res);
    } catch(err) {}
  }, 300);
});

document.getElementById('global-search').addEventListener('blur', () => {
  setTimeout(() => document.getElementById('search-results-dropdown').classList.remove('visible'), 200);
});

function renderSearchDropdown(res) {
  const dd = document.getElementById('search-results-dropdown');
  let html = '';
  if (res.machines && res.machines.length) {
    html += `<div class="search-group-title">Machines (${res.machines.length})</div>`;
    res.machines.forEach(m => {
      html += `<div class="search-result-item" onclick="showMachine('${jesc(m.scan_id)}')">
        <div><div class="sri-label">${esc(m.nom_pc)}</div><div class="sri-sub">${esc(m.ip)} &middot; ${esc(m.utilisateur)} &middot; ${esc(m.os_nom)}</div></div>
      </div>`;
    });
  }
  if (res.logiciels && res.logiciels.length) {
    html += `<div class="search-group-title">Logiciels (${res.logiciels.length})</div>`;
    res.logiciels.forEach(l => {
      html += `<div class="search-result-item" onclick="showLogiciel('${jesc(l.nom)}')">
        <div><div class="sri-label">${esc(l.nom)}</div><div class="sri-sub">${esc(l.editeur)} &bull; ${l.nb_installations} installation(s) &bull; ${badge(l.risque_niveau)}</div></div>
      </div>`;
    });
  }
  if (res.cves && res.cves.length) {
    html += `<div class="search-group-title">CVE (${res.cves.length})</div>`;
    res.cves.forEach(c => {
      html += `<div class="search-result-item" onclick="showLogiciel('${jesc(c.logiciel_nom)}')">
        <div><div class="sri-label sri-danger">${esc(c.cve_id)}</div><div class="sri-sub">${esc(c.logiciel_nom)} &bull; CVSS: ${c.cvss_score}</div></div>
      </div>`;
    });
  }
  if (!html) html = '<div class="search-result-item" style="cursor:default"><div class="sri-sub">Aucun resultat</div></div>';
  dd.innerHTML = html;
  dd.classList.add('visible');
}

async function loadDashboard() {
  const kpi = document.getElementById('dash-kpi');
  const charts = document.getElementById('dash-charts');
  kpi.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Chargement...</span></div>';
  try {
    const s = await api('/api/stats');
    setStatus(true);

    const score = s.score_conformite_global || 0;
    const scoreColor = score >= 80 ? 'success' : score >= 50 ? 'warning' : 'danger';

    kpi.innerHTML = `
      <div class="stat-card"><div class="stat-val accent">${s.total_pc || 0}</div><div class="stat-lbl">Postes inventories</div></div>
      <div class="stat-card success"><div class="stat-val success">${s.postes_actifs || 0}</div><div class="stat-lbl">Postes actifs</div></div>
      <div class="stat-card muted"><div class="stat-val">${s.postes_inactifs || 0}</div><div class="stat-lbl">Postes inactifs</div></div>
      <div class="stat-card"><div class="stat-val accent">${(s.total_logiciels || 0).toLocaleString()}</div><div class="stat-lbl">Installations logicielles</div></div>
      <div class="stat-card"><div class="stat-val">${s.logiciels_uniques || 0}</div><div class="stat-lbl">Logiciels uniques</div></div>
      <div class="stat-card warning"><div class="stat-val warning">${s.obsoletes || 0}</div><div class="stat-lbl">Logiciels obsoletes</div></div>
      <div class="stat-card warning"><div class="stat-val warning">${s.eol || 0}</div><div class="stat-lbl">Fin de support (EOL)</div></div>
      <div class="stat-card danger"><div class="stat-val danger">${s.vulnerables || 0}</div><div class="stat-lbl">Logiciels vulnerables</div></div>
      <div class="stat-card danger"><div class="stat-val danger">${s.critiques || 0}</div><div class="stat-lbl">Score critique (>= 8)</div></div>
      <div class="stat-card purple"><div class="stat-val purple">${s.total_cve || 0}</div><div class="stat-lbl">CVE connues</div></div>
      <div class="stat-card danger"><div class="stat-val danger">${s.cve_critiques || 0}</div><div class="stat-lbl">CVE critiques</div></div>
      <div class="stat-card ${scoreColor}"><div class="stat-val ${scoreColor}">${score}/100</div><div class="stat-lbl">Score Conformite ANSSI</div></div>
    `;

    const colors = ['#3b82f6','#10b981','#f59e0b','#ef4444','#8b5cf6','#06b6d4'];
    let osHtml = '', riskHtml = '', evHtml = '';

    const osEntries = Object.entries(s.os_repartition || {});
    if (osEntries.length) {
      const maxOs = Math.max(...osEntries.map(e => e[1]), 1);
      osEntries.forEach(([os, cnt], i) => {
        const pct = Math.round(cnt / maxOs * 100);
        osHtml += `<div class="bar-row">
          <div class="bar-lbl" title="${esc(os)}">${esc(os)}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${colors[i % colors.length]}"></div></div>
          <div class="bar-val">${cnt}</div>
        </div>`;
      });
    } else {
      osHtml = '<div style="color:var(--text-muted);font-size:12px">Aucune donnee</div>';
    }

    const riskColors = { 'Critique': '#ef4444', 'Eleve': '#f59e0b', 'Moyen': '#3b82f6', 'Faible': '#10b981' };
    const riskEntries = Object.entries(s.risques || {});
    const maxRisk = Math.max(...riskEntries.map(e => e[1]), 1);
    riskEntries.forEach(([lvl, cnt]) => {
      const pct = Math.round(cnt / maxRisk * 100);
      riskHtml += `<div class="bar-row">
        <div class="bar-lbl">${esc(lvl)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${riskColors[lvl] || '#64748b'}"></div></div>
        <div class="bar-val">${cnt}</div>
      </div>`;
    });

    const ev = s.evolution_parc || [];
    if (ev.length) {
      const maxEv = Math.max(...ev.map(e => e.cnt), 1);
      ev.forEach(e => {
        const h = Math.max(4, Math.round(e.cnt / maxEv * 72));
        evHtml += `<div title="${esc(e.date_scan)}: ${e.cnt} scan(s)" style="flex:1;background:var(--accent);border-radius:2px 2px 0 0;height:${h}px;min-width:6px;opacity:0.8"></div>`;
      });
    }

    charts.innerHTML = `
      <div class="panel">
        <div class="panel-title">Repartition par systeme d'exploitation</div>
        ${osHtml}
      </div>
      <div class="panel">
        <div class="panel-title">Niveaux de risques logiciels</div>
        ${riskHtml || '<div style="color:var(--text-muted);font-size:12px">Aucune donnee</div>'}
      </div>
      ${ev.length ? `<div class="panel" style="grid-column:1/-1">
        <div class="panel-title">Evolution des scans dans le temps</div>
        <div style="display:flex;align-items:flex-end;gap:3px;height:80px;padding-top:8px">${evHtml}</div>
      </div>` : ''}
    `;
  } catch(e) {
    kpi.innerHTML = `<div class="empty-state">Erreur de connexion : ${esc(e.message)}</div>`;
    setStatus(false);
  }
}

function buildCatQueryString(page) {
  const params = new URLSearchParams();
  const q = document.getElementById('cat-search').value;
  if (q) params.set('q', q);
  const cat = document.getElementById('cat-cat').value;
  if (cat) params.set('cat', cat);
  const risk = document.getElementById('cat-risk').value;
  if (risk) params.set('risk', risk);
  const eolF = document.getElementById('cat-eol').value;
  if (eolF) params.set('eol', eolF);
  const appF = document.getElementById('cat-approuve').value;
  if (appF) params.set('approuve', appF);
  const editeurType = document.getElementById('cat-editeur-type').value;
  if (editeurType) params.set('editeur', editeurType);
  const sourceF = document.getElementById('cat-source').value;
  if (sourceF) params.set('source', sourceF);
  const typeF = document.getElementById('cat-type').value;
  if (typeF) params.set('type', typeF);
  const metierF = document.getElementById('cat-metier').value;
  if (metierF) params.set('metier', metierF);
  const provenanceF = document.getElementById('cat-provenance').value;
  if (provenanceF) params.set('provenance', provenanceF);
  const postesF = document.getElementById('cat-postes').value;
  if (postesF) params.set('postes', postesF);
  params.set('page', page || 1);
  params.set('per_page', perPage);
  return '/api/logiciels?' + params.toString();
}

function updatePaginationUI() {
  const info = `${totalItems} logiciel(s) — Page ${currentPage}/${totalPages}`;
  document.getElementById('cat-count').textContent = info;
  document.getElementById('cat-page-info').textContent = `Page ${currentPage}/${totalPages}`;
  document.getElementById('cat-page-info-bottom').textContent = `Page ${currentPage} / ${totalPages}`;
  document.getElementById('cat-prev').disabled = currentPage <= 1;
  document.getElementById('cat-next').disabled = currentPage >= totalPages;
  document.getElementById('cat-prev-bottom').disabled = currentPage <= 1;
  document.getElementById('cat-next-bottom').disabled = currentPage >= totalPages;
  document.getElementById('cat-per-page').value = perPage;
}

function goToPage(n) {
  if (n < 1 || n > totalPages) return;
  currentPage = n;
  fetchCataloguePage();
}

function changePerPage(val) {
  perPage = parseInt(val) || 100;
  currentPage = 1;
  fetchCataloguePage();
}

async function fetchCataloguePage() {
  const table = document.getElementById('cat-table');
  table.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Chargement...</span></div>';
  try {
    const url = buildCatQueryString(currentPage);
    const resp = await api(url);
    catalogData = resp.data || [];
    totalItems = resp.total || 0;
    totalPages = resp.total_pages || 1;
    if (currentPage > totalPages) currentPage = Math.max(1, totalPages);
    applyLocalFilters();
    renderCatalogue(catalogData);
    updatePaginationUI();
  } catch(e) {
    table.innerHTML = `<div class="empty-state">Erreur : ${esc(e.message)}</div>`;
  }
}

function applyLocalFilters() {
  const paysF = document.getElementById('cat-pays').value;
  const paysSiegeF = document.getElementById('cat-pays-siege').value;
  const risqueSouvF = document.getElementById('cat-risque-souv').value;
  const niveauF = document.getElementById('cat-niveau').value;
  const origineF = document.getElementById('cat-origine').value;
  const refF = document.getElementById('cat-ref').value;
  if (!paysF && !paysSiegeF && !risqueSouvF && !niveauF && !origineF && !refF) return;
  catalogData = catalogData.filter(d => {
    if (paysF && d.pays !== paysF) return false;
    if (paysSiegeF && d.pays_siege !== paysSiegeF) return false;
    if (risqueSouvF && d.risque_souverainete !== risqueSouvF) return false;
    if (niveauF && d.niveau !== niveauF) return false;
    if (origineF && d.origine !== origineF) return false;
    if (refF) {
      const refInc = !d.metier || d.metier === 'Non classe' || !d.provenance_autorisee || !d.eol || d.eol === 'Inconnu' || d.approuve == 0;
      if (refF === 'incomplet' && !refInc) return false;
      if (refF === 'complet' && refInc) return false;
    }
    return true;
  });
}

async function loadCatalogue() {
  const table = document.getElementById('cat-table');
  table.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Chargement du catalogue...</span></div>';
  currentPage = 1;
  try {
    const url = buildCatQueryString(1);
    const resp = await api(url);
    catalogData = resp.data || [];
    totalItems = resp.total || 0;
    totalPages = resp.total_pages || 1;
    if (resp.filters) {
      if (resp.filters.categories) {
        document.getElementById('cat-cat').innerHTML = '<option value="">Toutes categories</option>' + resp.filters.categories.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
      }
      if (resp.filters.pays) {
        document.getElementById('cat-pays').innerHTML = '<option value="">Pays éditeur</option>' + resp.filters.pays.map(p => `<option value="${esc(p)}">${esc(p)}</option>`).join('');
      }
      if (resp.filters.origines) {
        document.getElementById('cat-origine').innerHTML = '<option value="">Origine</option>' + resp.filters.origines.map(o => `<option value="${esc(o)}">${esc(o)}</option>`).join('');
      }
      if (resp.filters.metiers) {
        document.getElementById('cat-metier').innerHTML = '<option value="">Métier</option>' + resp.filters.metiers.map(m => `<option value="${esc(m)}">${esc(m)}</option>`).join('');
      }
      if (resp.filters.sources) {
        document.getElementById('cat-source').innerHTML = '<option value="">Source</option>' + resp.filters.sources.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('');
      }
    }
    // Populate remaining dropdowns from page data (server may not provide all)
    const sieges = [...new Set(catalogData.map(d => d.pays_siege).filter(Boolean))].sort();
    if (sieges.length) {
      document.getElementById('cat-pays-siege').innerHTML = '<option value="">Siège social</option>' + sieges.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('');
    }
    const provs = [...new Set(catalogData.map(d => d.provenance_autorisee).filter(Boolean))].sort();
    if (provs.length) {
      document.getElementById('cat-provenance').innerHTML = '<option value="">Provenance</option>' + provs.map(p => `<option value="${esc(p)}">${esc(p)}</option>`).join('');
    }
    applyLocalFilters();
    renderCatalogue(catalogData);
    updatePaginationUI();
  } catch(e) {
    table.innerHTML = `<div class="empty-state">Erreur : ${esc(e.message)}</div>`;
  }
}

function badgeLic(cat) {
  const cls = LIC_CAT_BADGES[cat] || 'badge-inconnu';
  return `<span class="badge ${cls}">${esc(cat||'Inconnu')}</span>`;
}

function badgeSource(src) {
  const map = {
    'Registry':'badge badge-reg', 'Appx':'badge badge-appx', 'Winget':'badge badge-winget',
    'Chocolatey':'badge badge-choco', 'Portable':'badge badge-portable', 'PATH':'badge badge-path',
    'StartMenu':'badge badge-start', 'WindowsFeature':'badge badge-winfeat',
    'pip':'badge badge-pip', 'npm':'badge badge-npm', 'Composer':'badge badge-composer',
    'WSL':'badge badge-wsl'
  };
  const cls = map[src] || 'badge badge-faible';
  return `<span class="${cls}">${esc(src)}</span>`;
}

function badgeMetier(met) {
  const colors = {
    'Developpement':'#6C5CE7','BaseDonnees':'#0984E3','Design':'#E17055',
    'Multimedia':'#E84393','Bureautique':'#00B894','Securite':'#D63031',
    'Communication':'#00CEC9','Reseau':'#FDCB6E','Finance':'#636E72',
    'Utilitaire':'#74B9FF','Systeme':'#2D3436','Non classe':'#B2BEC3',
    'Autre':'#B2BEC3'
  };
  const c = colors[met] || '#B2BEC3';
  const darkText = {'#FDCB6E':'#2D3436','#74B9FF':'#2D3436','#B2BEC3':'#2D3436','#00CEC9':'#2D3436','#00B894':'#fff'};
  const textColor = darkText[c] || '#fff';
  return `<span class="badge badge-metier" style="background:${c};color:${textColor};font-size:10px">${esc(met)}</span>`;
}

function badgeOrigine(org) {
  const map = {
    'Windows':'badge badge-windows',
    'Intune':'badge badge-intune',
    'Utilisateur':'badge badge-user'
  };
  const cls = map[org] || 'badge badge-faible';
  return `<span class="${cls}">${esc(org)}</span>`;
}

function toggleCatalogueGroup() {
  _catGroupByMetier = !_catGroupByMetier;
  const btn = document.getElementById('cat-group-toggle');
  btn.textContent = _catGroupByMetier ? '⊟ Degrouper' : '⊞ Grouper';
  renderCatalogue(catalogData);
  updatePaginationUI();
}

function renderCatalogue(data) {
  if (!data.length) {
    document.getElementById('cat-table').innerHTML = '<div class="empty-state">Aucun logiciel trouve.</div>';
    return;
  }
  let html = '';
  if (_catGroupByMetier) {
    const grouped = {};
    data.forEach(d => {
      const met = d.metier || 'Non classe';
      if (!grouped[met]) grouped[met] = [];
      grouped[met].push(d);
    });
    const metKeys = Object.keys(grouped).sort();
    for (const met of metKeys) {
      const sws = grouped[met];
      html += `<table style="margin-bottom:12px"><thead><tr style="background:var(--surface-alt)">
        <th colspan="15" style="padding:8px 12px;font-size:13px">${badgeMetier(met)} <span style="font-weight:400;color:var(--text-muted)">${sws.length} logiciel(s)</span></th>
      </tr></thead><tbody>`;
      sws.forEach(d => {
        html += _catRow(d);
      });
      html += '</tbody></table>';
    }
  } else {
    html = `<table><thead><tr>
      <th>Logiciel</th><th>Editeur</th><th>Souveraineté</th><th>Metier</th><th>Categorie</th><th>Risque</th>
      <th>Postes</th><th>Origine</th><th>Sources</th><th>Niveau</th><th>Provenance</th><th>EOL</th><th>Approbation</th><th>État Réf.</th><th style="width:40px"></th>
    </tr></thead><tbody>`;
    data.forEach(d => { html += _catRow(d); });
    html += '</tbody></table>';
  }
  document.getElementById('cat-table').innerHTML = html;
}

function badgeNiveauCat(n) {
  if (!n) return '-';
  const map = {'Windows Base':'badge-danger', 'Installé par Administrateur':'badge-warning', 'Installé par Utilisateur courant':'badge-user'};
  let icon = '';
  return `<span class="badge ${map[n] || 'badge-inconnu'}" style="font-size:10px">${icon}${esc(n)}</span>`;
}

function _catRow(d) {
  const isCrit = d.risque_niveau === 'Critique';
  const isEol = d.eol === 'OUI' || d.eol == 1;
  const isMs = d.est_microsoft == 1;
  const sources = (d.install_sources || '').split(',').filter(Boolean);
  
  const isMetier = d.metier && !['Systeme', 'Utilitaire', 'Non classe', ''].includes(d.metier);
  const rowClass = isCrit ? 'row-danger' : isEol ? 'row-warning' : isMetier ? 'row-metier' : '';
  
  const refIncomplet = !d.metier || d.metier === 'Non classe' || !d.provenance_autorisee || !d.eol || d.eol === 'Inconnu' || d.approuve == 0;
  const badgeRef = refIncomplet ? '<span class="badge badge-warning" style="font-size:10px">Incomplet</span>' : '<span class="badge badge-success" style="font-size:10px">Complet</span>';

  const sovRiskColor = {'Critique':'#e74c3c','Eleve':'#e67e22','Moyen':'#f39c12'};
  const sovStyle = c => `background:${sovRiskColor[c]||'#636E72'};color:#fff;font-size:9px;padding:1px 4px;border-radius:3px;white-space:nowrap`;
  let sovHtml = '-';
  if (d.pays) {
    const parts = [`<span class="badge" style="background:#636E72;color:#fff;font-size:10px" title="Pays editeur">${esc(d.pays)}</span>`];
    if (d.pays_siege && d.pays_siege !== d.pays) {
      parts.push(`<span style="font-size:9px;color:var(--text-muted)">Siège: ${esc(d.pays_siege)}</span>`);
    }
    if (d.risque_souverainete && d.risque_souverainete !== 'Faible') {
      parts.push(`<span style="${sovStyle(d.risque_souverainete)}" title="Risque souverainete">${esc(d.risque_souverainete)}</span>`);
    }
    let line2 = '';
    if (d.pays_hebergement && d.pays_hebergement !== d.pays) {
      line2 += `<span style="font-size:9px;color:var(--text-muted);margin-right:4px" title="Hebergement">Héb: ${esc(d.pays_hebergement)}</span>`;
    }
    if (d.pays_developpement && d.pays_developpement !== d.pays) {
      line2 += `<span style="font-size:9px;color:var(--text-muted)" title="Developpement">Dév: ${esc(d.pays_developpement)}</span>`;
    }
    let line3 = '';
    if (d.restrictions) {
      line3 = `<div style="font-size:8px;color:#e74c3c;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(d.restrictions)}">Restr: ${esc(d.restrictions)}</div>`;
    }
    sovHtml = `<div style="line-height:1.4">${parts.join(' ')}${line2 ? '<br>'+line2 : ''}${line3}</div>`;
  }

  return `<tr class="${rowClass}" onclick="showLogiciel('${jesc(d.nom)}')">
    <td>
      <div class="td-main">${esc(d.nom)}</div>
      <div class="td-sub">${isMs ? '<span class="badge badge-microsoft">Microsoft</span>' : '<span class="badge badge-tiers">Tiers</span>'}</div>
    </td>
    <td>${esc(d.editeur) || '-'}</td>
    <td style="min-width:110px">${sovHtml}</td>
    <td>${d.metier ? badgeMetier(d.metier) : '-'}</td>
    <td>${esc(d.categorie) || '-'}</td>
    <td>${badge(d.risque_niveau)}</td>
    <td><strong>${d.nb_postes || 0}</strong> poste(s)</td>
    <td>${badgeOrigine(d.origine)}</td>
    <td>${sources.map(s => badgeSource(s)).join(' ')}</td>
    <td>${badgeNiveauCat(d.niveau)}</td>
    <td>${d.provenance_autorisee ? '<span class="badge badge-provenance" style="font-size:10px">' + esc(d.provenance_autorisee) + '</span>' : '-'}</td>
    <td>${isEol ? '<span class="badge badge-eol">EOL</span>' : '-'}</td>
    <td>${d.approuve == 1 ? '<span class="badge badge-approuve">Approuve</span>' : '<span class="badge badge-nonapprouve">Non approuve</span>'}</td>
    <td>${badgeRef}</td>
    <td style="position:relative">
      <button class="btn btn-sm" style="font-size:12px;padding:2px 6px" onclick="event.stopPropagation();toggleCatActions(this)" title="Actions">⋮</button>
      <div class="cat-actions-menu" style="display:none;position:absolute;right:0;top:100%;z-index:100;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:4px 0;min-width:140px;box-shadow:0 4px 12px rgba(0,0,0,0.3)">
        <div style="padding:6px 12px;font-size:11px;cursor:pointer" onclick="event.stopPropagation();window.toggleCatApprove('${jesc(d.nom)}', ${d.approuve == 1 ? 0 : 1})">
          ${d.approuve == 1 ? 'Retirer approbation' : 'Approuver'}
        </div>
        <div style="padding:6px 12px;font-size:11px;cursor:pointer" onclick="event.stopPropagation();window.deleteCatalogue('${jesc(d.nom)}')">
          Supprimer
        </div>
      </div>
    </td>
  </tr>`;
}

window.toggleCatActions = function(btn) {
  const menu = btn.nextElementSibling;
  document.querySelectorAll('.cat-actions-menu').forEach(m => { if (m !== menu) m.style.display = 'none'; });
  menu.style.display = menu.style.display === 'none' ? 'block' : 'none';
};
document.addEventListener('click', function(e) {
  if (!e.target.closest('.cat-actions-menu') && !e.target.closest('button[onclick*="toggleCatActions"]')) {
    document.querySelectorAll('.cat-actions-menu').forEach(m => m.style.display = 'none');
  }
});
window.toggleCatApprove = async function(nom, val) {
  try {
    await api('/api/logiciel/' + encodeURIComponent(nom), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({approuve: val})
    });
    fetchCataloguePage();
  } catch(e) { alert('Erreur: ' + e.message); }
};
window.deleteCatalogue = async function(nom) {
  if (!confirm('Supprimer definitivement ' + nom + ' du catalogue ?')) return;
  try {
    await api('/api/logiciel/' + encodeURIComponent(nom) + '/delete-catalogue', { method: 'DELETE' });
    fetchCataloguePage();
  } catch(e) { alert('Erreur: ' + e.message); }
};

window.filterCatalogue = function() {
  currentPage = 1;
  fetchCataloguePage();
};

async function loadMachines() {
  const table = document.getElementById('mach-table');
  table.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Chargement des postes...</span></div>';
  try {
    machinesData = await api('/api/machines');
    const oss = [...new Set(machinesData.map(m => m.os_nom).filter(Boolean))].sort();
    const sel = document.getElementById('mach-os');
    sel.innerHTML = '<option value="">Tous OS</option>' + oss.map(o => `<option value="${esc(o)}">${esc(o)}</option>`).join('');
    renderMachines(machinesData);
  } catch(e) {
    table.innerHTML = `<div class="empty-state">Erreur : ${esc(e.message)}</div>`;
  }
}

function renderMachines(data) {
  document.getElementById('mach-count').textContent = `${data.length} machine(s)`;
  if (!data.length) {
    document.getElementById('mach-table').innerHTML = '<div class="empty-state">Aucune machine.</div>';
    return;
  }
  let html = `<table><thead><tr>
    <th>Poste</th><th>IP / MAC</th><th>Utilisateur</th><th>OS</th><th>CPU / RAM</th>
    <th>Stockage</th><th>Score Secu.</th><th>Risques</th><th>Logiciels</th><th>Dernier scan</th>
  </tr></thead><tbody>`;
  data.forEach(m => {
    const crit = m.nb_critiques || 0;
    html += `<tr class="${crit > 0 ? 'row-danger' : ''}" onclick="showMachine('${jesc(m.scan_id)}')">
      <td>
        <div class="td-main">${esc(m.nom_pc)}</div>
        <div class="td-sub">${esc(m.type_machine) || ''} ${esc(m.fabricant) || ''} ${esc(m.modele) || ''}</div>
      </td>
      <td>
        <div>${esc(m.ip) || '-'}</div>
        <div class="td-mono">${esc(m.mac) || ''}</div>
      </td>
      <td>${esc(m.utilisateur) || '-'}</td>
      <td>
        <div>${esc(m.os_nom) || '-'}</div>
        <div class="td-sub">${esc(m.os_build) || ''}</div>
      </td>
      <td>
        <div class="td-sub">${esc(m.cpu_nom) ? m.cpu_nom.substring(0,30) : '-'}</div>
        <div class="td-sub">${m.ram_gb || 0} Go RAM</div>
      </td>
      <td>
        <div>${m.disque_libre_gb || 0} Go libre</div>
        <div class="progress-bar" style="width:80px;margin-top:4px"><div class="progress-fill" style="width:${100-(m.disque_pct_libre||0)}%;background:${(m.disque_pct_libre||0) < 20 ? 'var(--danger)' : 'var(--accent)'}"></div></div>
      </td>
      <td>
        <div style="font-weight:600;color:${(m.score_securite||0)>=70 ? 'var(--success)' : 'var(--warning)'}">${m.score_securite || 0}/100</div>
      </td>
      <td>
        ${crit ? `<span class="badge badge-critique">${crit} crit.</span> ` : ''}
        ${m.nb_eol ? `<span class="badge badge-eol">${m.nb_eol} EOL</span> ` : ''}
        ${m.nb_obsoletes ? `<span class="badge badge-obsolete">${m.nb_obsoletes} obs.</span> ` : ''}
        ${!crit && !m.nb_eol && !m.nb_obsoletes ? '<span class="badge badge-ok">Sain</span>' : ''}
      </td>
      <td>${m.nb_logiciels || 0}</td>
      <td>
        <div class="td-sub">${esc(m.date_scan) || '-'}</div>
        <div class="td-sub">${esc(m.heure_scan) || ''}</div>
      </td>
    </tr>`;
  });
  html += '</tbody></table>';
  document.getElementById('mach-table').innerHTML = html;
}

window.filterMachines = function() {
  const q = document.getElementById('mach-search').value.toLowerCase();
  const os = document.getElementById('mach-os').value;
  const risk = document.getElementById('mach-risk').value;
  const f = machinesData.filter(m => {
    if (q && !((m.nom_pc||'').toLowerCase().includes(q) || (m.ip||'').includes(q) || (m.utilisateur||'').toLowerCase().includes(q))) return false;
    if (os && m.os_nom !== os) return false;
    if (risk === 'critique' && !(m.nb_critiques > 0)) return false;
    if (risk === 'eol' && !(m.nb_eol > 0)) return false;
    if (risk === 'sain' && (m.nb_critiques > 0 || m.nb_eol > 0 || m.nb_obsoletes > 0)) return false;
    return true;
  });
  renderMachines(f);
};

async function loadVulns() {
  const table = document.getElementById('vuln-table');
  table.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Analyse des vulnerabilites...</span></div>';
  try {
    vulnsData = await api('/api/vulnerabilites');
    renderVulns(vulnsData);
  } catch(e) {
    table.innerHTML = `<div class="empty-state">Erreur : ${esc(e.message)}</div>`;
  }
}

function renderVulns(data) {
  document.getElementById('vuln-count').textContent = `${data.length} entree(s)`;
  if (!data.length) {
    document.getElementById('vuln-table').innerHTML = '<div class="empty-state">Aucun risque majeur detecte.</div>';
    return;
  }
  let html = `<table><thead><tr>
    <th>Logiciel</th><th>Editeur</th><th>Niveau de Risque</th><th>Score</th><th>Postes impactes</th><th>Motif</th>
  </tr></thead><tbody>`;
  data.forEach(d => {
    html += `<tr class="${d.risque_niveau === 'Critique' ? 'row-danger' : d.risque_niveau === 'Eleve' ? 'row-warning' : ''}" onclick="showLogiciel('${jesc(d.nom)}')">
      <td>
        <div class="td-main">${esc(d.nom)}</div>
        <div class="td-sub">${esc(d.version) || ''}</div>
      </td>
      <td>${esc(d.editeur) || '-'}</td>
      <td>${badge(d.risque_niveau)}</td>
      <td><strong>${d.risque_score || 0}</strong>/10</td>
      <td><strong style="color:var(--accent)">${d.machines_impactees || 1}</strong> machine(s)</td>
      <td><span style="color:var(--text-secondary);font-size:12px">${esc(d.risque_desc) || ''}</span></td>
    </tr>`;
  });
  html += '</tbody></table>';
  document.getElementById('vuln-table').innerHTML = html;
}

window.filterVulns = function() {
  const q = document.getElementById('vuln-search').value.toLowerCase();
  const lvl = document.getElementById('vuln-level').value;
  const f = vulnsData.filter(d => {
    if (q && !(d.nom||'').toLowerCase().includes(q)) return false;
    if (lvl && d.risque_niveau !== lvl) return false;
    return true;
  });
  renderVulns(f);
};

const LIC_CAT_BADGES = {
  'Open Source':'badge-oss', 'Freeware':'badge-gratuit', 'Payant':'badge-payant',
  'Freemium':'badge-freemium', 'Inclus Windows':'badge-windows', 'Essai':'badge-essai',
  'Donationware':'badge-donation', 'Adware':'badge-adware', 'Abandonware':'badge-abandon',
  'Inconnu':'badge-inconnu'
};
const LIC_CAT_COLORS_BG = {
  'Open Source':'#065f46','Freeware':'#1e40af','Payant':'#7f1d1d',
  'Freemium':'#78350f','Inclus Windows':'#4c1d95','Essai':'#7c2d12',
  'Donationware':'#0f766e','Adware':'#7f1d1d','Abandonware':'#374151',
  'Inconnu':'#374151'
};
const RISQUE_COLORS = { 'Critique':'var(--danger)','Eleve':'#e67e22','Moyen':'#f39c12','Faible':'#3498db','Inconnu':'var(--text-muted)' };

async function loadLicences() {
  const table = document.getElementById('lic-table');
  table.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Chargement des licences...</span></div>';
  try {
    logicielsLicData = await api('/api/logiciels-licences');
    licencesData = await api('/api/licences');
    const eds = [...new Set(logicielsLicData.map(d => d.editeur).filter(Boolean))].sort();
    document.getElementById('lic-ed-filter').innerHTML = '<option value="">Tous editeurs</option>' + eds.map(e => `<option value="${esc(e)}">${esc(e)}</option>`).join('');
    renderLicApp(logicielsLicData);
    renderLicKpi(logicielsLicData);
  } catch(e) {
    table.innerHTML = `<div class="empty-state">Erreur chargement: ${esc(e.message)}. Verifiez que le serveur Flask tourne.</div>`;
  }
}

function renderLicKpi(data) {
  const total = data.length;
  const counts = {};
  data.forEach(d => { counts[d.categorie_licence] = (counts[d.categorie_licence] || 0) + 1; });
  const topCat = Object.entries(counts).sort((a,b) => b[1]-a[1]);
  let html = `<div class="stat-card"><div class="stat-val accent">${total}</div><div class="stat-lbl">Applications scannees</div></div>`;
  topCat.slice(0, 5).forEach(([cat, cnt]) => {
    const pct = Math.round(cnt/total*100);
    const bg = LIC_CAT_COLORS_BG[cat] || '#374151';
    html += `<div class="stat-card"><div class="stat-val" style="color:var(--text)">${cnt}</div><div class="stat-lbl" style="font-size:11px"><span class="badge ${LIC_CAT_BADGES[cat]||'badge-inconnu'}">${esc(cat)}</span> ${pct}%</div></div>`;
  });
  document.getElementById('lic-kpi').innerHTML = html;
}

function renderLicApp(data) {
  const table = document.getElementById('lic-table');
  if (!data.length) {
    table.innerHTML = '<div class="empty-state">Aucune application scannee. Lancez une collecte depuis l\'onglet Machines.</div>';
    document.getElementById('lic-kpi').innerHTML = '';
    return;
  }
  let html = `<table><thead><tr>
    <th>Application</th><th>Editeur</th><th>Licence</th><th>Sous-type</th>
    <th>Installation</th><th>Postes</th><th>Versions</th><th>Risque</th><th>Actions</th>
  </tr></thead><tbody>`;
  data.forEach(d => {
    const badgeCls = LIC_CAT_BADGES[d.categorie_licence] || 'badge-inconnu';
    const manuelle = d.licence_manuelle;
    const risqueColor = RISQUE_COLORS[d.risque_niveau] || 'var(--text-muted)';
    const installLabel = d.install_type === 'Portable (.exe)' ? 'Portable' : d.install_type === 'Composant Windows' ? 'Windows' : 'Standard';
    const n = jesc(d.nom), e = jesc(d.editeur), c = jesc(d.categorie_licence);
    html += `<tr onclick="showLicDetail('${n}','${e}')" style="cursor:pointer">
      <td class="td-main">${esc(d.nom)} <span style="font-size:10px;color:var(--text-muted)">v${esc(d.version_recente)}</span></td>
      <td style="font-size:11px">${esc(extrait_editeur(d.editeur))}</td>
      <td><span class="badge ${badgeCls}">${esc(d.categorie_licence)}</span></td>
      <td style="font-size:11px;color:var(--text-muted)">${esc(d.sous_type_licence) || '-'}</td>
      <td style="font-size:11px"><span class="badge badge-faible">${installLabel}</span> ${esc(d.install_type)}</td>
      <td>${d.nb_machines}</td>
      <td>${d.nb_versions}</td>
      <td><span style="color:${risqueColor};font-size:11px;font-weight:500">${esc(d.risque_niveau||'-')}</span></td>
      <td>
        <button class="btn btn-secondary btn-xs" onclick="event.stopPropagation();showLicenceFormFromApp('${n}','${e}','${c}')">${manuelle ? 'Editer licence' : 'Ajouter licence'}</button>
      </td>
    </tr>`;
  });
  html += '</tbody></table>';
  table.innerHTML = html;
}

function extrait_editeur(ed) {
  if (!ed) return '-';
  const m = ed.match(/^CN=([^,]+)/);
  if (m) return m[1];
  if (ed.length > 30) return ed.slice(0,28)+'...';
  return ed;
}

window.filterLicencesApp = function() {
  const q = document.getElementById('lic-search').value.toLowerCase();
  const cat = document.getElementById('lic-cat-filter')?.value || '';
  const ed = document.getElementById('lic-ed-filter')?.value || '';
  const f = logicielsLicData.filter(d => {
    if (q && !(d.nom||'').toLowerCase().includes(q) && !(d.editeur||'').toLowerCase().includes(q)) return false;
    if (cat && (d.categorie_licence||'') !== cat) return false;
    if (ed && (d.editeur||'') !== ed) return false;
    return true;
  });
  renderLicApp(f);
  renderLicKpi(f);
};

window.showLicDetail = function(nom, editeur) {
  const d = logicielsLicData.find(x => x.nom === nom && x.editeur === editeur);
  if (!d) return;
  document.getElementById('dlic-title').textContent = d.nom;
  const badgeCls = LIC_CAT_BADGES[d.categorie_licence] || 'badge-inconnu';
  const cout = d.cout_annuel ? d.cout_annuel + ' EUR' : 'Non renseigne';
  document.getElementById('dlic-body').innerHTML = `
    <div class="field-grid">
      <div class="form-group" style="grid-column:1/-1;display:flex;align-items:center;gap:10px">
        <span class="badge ${badgeCls}" style="font-size:14px;padding:4px 12px">${esc(d.categorie_licence)}</span>
        ${d.licence_manuelle ? '<span class="badge badge-ok">Licence manuelle</span>' : '<span class="badge badge-warn">Detection automatique</span>'}
        ${d.numero_licence ? '<span class="badge badge-info">N° ' + esc(d.numero_licence) + '</span>' : ''}
      </div>
      <div style="grid-column:1/-1;display:grid;grid-template-columns:1fr 1fr;gap:12px;background:var(--bg-card);border-radius:8px;padding:12px">
        <div><label style="font-size:10px;color:var(--text-muted);text-transform:uppercase">Type de licence</label><div style="font-weight:600">${esc(d.categorie_licence)}</div></div>
        <div><label style="font-size:10px;color:var(--text-muted);text-transform:uppercase">Sous-type</label><div>${esc(d.sous_type_licence) || 'Non renseigne'}</div></div>
        <div><label style="font-size:10px;color:var(--text-muted);text-transform:uppercase">Nombre de licences</label><div>${d.nombre_licences != null ? d.nombre_licences : 'Non renseigne'}</div></div>
        <div><label style="font-size:10px;color:var(--text-muted);text-transform:uppercase">Nb utilisees</label><div>${d.nb_utilisees != null ? d.nb_utilisees : 'Non renseigne'}</div></div>
        <div><label style="font-size:10px;color:var(--text-muted);text-transform:uppercase">Date d'expiration</label><div>${d.date_expiration || 'Non renseignee'}</div></div>
        <div><label style="font-size:10px;color:var(--text-muted);text-transform:uppercase">Date d'achat</label><div>${d.date_achat || 'Non renseignee'}</div></div>
        <div><label style="font-size:10px;color:var(--text-muted);text-transform:uppercase">Cout annuel</label><div>${cout}</div></div>
        <div><label style="font-size:10px;color:var(--text-muted);text-transform:uppercase">Fournisseur</label><div>${esc(d.fournisseur) || 'Non renseigne'}</div></div>
      </div>
      <hr class="section-sep" style="grid-column:1/-1;margin:8px 0">
      ${afficheChamp('Editeur', d.editeur)}
      ${afficheChamp('Version recente', d.version_recente)}
      ${afficheChamp('Type installation', d.install_type)}
      ${afficheChamp('Source installation', d.install_source)}
      ${afficheChamp('Nombre de postes', d.nb_machines)}
      ${afficheChamp('Risque', d.risque_niveau + (d.risque_score ? ' ('+d.risque_score+'/10)' : ''))}
      ${afficheChamp('Contact', d.contact || 'Non renseigne')}
      ${afficheChamp('Description', d.description || 'Non disponible')}
      ${afficheChamp('Notes', d.notes || 'Non renseigne')}
      ${afficheChamp('Chemin', d.chemin || 'Non disponible')}
    </div>
    <hr class="section-sep">
    <div style="display:flex;gap:8px">
      <button class="btn btn-primary" onclick="closeDrawer('licence');showLicenceFormFromApp('${jesc(d.nom)}','${jesc(d.editeur)}','${jesc(d.categorie_licence)}')">${d.licence_manuelle ? 'Modifier la licence' : 'Ajouter une licence manuelle'}</button>
      <button class="btn btn-secondary" onclick="closeDrawer('licence')">Fermer</button>
    </div>`;
  openDrawer('licence');
};

function afficheChamp(label, value) {
  return `<div class="form-group"><label class="form-label" style="font-size:11px;color:var(--text-muted)">${label}</label><div style="font-size:13px">${value || '-'}</div></div>`;
}

window.showLicenceFormFromApp = function(nom, editeur, cat) {
  const existing = licencesData.find(l => l.logiciel_nom === nom && (l.editeur||'') === editeur);
  if (existing) { showLicenceForm(existing.id); return; }
  showLicenceForm(null, nom, editeur, cat);
};

window.showLicenceForm = function(id, prefillNom, prefillEditeur, prefillCat) {
  const lic = id ? licencesData.find(l => l.id === id) : {};
  const catList = Object.keys(LIC_CAT_BADGES);
  document.getElementById('dlic-title').textContent = id ? 'Modifier la licence' : 'Nouvelle licence';
  document.getElementById('dlic-body').innerHTML = `
    <div class="licence-form-grid">
      <div class="form-group"><label class="form-label">Logiciel *</label><input type="text" id="lf-nom" value="${esc(lic?.logiciel_nom||prefillNom||'')}"></div>
      <div class="form-group"><label class="form-label">Editeur</label><input type="text" id="lf-editeur" value="${esc(lic?.editeur||prefillEditeur||'')}"></div>
      <div class="form-group"><label class="form-label">Categorie licence</label>
        <select id="lf-categorie">
          <option value="">-- Detection auto --</option>
          ${catList.map(t => `<option ${(lic?.categorie_licence||prefillCat)===t?'selected':''}>${t}</option>`).join('')}
        </select>
      </div>
      <div class="form-group"><label class="form-label">Type de licence</label>
        <select id="lf-type">
          <option value="">--</option>
          ${['Proprietaire','Open Source','Freemium','Abonnement','Perpetuelle','Par utilisateur','Par poste'].map(t => `<option ${lic?.type_licence===t?'selected':''}>${t}</option>`).join('')}
        </select>
      </div>
      <div class="form-group"><label class="form-label">Numero de licence</label><input type="text" id="lf-num" value="${esc(lic?.numero_licence||'')}"></div>
      <div class="form-group"><label class="form-label">Nb total de licences</label><input type="number" id="lf-nb" value="${lic?.nb_licences||0}" min="0"></div>
      <div class="form-group"><label class="form-label">Nb utilisees</label><input type="number" id="lf-nbused" value="${lic?.nb_utilisees||0}" min="0"></div>
      <div class="form-group"><label class="form-label">Date d'achat</label><input type="date" id="lf-achat" value="${esc(lic?.date_achat||'')}"></div>
      <div class="form-group"><label class="form-label">Date d'expiration</label><input type="date" id="lf-exp" value="${esc(lic?.date_expiration||'')}"></div>
      <div class="form-group"><label class="form-label">Cout annuel (EUR)</label><input type="number" id="lf-cout" value="${lic?.cout_annuel||0}" min="0"></div>
      <div class="form-group"><label class="form-label">Fournisseur</label><input type="text" id="lf-fourn" value="${esc(lic?.fournisseur||'')}"></div>
      <div class="form-group"><label class="form-label">Contact fournisseur</label><input type="text" id="lf-contact" value="${esc(lic?.contact_fournisseur||'')}"></div>
      <div class="form-group"><label class="form-label">Renouvellement auto</label>
        <select id="lf-renew"><option value="0" ${!lic?.renouvellement_auto?'selected':''}>Non</option><option value="1" ${lic?.renouvellement_auto?'selected':''}>Oui</option></select>
      </div>
      <div class="form-group" style="grid-column:1/-1"><label class="form-label">Notes</label><textarea id="lf-notes" rows="3">${esc(lic?.notes||'')}</textarea></div>
    </div>
    <div style="margin-top:16px;display:flex;gap:8px">
      <button class="btn btn-primary" onclick="saveLicence(${id||'null'})">Enregistrer</button>
      <button class="btn btn-secondary" onclick="closeDrawer('licence')">Annuler</button>
    </div>`;
  openDrawer('licence');
};

window.saveLicence = async function(id) {
  const payload = {
    id: id || undefined,
    logiciel_nom: document.getElementById('lf-nom').value,
    editeur: document.getElementById('lf-editeur').value,
    categorie_licence: document.getElementById('lf-categorie').value || undefined,
    type_licence: document.getElementById('lf-type').value,
    numero_licence: document.getElementById('lf-num').value,
    nb_licences: parseInt(document.getElementById('lf-nb').value) || 0,
    nb_utilisees: parseInt(document.getElementById('lf-nbused').value) || 0,
    date_achat: document.getElementById('lf-achat').value,
    date_expiration: document.getElementById('lf-exp').value,
    cout_annuel: parseFloat(document.getElementById('lf-cout').value) || 0,
    fournisseur: document.getElementById('lf-fourn').value,
    contact_fournisseur: document.getElementById('lf-contact').value,
    renouvellement_auto: parseInt(document.getElementById('lf-renew').value),
    notes: document.getElementById('lf-notes').value,
  };
  try {
    await api('/api/licences', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    closeDrawer('licence');
    const navLic = document.querySelector('.nav-item[data-tab="licences"]');
    if (navLic) delete navLic.dataset.loaded;
    loadLicences();
  } catch(e) { alert('Erreur : ' + e.message); }
};

window.deleteLicenceApp = async function(nom, editeur) {
  const lic = licencesData.find(l => l.logiciel_nom === nom && (l.editeur||'') === editeur);
  if (!lic) return;
  if (!confirm('Supprimer la licence pour ' + nom + ' ?')) return;
  try {
    await api('/api/licences/' + lic.id, { method: 'DELETE' });
    const navLicD = document.querySelector('.nav-item[data-tab="licences"]');
    if (navLicD) delete navLicD.dataset.loaded;
    loadLicences();
  } catch(e) { alert('Erreur : ' + e.message); }
};

async function loadConformite() {
  try {
    const data = await api('/api/conformite');
    const rules = data.regles || [];
    const domaines = data.domaines || {};

    // Score global
    const score = data.score || 0;
    const scoreColor = score >= 80 ? 'var(--success)' : score >= 50 ? 'var(--warning)' : 'var(--danger)';
    document.getElementById('conf-score-val').textContent = score;
    document.getElementById('conf-score-val').style.color = scoreColor;
    const okCount = rules.filter(r => r.statut === 'OK').length;
    const partielCount = rules.filter(r => r.statut === 'Partiel').length;
    const koCount = rules.filter(r => r.statut === 'KO').length;
    document.getElementById('conf-score-detail').innerHTML =
      `${okCount} OK, ${partielCount} partiel, ${koCount} KO sur ${rules.length} regles &middot; ${data.total_machines || 0} machines`;

    // Domaines
    let domainesHtml = '';
    for (const [dom, info] of Object.entries(domaines)) {
      const dc = info.couleur === 'success' ? 'var(--success)' : info.couleur === 'warning' ? 'var(--warning)' : 'var(--danger)';
      domainesHtml += `<div class="domaine-card">
        <div class="domaine-header">
          <span class="domaine-name">${esc(dom)}</span>
          <span class="domaine-poids">${info.poids} pts</span>
        </div>
        <div class="domaine-bar-wrap">
          <div class="domaine-bar" style="width:${info.score}%;background:${dc}"></div>
        </div>
        <div class="domaine-score" style="color:${dc}">${info.score}%</div>
        <div class="domaine-regles">${info.nb_regles} regles</div>
      </div>`;
    }
    document.getElementById('conf-domaines').innerHTML = domainesHtml || '<div class="empty-state">Aucun domaine</div>';

    // Regles
    let html = '';
    rules.forEach(r => {
      const isVerifiable = r.statut !== 'Non verifie';
      if (!isVerifiable) return;
      const cls = r.statut === 'OK' ? 'badge-ok' : r.statut === 'Partiel' ? 'badge-warn' : 'badge-nok';
      const barColor = r.statut === 'OK' ? 'var(--success)' : r.statut === 'Partiel' ? 'var(--warning)' : 'var(--danger)';
      const barPct = r.pct || 0;
      const koMachines = r.machines_ko || [];
      const expandedId = 'ko-details-' + r.regle.replace(/[^a-z0-9]/gi, '');
      const couv = r.couverture || 0;
      const couvCls = couv >= 80 ? 'badge-ok' : couv >= 50 ? 'badge-warn' : 'badge-nok';

      html += `<div class="rule-item">
        <div class="rule-header">
          <div class="rule-left">
            <span class="badge ${cls}" style="font-size:10px">${esc(r.statut)}</span>
            <span class="rule-name">${esc(r.description)}</span>
            <span class="rule-niveau badge badge-${r.niveau === 'Critique' ? 'nok' : r.niveau === 'Eleve' ? 'warn' : 'faible'}" style="font-size:9px;margin-left:6px">${esc(r.niveau)}</span>
            <span class="badge ${couvCls}" style="font-size:8px;margin-left:4px" title="Couverture: ${couv}% des machines ont la donnee necessaire">${couv}%</span>
          </div>
          <div class="rule-right">
            <span class="rule-poids">P${r.poids}</span>
            <span class="rule-count">${r.ok}/${r.total} machines</span>
          </div>
        </div>
        <div class="rule-bar-wrap">
          <div class="rule-bar" style="width:${barPct}%;background:${barColor}"></div>
        </div>
        <div class="rule-meta">
          ${r.remediation ? `<span class="rule-remediation" title="${esc(r.remediation)}">${esc(r.remediation)}</span>` : ''}
          ${koMachines.length ? `<button class="btn btn-ghost btn-xs" onclick="toggleEl('${expandedId}')" style="margin-left:auto;font-size:10px">${koMachines.length} machine(s) en echec &darr;</button>` : ''}
        </div>
        ${koMachines.length ? `<div id="${expandedId}" class="rule-ko-list" style="display:none">
          ${koMachines.map(km => `<div class="rule-ko-item"><strong>${esc(km.machine)}</strong>${km.raison ? ': ' + esc(km.raison) : ''}</div>`).join('')}
        </div>` : ''}
      </div>`;
    });

    // Regles non verifiables (affichage separe, attenue)
    const nonVerifiables = rules.filter(r => r.statut === 'Non verifie');
    if (nonVerifiables.length) {
      html += '<div class="panel-title" style="margin-top:16px;font-size:12px;color:var(--text-muted)">Regles non verifiables (donnees manquantes)</div>';
      nonVerifiables.forEach(r => {
        html += `<div class="rule-item" style="opacity:0.5">
          <div class="rule-header">
            <div class="rule-left"><span class="badge badge-inconnu" style="font-size:9px">N/V</span>
            <span class="rule-name" style="font-size:12px">${esc(r.description)}</span></div>
            <div class="rule-right"><span class="rule-poids" style="font-size:10px">P${r.poids}</span></div>
          </div>
        </div>`;
      });
    }
    document.getElementById('conf-rules-list').innerHTML = html || '<div class="empty-state">Aucune regle.</div>';

    // Extra rules (custom)
    if (data.extra_regles && data.extra_regles.length) {
      let extraHtml = '<div class="panel-title" style="margin-top:16px">Regles personnalisees</div>';
      data.extra_regles.forEach(r => {
        const cls = r.statut === 'OK' || r.statut === 'ok' ? 'badge-ok' : 'badge-nok';
        extraHtml += `<div class="rule-item" style="opacity:0.7">
          <div class="rule-header">
            <div class="rule-left"><span class="rule-name" style="font-size:12px">${esc(r.regle)}</span></div>
            <div class="rule-right"><span class="badge ${cls}">${esc(r.statut)}</span></div>
          </div>
        </div>`;
      });
      document.getElementById('conf-extra-rules').innerHTML = extraHtml;
    }
  } catch(e) {
    document.getElementById('conf-rules-list').innerHTML = `<div class="empty-state">Erreur : ${esc(e.message)}</div>`;
  }
}

function toggleEl(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

let _secAuditData = [];

async function loadSecurite() {
  const table = document.getElementById('sec-table');
  table.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Analyse de securite...</span></div>';
  try {
      const audit = await api('/api/audit/security');
      _secAuditData = audit.logiciels || [];
      const catCounts = {critique:0, urgent:0, recommande:0, surveiller:0, ok:0};
      _secAuditData.forEach(d => { catCounts[d.cat_action] = (catCounts[d.cat_action]||0) + 1; });
      const scoreMoyen = _secAuditData.length ? Math.round(_secAuditData.reduce((s,d)=>s+(d.score_audit||0),0)/_secAuditData.length) : 0;
      document.getElementById('sec-kpi').innerHTML = `
        <div class="stat-card"><div class="stat-val" style="color:var(--danger)">${audit.critiques || 0}</div><div class="stat-lbl">Score &lt; 30</div></div>
        <div class="stat-card"><div class="stat-val" style="color:#e74c3c">${catCounts.urgent||0}</div><div class="stat-lbl">Urgent</div></div>
        <div class="stat-card"><div class="stat-val" style="color:var(--warning)">${catCounts.recommande||0}</div><div class="stat-lbl">Recommande</div></div>
        <div class="stat-card"><div class="stat-val accent">${catCounts.surveiller||0}</div><div class="stat-lbl">A surveiller</div></div>
        <div class="stat-card"><div class="stat-val" style="color:var(--success)">${catCounts.ok||0}</div><div class="stat-lbl">OK</div></div>
        <div class="stat-card"><div class="stat-val" style="color:#8b5cf6">${scoreMoyen}</div><div class="stat-lbl">Score moyen /100</div></div>
        <div class="stat-card"><div class="stat-val">${audit.total||0}</div><div class="stat-lbl">Total audites</div></div>
      `;
      renderSecAudit(_secAuditData);
    } catch(e) {
      table.innerHTML = `<div class="empty-state">Erreur : ${esc(e.message)}</div>`;
    }
  }

  function _secBadge(v, c) {
    return v ? `<span class="badge" style="background:${c||'var(--text-muted)'};color:#fff;font-size:9px">${esc(v)}</span>` : '-';
  }
  const CAT_ACTION_LABELS = {critique:{l:'Critique - action immediate',c:'var(--danger)'}, urgent:{l:'Urgent - patcher rapidement',c:'#e74c3c'}, recommande:{l:'Recommande - mettre a jour',c:'var(--warning)'}, surveiller:{l:'A surveiller',c:'var(--accent)'}, ok:{l:'OK - aucune action',c:'var(--success)'}};
  function renderSecAudit(data) {
    const table = document.getElementById('sec-table');
    document.getElementById('sec-count').textContent = `${data.length} logiciel(s)`;
    if (!data.length) {
      table.innerHTML = '<div class="empty-state">Aucun resultat.</div>';
      return;
    }
    const order = ['critique', 'urgent', 'recommande', 'surveiller', 'ok'];
    const grouped = {};
    data.forEach(d => {
      const cat = d.cat_action || 'ok';
      if (!grouped[cat]) grouped[cat] = [];
      grouped[cat].push(d);
    });
    let html = '';
    let first = true;
    order.forEach(cat => {
      const items = grouped[cat];
      if (!items || !items.length) return;
      const info = CAT_ACTION_LABELS[cat] || {l:cat, c:'var(--text-muted)'};
      const catBadge = cat === 'critique' ? 'badge-critique' : cat === 'urgent' ? 'badge-eleve' : cat === 'recommande' ? 'badge-warning' : cat === 'surveiller' ? 'badge-moyen' : 'badge-faible';
      html += `<table style="margin-bottom:10px"><thead><tr style="background:${info.c}22">
        <th colspan="12" style="padding:6px 12px;font-size:12px;cursor:pointer;user-select:none" onclick="toggleSecGroup(this)">
          <span style="display:flex;align-items:center;gap:8px">
            <span class="badge ${catBadge}">${items.length}</span>
            <span style="font-weight:600;color:${info.c}">${esc(info.l)}</span>
            <span style="font-size:10px;color:var(--text-muted)">clic pour masquer/afficher</span>
          </span>
        </th>
      </tr></thead><tbody class="sec-group-body">
        <tr style="background:var(--surface-alt);font-size:10px;color:var(--text-muted)">
          <th style="padding:4px 8px">Logiciel</th><th style="padding:4px 8px">Installé</th><th style="padding:4px 8px">Dernière</th><th style="padding:4px 8px">Retard</th><th style="padding:4px 8px">Postes</th><th style="padding:4px 8px">CVE</th><th style="padding:4px 8px">CVSS</th><th style="padding:4px 8px">Risque</th><th style="padding:4px 8px">CISA</th><th style="padding:4px 8px">EOL</th><th style="padding:4px 8px">Score</th><th style="padding:4px 8px">Action</th>
        </tr>`;
      items.forEach(d => {
        const riskColor = d.risque_score >= 8 ? 'var(--danger)' : d.risque_score >= 5 ? 'var(--warning)' : d.risque_score >= 2 ? 'var(--accent)' : 'var(--text-muted)';
        const delayColor = d.update_delay ? (d.update_delay.includes('versions') ? 'var(--danger)' : 'var(--warning)') : '';
        const scoreColor = (d.score_audit||0) >= 80 ? 'var(--success)' : (d.score_audit||0) >= 50 ? 'var(--warning)' : 'var(--danger)';
        html += `<tr onclick="showLogiciel('${jesc(d.nom)}')" style="cursor:pointer">
          <td style="font-weight:500;padding:4px 8px">${esc(d.nom)}<br><span style="font-size:9px;color:var(--text-muted)">${esc(d.editeur)}</span></td>
          <td style="font-size:10px;padding:4px 8px">${esc(d.version_installee) || '-'}</td>
          <td style="font-size:10px;font-weight:500;padding:4px 8px">${esc(d.derniere_version) || '-'}
            ${d.latest_version_eol ? '<br><span style="font-size:8px;color:var(--danger)">⚠ EOL</span>' : ''}
          </td>
          <td style="font-size:10px;padding:4px 8px">${_secBadge(d.update_delay, delayColor)}</td>
          <td style="text-align:center;padding:4px 8px">${d.nb_postes}</td>
          <td style="text-align:center;padding:4px 8px"><span class="badge ${d.cve_count ? 'badge-eleve' : 'badge-faible'}" style="font-size:9px">${d.cve_count}</span></td>
          <td style="text-align:center;padding:4px 8px">${d.max_cvss ? `<span class="badge ${d.max_cvss >= 9 ? 'badge-critique' : d.max_cvss >= 7 ? 'badge-eleve' : 'badge-moyen'}" style="font-size:9px">${d.max_cvss}</span>` : '-'}</td>
          <td style="text-align:center;padding:4px 8px"><span class="badge" style="background:${riskColor};color:#fff;font-size:9px">${esc(d.risque_niveau)}</span></td>
          <td style="text-align:center;padding:4px 8px">${d.cisa_kev ? '<span class="badge badge-critique" style="font-size:8px">⚠</span>' : '-'}</td>
          <td style="text-align:center;padding:4px 8px">${d.eol === 'OUI' || d.eol == '1' ? '<span class="badge badge-eol" style="font-size:9px">EOL</span>' : '-'}</td>
          <td style="text-align:center;padding:4px 8px"><span class="badge" style="background:${scoreColor};color:#fff;font-size:9px">${d.score_audit||0}</span></td>
          <td style="font-size:10px;padding:4px 8px;max-width:130px;color:${(d.recommandation||'').includes('urgemment') ? 'var(--danger)' : d.recommandation !== 'A jour' ? 'var(--warning)' : 'var(--success)'}">${esc(d.recommandation)}</td>
        </tr>`;
      });
      html += '</tbody></table>';
    });
    table.innerHTML = html;
  }

  window.toggleSecGroup = function(th) {
    const tbody = th.closest('thead').nextElementSibling;
    tbody.style.display = tbody.style.display === 'none' ? '' : 'none';
  };

  window.filterSecAudit = function() {
    const q = document.getElementById('sec-search').value.toLowerCase();
    const riskF = document.getElementById('sec-filter-risk').value;
    const cisaF = document.getElementById('sec-filter-cisa').value;
    let data = _secAuditData;
    if (q) data = data.filter(d => (d.nom||'').toLowerCase().includes(q) || (d.editeur||'').toLowerCase().includes(q));
    if (riskF) data = data.filter(d => d.risque_niveau === riskF);
    if (cisaF === 'oui') data = data.filter(d => d.cisa_kev);
    if (cisaF === 'non') data = data.filter(d => !d.cisa_kev);
    renderSecAudit(data);
  };

window.runBatchEnrich = async function() {
  const btn = document.querySelector('button[onclick="runBatchEnrich()"]');
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = '⏳ Enrichissement...';
  try {
    await api('/api/cve/batch-enrich', {method:'POST'});
    await api('/api/versions/batch', {method:'POST'});
    await loadSecurite();
  } catch(e) {
    alert('Erreur: ' + e.message);
  }
  btn.disabled = false;
  btn.textContent = orig;
};

window.loadHistorique = async function() {
  const list = document.getElementById('hist-list');
  list.innerHTML = '<div class="loading-state"><div class="spinner"></div></div>';
  try {
    const pc = document.getElementById('hist-pc').value;
    const sw = document.getElementById('hist-sw').value;
    const type = document.getElementById('hist-type').value;
    const data = await api(`/api/historique?limit=200${pc?'&nom_pc='+encodeURIComponent(pc):''}${sw?'&logiciel='+encodeURIComponent(sw):''}`);
    const filtered = type ? data.filter(d => d.type_action === type) : data;
    if (!filtered.length) { list.innerHTML = '<div class="empty-state">Aucun evenement.</div>'; return; }
    list.innerHTML = filtered.map(h => {
      const cls = `action-${h.type_action || 'scan_complete'}`;
      let detail = '';
      if (h.type_action === 'installation') detail = `v${esc(h.nouvelle_version || '?')} installe sur <strong>${esc(h.nom_pc)}</strong>`;
      else if (h.type_action === 'desinstallation') detail = `v${esc(h.ancienne_version || '?')} supprime de <strong>${esc(h.nom_pc)}</strong>`;
      else if (h.type_action === 'mise_a_jour') detail = `v${esc(h.ancienne_version)} -&gt; v${esc(h.nouvelle_version)} sur <strong>${esc(h.nom_pc)}</strong>`;
      else detail = `Scan complet : <strong>${esc(h.nom_pc)}</strong>`;
      return `<div class="history-item">
        <div class="history-date">
          <div>${esc(h.date_action) || ''}</div>
          <div style="font-size:10px;color:var(--text-muted)">${esc(h.heure_action) || ''}</div>
        </div>
        <div class="history-content">
          <span class="action-type ${cls}">${esc(h.type_action || '').replace('_',' ')}</span>
          &nbsp;${esc(h.logiciel_nom || '-') !== '-' ? `<strong>${esc(h.logiciel_nom)}</strong> &mdash; ` : ''}${detail}
        </div>
      </div>`;
    }).join('');
  } catch(e) {
    list.innerHTML = `<div class="empty-state">Erreur : ${esc(e.message)}</div>`;
  }
};

async function loadStatistiques() {
  try {
    const data = await api('/api/stats/adv');
    const colors = ['#3b82f6','#10b981','#f59e0b','#ef4444','#8b5cf6'];

    function renderStatList(containerId, items, keyLabel, keyVal, colorFn) {
      const el = document.getElementById(containerId);
      if (!items || !items.length) { el.innerHTML = '<div style="color:var(--text-muted);font-size:12px">Aucune donnee.</div>'; return; }
      const maxVal = Math.max(...items.map(i => i[keyVal] || 0), 1);
      el.innerHTML = items.map((item, idx) => {
        const pct = Math.round((item[keyVal] || 0) / maxVal * 100);
        const color = colorFn ? colorFn(item) : colors[idx % colors.length];
        return `<div class="bar-row">
          <div class="bar-lbl" title="${esc(item[keyLabel])}" style="min-width:150px">${esc((item[keyLabel]||'').substring(0,28))}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${color}"></div></div>
          <div class="bar-val">${item[keyVal] || 0}</div>
        </div>`;
      }).join('');
    }

    renderStatList('stat-top-utilises', data.top_utilises, 'nom', 'nb', null);
    renderStatList('stat-top-vuln', data.top_vulnerables, 'nom', 'score', i => {
      const s = i.score || 0;
      return s >= 8 ? '#ef4444' : s >= 5 ? '#f59e0b' : '#3b82f6';
    });
    renderStatList('stat-top-obs', data.top_obsoletes, 'nom', 'nb', () => '#f59e0b');
    renderStatList('stat-multi-ver', data.multi_versions, 'nom', 'nb_versions', null);

    const ev = data.evolution || [];
    const evEl = document.getElementById('stat-evolution');
    if (!ev.length) { evEl.innerHTML = '<div style="color:var(--text-muted);font-size:12px">Aucune donnee.</div>'; return; }
    const maxEv = Math.max(...ev.map(e => e.nb || e.cnt || 0), 1);
    evEl.innerHTML = ev.map(e => {
      const val2 = e.nb || e.cnt || 0;
      const h = Math.max(4, Math.round(val2 / maxEv * 72));
      return `<div title="${esc(e.date_scan)}: ${val2}" style="flex:1;background:var(--accent);border-radius:2px 2px 0 0;height:${h}px;min-width:6px;opacity:0.75;cursor:default"></div>`;
    }).join('');
  } catch(e) {
    console.error(e);
  }
}

function renderMachineSwRows(rows) {
  const grouped = {};
  const nonMetier = [];
  rows.forEach(l => {
    if (l.est_metier === false) {
      nonMetier.push(l);
      return;
    }
    const met = l.metier || 'Non classe';
    if (!grouped[met]) grouped[met] = [];
    grouped[met].push(l);
  });
  const metKeys = Object.keys(grouped).sort();
  let html = '';
  if (nonMetier.length) {
    html += `<tr style="background:rgba(255,152,0,0.15)"><td colspan="12" style="padding:8px 12px;font-weight:700;font-size:12px;color:#FF9800;border-bottom:2px solid #FF9800">
      <span style="display:inline-flex;align-items:center;gap:6px"><span style="font-size:16px">&#9888;</span> Logiciels non metier (${nonMetier.length}) <span style="font-weight:400;font-size:10px;color:var(--text-muted)">potentiel Shadow IT</span></span>
    </td></tr>`;
    for (const l of nonMetier) {
      const paysBadge = l.pays ? `<span class="badge badge-metier" style="background:#636E72;color:#fff;font-size:9px;padding:1px 4px">${esc(l.pays)}</span>` : '';
      html += `<tr onclick="showLogiciel('${jesc(l.nom)}')" class="dm-sw-row" style="background:rgba(255,152,0,0.06)">
        <td class="td-main"><span class="badge badge-warning" style="font-size:9px;padding:1px 5px">Non metier</span> ${esc(l.nom)}</td>
        <td class="td-sub">${esc(l.version)||'-'}</td>
        <td>${esc(l.editeur)||'-'} ${paysBadge}</td>
        <td>${badgeOrigine(l.origine)}</td>
        <td>${esc(l.install_source)||'-'}</td>
        <td>${l.provenance_autorisee ? '<span class="badge badge-provenance" style="font-size:9px;padding:1px 4px">' + esc(l.provenance_autorisee) + '</span>' : '-'}</td>
        <td style="font-size:11px;color:var(--text-muted);max-width:130px;overflow:hidden;text-overflow:ellipsis" title="${esc(l.description||'')}">${esc((l.description||'').substring(0,35)) || '-'}</td>
        <td>${badge(l.risque_niveau)}</td>
        <td>${l.eol==='OUI'||l.eol==1?'<span class="badge badge-eol">EOL</span>':'-'}</td>
        <td>${l.taille_kb?l.taille_kb+' Ko':'-'}</td>
        <td style="white-space:nowrap">
          <button class="btn btn-sm" style="font-size:10px;padding:2px 6px" onclick="event.stopPropagation();editSwNote('${jesc(l.nom)}', '${l.id}', '${jesc(l.notes||'')}')" title="${esc(l.notes||'Ajouter note')}">${l.notes ? '📝' : '➕'}</button>
          <button class="btn btn-sm" style="font-size:10px;padding:2px 6px;margin-left:2px" onclick="event.stopPropagation();showLogiciel('${jesc(l.nom)}')" title="Modifier">✏️</button>
        </td>
      </tr>`;
    }
  }
  for (const met of metKeys) {
    const sws = grouped[met];
    html += `<tr style="background:var(--surface-alt)"><td colspan="12" style="padding:8px 12px;font-weight:700;font-size:12px;color:var(--accent);cursor:pointer;border-bottom:2px solid var(--border)" onclick="const n=this.parentElement.nextElementSibling;n.style.display=n.style.display==='none'?'':'none'">
      ${badgeMetier(met)} ${sws.length} logiciel(s)
    </td></tr>`;
    for (const l of sws) {
      const paysBadge = l.pays ? `<span class="badge badge-metier" style="background:#636E72;color:#fff;font-size:9px;padding:1px 4px">${esc(l.pays)}</span>` : '';
      html += `<tr onclick="showLogiciel('${jesc(l.nom)}')" class="dm-sw-row">
        <td class="td-main">${badgeMetier(l.metier||'Non classe')} ${esc(l.nom)}</td>
        <td class="td-sub">${esc(l.version)||'-'}</td>
        <td>${esc(l.editeur)||'-'} ${paysBadge}</td>
        <td>${badgeOrigine(l.origine)}</td>
        <td>${esc(l.install_source)||'-'}</td>
        <td>${l.provenance_autorisee ? '<span class="badge badge-provenance" style="font-size:9px;padding:1px 4px">' + esc(l.provenance_autorisee) + '</span>' : '-'}</td>
        <td style="font-size:11px;color:var(--text-muted);max-width:130px;overflow:hidden;text-overflow:ellipsis" title="${esc(l.description||'')}">${esc((l.description||'').substring(0,35)) || '-'}</td>
        <td>${badge(l.risque_niveau)}</td>
        <td>${l.eol==='OUI'||l.eol==1?'<span class="badge badge-eol">EOL</span>':'-'}</td>
        <td>${l.taille_kb?l.taille_kb+' Ko':'-'}</td>
        <td style="white-space:nowrap">
          <button class="btn btn-sm" style="font-size:10px;padding:2px 6px" onclick="event.stopPropagation();editSwNote('${jesc(l.nom)}', '${l.id}', '${jesc(l.notes||'')}')" title="${esc(l.notes||'Ajouter note')}">${l.notes ? '📝' : '➕'}</button>
          <button class="btn btn-sm" style="font-size:10px;padding:2px 6px;margin-left:2px" onclick="event.stopPropagation();showLogiciel('${jesc(l.nom)}')" title="Modifier">✏️</button>
        </td>
      </tr>`;
    }
  }
  return html;
}

window.showMachineForm = async function(scanId) {
  openDrawer('machine-edit');
  const body = document.getElementById('dme-body');
  let d = {};
  if (scanId) {
    document.getElementById('dme-title').textContent = 'Modifier la machine';
    try {
      d = await api('/api/machine/' + encodeURIComponent(scanId));
    } catch(e) {
      body.innerHTML = `<div class="empty-state">Erreur chargement: ${esc(e.message)}</div>`;
      return;
    }
  } else {
    document.getElementById('dme-title').textContent = 'Ajouter une machine';
  }
  const m = d;
  body.innerHTML = `
    <div class="field-grid" style="grid-template-columns:1fr 1fr;gap:12px">
      <input type="hidden" id="mef-scan-id" value="${esc(m.scan_id||'')}">
      <div class="form-group"><label class="form-label">Nom du poste *</label><input type="text" id="mef-nom-pc" value="${esc(m.nom_pc||'')}" required></div>
      <div class="form-group"><label class="form-label">IP</label><input type="text" id="mef-ip" value="${esc(m.ip||'')}"></div>
      <div class="form-group"><label class="form-label">MAC</label><input type="text" id="mef-mac" value="${esc(m.mac||'')}"></div>
      <div class="form-group"><label class="form-label">Utilisateur</label><input type="text" id="mef-utilisateur" value="${esc(m.utilisateur||'')}"></div>
      <div class="form-group"><label class="form-label">Domaine</label><input type="text" id="mef-domaine" value="${esc(m.domaine||'')}"></div>
      <div class="form-group"><label class="form-label">OS</label><input type="text" id="mef-os-nom" value="${esc(m.os_nom||'')}"></div>
      <div class="form-group"><label class="form-label">Version OS</label><input type="text" id="mef-os-version" value="${esc(m.os_version||'')}"></div>
      <div class="form-group"><label class="form-label">Build OS</label><input type="text" id="mef-os-build" value="${esc(m.os_build||'')}"></div>
      <div class="form-group"><label class="form-label">Architecture</label><input type="text" id="mef-os-arch" value="${esc(m.os_arch||'')}"></div>
      <div class="form-group"><label class="form-label">Fabricant</label><input type="text" id="mef-fabricant" value="${esc(m.fabricant||'')}"></div>
      <div class="form-group"><label class="form-label">Modèle</label><input type="text" id="mef-modele" value="${esc(m.modele||'')}"></div>
      <div class="form-group"><label class="form-label">Type machine</label>
        <select id="mef-type-machine">
          <option value="">--</option>
          <option value="Desktop" ${m.type_machine==='Desktop'?'selected':''}>Desktop</option>
          <option value="Portable" ${m.type_machine==='Portable'?'selected':''}>Portable</option>
          <option value="Server" ${m.type_machine==='Server'?'selected':''}>Serveur</option>
          <option value="Virtual" ${m.type_machine==='Virtual'?'selected':''}>Virtuelle</option>
          <option value="Tablette" ${m.type_machine==='Tablette'?'selected':''}>Tablette</option>
        </select>
      </div>
      <div class="form-group"><label class="form-label">CPU</label><input type="text" id="mef-cpu-nom" value="${esc(m.cpu_nom||'')}"></div>
      <div class="form-group"><label class="form-label">Cœurs CPU</label><input type="number" id="mef-cpu-coeurs" value="${m.cpu_coeurs||''}" min="0"></div>
      <div class="form-group"><label class="form-label">RAM (Go)</label><input type="number" id="mef-ram-gb" value="${m.ram_gb||''}" min="0" step="0.1"></div>
      <div class="form-group"><label class="form-label">Disque total (Go)</label><input type="number" id="mef-disque-taille" value="${m.disque_taille_gb||''}" min="0" step="0.1"></div>
      <div class="form-group"><label class="form-label">Disque libre (Go)</label><input type="number" id="mef-disque-libre" value="${m.disque_libre_gb||''}" min="0" step="0.1"></div>
      <div class="form-group"><label class="form-label">% libre disque</label><input type="number" id="mef-disque-pct" value="${m.disque_pct_libre||''}" min="0" max="100" step="0.1"></div>
      <div class="form-group"><label class="form-label">Uptime (jours)</label><input type="number" id="mef-uptime" value="${m.uptime_jours||''}" min="0" step="0.01"></div>
      <div class="form-group"><label class="form-label">Département</label><input type="text" id="mef-department" value="${esc(m.department||'')}"></div>
      <div class="form-group"><label class="form-label">Localisation</label><input type="text" id="mef-location" value="${esc(m.location||'')}"></div>
      <div class="form-group"><label class="form-label">Date scan</label><input type="text" id="mef-date-scan" value="${esc(m.date_scan||'')}" placeholder="YYYY-MM-DD"></div>
      <div class="form-group"><label class="form-label">Heure scan</label><input type="text" id="mef-heure-scan" value="${esc(m.heure_scan||'')}" placeholder="HH:MM:SS"></div>
      <div class="form-group"><label class="form-label">Score sécurité</label><input type="number" id="mef-score-secu" value="${m.score_securite||0}" min="0" max="100"></div>
                <div class="form-group"><label class="form-label">Score conformité</label><input type="number" id="mef-score-conf" value="${m.score_conformite||0}" min="0" max="100"></div>
      <div class="form-group"><label class="form-label">Actif</label>
        <select id="mef-actif">
          <option value="1" ${m.actif!=0?'selected':''}>Oui</option>
          <option value="0" ${m.actif===0?'selected':''}>Non</option>
        </select>
      </div>
      <div class="form-group" style="grid-column:1/-1"><label class="form-label">Notes</label><textarea id="mef-notes" rows="3">${esc(m.notes||'')}</textarea></div>
    </div>
    <div style="margin-top:16px;display:flex;gap:8px">
      <button class="btn btn-primary" onclick="saveMachine()">Enregistrer</button>
      ${scanId ? `<button class="btn btn-danger" onclick="deleteMachine('${jesc(scanId)}')" style="margin-left:auto">Supprimer</button>` : ''}
      <button class="btn btn-secondary" onclick="closeDrawer('machine-edit')">Annuler</button>
    </div>`;
};

window.saveMachine = async function() {
  const payload = {
    scan_id: document.getElementById('mef-scan-id').value,
    nom_pc: document.getElementById('mef-nom-pc').value,
    ip: document.getElementById('mef-ip').value,
    mac: document.getElementById('mef-mac').value,
    utilisateur: document.getElementById('mef-utilisateur').value,
    domaine: document.getElementById('mef-domaine').value,
    os_nom: document.getElementById('mef-os-nom').value,
    os_version: document.getElementById('mef-os-version').value,
    os_build: document.getElementById('mef-os-build').value,
    os_arch: document.getElementById('mef-os-arch').value,
    fabricant: document.getElementById('mef-fabricant').value,
    modele: document.getElementById('mef-modele').value,
    type_machine: document.getElementById('mef-type-machine').value,
    cpu_nom: document.getElementById('mef-cpu-nom').value,
    cpu_coeurs: parseInt(document.getElementById('mef-cpu-coeurs').value) || 0,
    ram_gb: parseFloat(document.getElementById('mef-ram-gb').value) || 0,
    disque_taille_gb: parseFloat(document.getElementById('mef-disque-taille').value) || 0,
    disque_libre_gb: parseFloat(document.getElementById('mef-disque-libre').value) || 0,
    disque_pct_libre: parseFloat(document.getElementById('mef-disque-pct').value) || 0,
    uptime_jours: parseFloat(document.getElementById('mef-uptime').value) || 0,
    department: document.getElementById('mef-department').value,
    location: document.getElementById('mef-location').value,
    date_scan: document.getElementById('mef-date-scan').value,
    heure_scan: document.getElementById('mef-heure-scan').value,
    score_securite: parseInt(document.getElementById('mef-score-secu').value) || 0,
    score_conformite: parseInt(document.getElementById('mef-score-conf').value) || 0,
    actif: parseInt(document.getElementById('mef-actif').value),
    notes: document.getElementById('mef-notes').value,
  };
  if (!payload.nom_pc.trim()) {
    alert('Le nom du poste est obligatoire.');
    return;
  }
  try {
    await api('/api/machine/save', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    closeDrawer('machine-edit');
    // Reload machines tab
    const navMach = document.querySelector('.nav-item[data-tab="machines"]');
    if (navMach) delete navMach.dataset.loaded;
    loadMachines();
  } catch(e) {
    alert('Erreur: ' + e.message);
  }
};

window.deleteMachine = async function(scanId) {
  if (!confirm('Supprimer définitivement cette machine et ses logiciels associés ?')) return;
  try {
    await api('/api/machine/' + encodeURIComponent(scanId) + '/delete', { method: 'DELETE' });
    closeDrawer('machine-edit');
    const navMachD = document.querySelector('.nav-item[data-tab="machines"]');
    if (navMachD) delete navMachD.dataset.loaded;
    loadMachines();
  } catch(e) {
    alert('Erreur: ' + e.message);
  }
};

window.saveMachineNotes = async function(scanId) {
  const notes = document.getElementById('dm-notes').value;
  try {
    await api('/api/machine/' + encodeURIComponent(scanId) + '/notes', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({notes: notes})
    });
  } catch(e) {
    alert('Erreur: ' + e.message);
  }
};

window.editSwNote = function(nom, swId, currentNote) {
  const note = prompt('Note pour ' + nom + ':', currentNote || '');
  if (note === null) return;
  const scanId = currentScanId;
  api('/api/machine/' + encodeURIComponent(scanId) + '/sw/' + swId + '/notes', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({notes: note})
  }).then(() => {
    const sw = window._machineSw.find(s => s.id == swId);
    if (sw) sw.notes = note;
    document.getElementById('dm-sw-tbody').innerHTML = renderMachineSwRows(window._filteredMachineSw || window._machineSw);
  }).catch(e => alert('Erreur: ' + e.message));
};

window.filterMachineSw = function() {
  const q = (document.getElementById('dm-sw-search').value||'').toLowerCase();
  const origine = document.getElementById('dm-sw-origine').value;
  const risk = document.getElementById('dm-sw-risk').value;
  const eolF = document.getElementById('dm-sw-eol').value;
  const metierF = document.getElementById('dm-sw-metier').value;
  const data = window._machineSw || [];
  const f = data.filter(l => {
    if (q && !(l.nom||'').toLowerCase().includes(q) && !(l.editeur||'').toLowerCase().includes(q)) return false;
    if (origine && l.origine !== origine) return false;
    if (risk && l.risque_niveau !== risk) return false;
    if (eolF === 'OUI' && l.eol !== 'OUI' && l.eol != 1) return false;
    if (metierF && (l.metier||'Non classe') !== metierF) return false;
    return true;
  });
  window._filteredMachineSw = f;
  document.getElementById('dm-sw-tbody').innerHTML = renderMachineSwRows(f);
  document.getElementById('dm-sw-count').textContent = f.length < data.length ? `(${f.length} filtre(s))` : '';
};

window.showMachine = async function(scanId) {
  currentScanId = scanId;
  openDrawer('machine');
  document.querySelectorAll('#drawer-machine .inner-pane').forEach(p => p.innerHTML = '<div class="loading-state"><div class="spinner"></div></div>');
  document.getElementById('dm-title').textContent = 'Chargement...';
  document.getElementById('dm-sub').textContent = '';
  document.querySelectorAll('.inner-tab[data-drawer="machine"]').forEach((t,i) => t.classList.toggle('active', i===0));
  document.querySelectorAll('#drawer-machine .inner-pane').forEach((p,i) => p.classList.toggle('active', i===0));

  try {
    const d = await api('/api/machine/' + encodeURIComponent(scanId));
    document.getElementById('dm-title').textContent = d.nom_pc || 'Inconnu';
    document.getElementById('dm-sub').textContent = `${[d.ip, d.utilisateur, d.os_nom, 'Scan: '+d.date_scan].filter(Boolean).join(' | ')}`;

    document.getElementById('dm-info').innerHTML = `
      <div class="stats-grid" style="grid-template-columns:repeat(3,1fr);margin-bottom:16px">
        <div class="stat-card success"><div class="stat-val success">${(d.logiciels||[]).length}</div><div class="stat-lbl">Logiciels</div></div>
        <div class="stat-card ${(d.score_securite||0)>=70?'success':'warning'}"><div class="stat-val">${d.score_securite||0}/100</div><div class="stat-lbl">Score Securite</div></div>
        <div class="stat-card ${(d.score_conformite||0)>=70?'success':'warning'}"><div class="stat-val">${d.score_conformite||0}/100</div><div class="stat-lbl">Conformite</div></div>
      </div>
      <div class="field-grid" id="dm-info-view">
        ${fld('Fabricant', d.fabricant)}
        ${fld('Modele', d.modele)}
        ${fld('Type machine', d.type_machine)}
        ${fld('OS', `${d.os_nom||''} ${d.os_build||''}`)}
        ${fld('Architecture', d.os_arch)}
        ${fld('CPU', d.cpu_nom, true)}
        ${fld('Coeurs CPU', d.cpu_coeurs)}
        ${fld('RAM (Go)', d.ram_gb)}
        ${fld('Disque total (Go)', d.disque_taille_gb)}
        ${fld('Disque libre (Go)', d.disque_libre_gb ? d.disque_libre_gb + ' (' + (d.disque_pct_libre||0) + '%)' : null)}
        ${fld('Domaine', d.domaine)}
        ${fld('Utilisateur', d.utilisateur)}
        ${fld('Version BIOS', d.version_bios)}
        ${fld('Uptime (jours)', d.uptime_jours)}
        ${fld('Date du scan', d.date_scan)}
        ${fld('Heure du scan', d.heure_scan)}
      </div>
      <div style="margin-top:8px" id="dm-info-edit-area"></div>
      <div style="margin-top:6px"><button class="btn btn-primary btn-sm" onclick="window.editMachineSection('info')">Modifier</button></div>
      <hr class="section-sep">
      <div style="font-size:13px;font-weight:600;margin-bottom:8px">Notes sur la machine</div>
      <div style="display:flex;gap:8px">
        <textarea id="dm-notes" rows="3" style="flex:1;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:var(--radius-sm);font-size:12px">${esc(d.notes||'')}</textarea>
        <button class="btn btn-primary" style="align-self:flex-end;font-size:12px;padding:6px 12px" onclick="saveMachineNotes('${jesc(d.scan_id)}')">Enreg.</button>
      </div>
      ${renderHotfixes(d.hotfixes)}
      ${renderDiff(d.diff)}
    `;

    const sec = d.securite || {};
    const av = sec.antivirus || {};
    const fw = sec.firewall || {};
    const bl = sec.bitlocker || {};
    document.getElementById('dm-securite').innerHTML = `
      <div class="field-grid" id="dm-securite-view">
        ${fld('Antivirus', av.nom)}
        ${fld('AV Actif', av.actif ? 'Oui' : 'Non')}
        ${fld('Protection temps reel', av.temps_reel ? 'Active' : 'Inactive')}
        ${fld('Signature AV', av.signature_version)}
        ${fld('Age signature (j)', av.signature_age_j)}
        ${fld('Pare-feu', fw.actif ? 'Actif' : 'Inactif')}
        ${fld('Profils FW', (fw.profils||[]).join(', '))}
        ${fld('BitLocker', bl.present ? 'Present' : 'Absent')}
        ${fld('Volumes chiffres', bl.volumes_chiffres != null ? bl.volumes_chiffres + ' / ' + bl.total_volumes : null)}
        ${fld('Secure Boot', sec.secure_boot != null ? (sec.secure_boot ? 'Actif' : 'Inactif') : null)}
        ${fld('Credential Guard', sec.credential_guard != null ? (sec.credential_guard ? 'Actif' : 'Inactif') : null)}
        ${fld('RDP expose', sec.rdp ? 'Oui' : 'Non')}
        ${fld('SMB actif', sec.smb ? 'Oui' : 'Non')}
      </div>
      <div id="dm-securite-edit-area" style="margin-top:8px"></div>
      <div style="margin-top:6px"><button class="btn btn-primary btn-sm" onclick="window.editMachineSection('securite')">Modifier</button></div>
      ${renderPorts(d.ports_ecoute)}
    `;

    const lgs = d.logiciels || [];
    window._machineSw = lgs;
    const metiersList = [...new Set(lgs.map(l => l.metier || 'Non classe').filter(Boolean))].sort();
    document.getElementById('dm-logiciels').innerHTML = `
      <div style="margin-bottom:8px;display:flex;gap:6px;flex-wrap:wrap;align-items:center">
        <span style="font-size:12px;color:var(--text-muted)">${lgs.length} logiciel(s)</span>
        <input id="dm-sw-search" type="text" placeholder="Filtrer par nom..." oninput="filterMachineSw()" style="flex:1;min-width:150px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:4px;font-size:12px">
        <select id="dm-sw-origine" onchange="filterMachineSw()" style="background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:4px;font-size:12px">
          <option value="">Toute origine</option>
          <option value="Windows">Windows</option>
          <option value="Intune">Intune</option>
          <option value="Utilisateur">Utilisateur</option>
        </select>
        <select id="dm-sw-risk" onchange="filterMachineSw()" style="background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:4px;font-size:12px">
          <option value="">Tout risque</option>
          <option value="Critique">Critique</option>
          <option value="Eleve">Eleve</option>
          <option value="Moyen">Moyen</option>
          <option value="Faible">Faible</option>
        </select>
        <select id="dm-sw-eol" onchange="filterMachineSw()" style="background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:4px;font-size:12px">
          <option value="">EOL: tous</option>
          <option value="OUI">EOL uniquement</option>
        </select>
        <select id="dm-sw-metier" onchange="filterMachineSw()" style="background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:4px;font-size:12px">
          <option value="">Tout metier</option>
          ${metiersList.map(m => `<option value="${esc(m)}">${esc(m)}</option>`).join('')}
        </select>
        <span id="dm-sw-count" style="font-size:11px;color:var(--text-muted)"></span>
      </div>
      <div class="table-wrap">
        <table style="font-size:12px">
          <thead><tr><th>Nom</th><th>Version</th><th>Editeur / Pays</th><th>Origine</th><th>Source</th><th>Provenance</th><th>Description</th><th>Risque</th><th>EOL</th><th>Taille</th><th>Actions</th></tr></thead>
          <tbody id="dm-sw-tbody">
            ${renderMachineSwRows(lgs)}
          </tbody>
        </table>
      </div>`;

    const net = d.reseau || {};
    const interfaces = net.interfaces || [];
    document.getElementById('dm-reseau').innerHTML = `
      <div class="field-grid" id="dm-reseau-view">
        ${fld('IP principale', net.ip)}
        ${fld('MAC', net.mac, true)}
        ${fld('Type reseau', net.type_reseau)}
        ${fld('Passerelle', net.passerelle)}
        ${fld('DNS', (net.dns||[]).join(', '))}
        ${fld('VPN actif', net.vpn != null ? (net.vpn ? 'Oui' : 'Non') : null)}
        ${fld('Proxy', net.proxy != null ? (net.proxy ? 'Oui' : 'Non') : null)}
      </div>
      <div id="dm-reseau-edit-area" style="margin-top:8px"></div>
      <div style="margin-top:6px"><button class="btn btn-primary btn-sm" onclick="window.editMachineSection('reseau')">Modifier</button></div>
      ${interfaces.length ? `<hr class="section-sep"><div style="font-size:12px;font-weight:600;margin-bottom:8px">Interfaces reseau</div>
        ${interfaces.map(i => `<div style="background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:8px 12px;margin-bottom:6px;font-size:12px">
          <strong>${esc(i.nom)}</strong> &bull; ${esc(i.mac)} &bull; ${esc(i.ip)||'-'} &bull; ${i.vitesse_mbps||0} Mb/s
        </div>`).join('')}` : ''}
    `;

    const procs = d.processus || [];
    const suspects = procs.filter(p => p.suspect);
    document.getElementById('dm-processus').innerHTML = `
      ${suspects.length ? `<div class="alert alert-danger">
        ${suspects.length} processus suspect(s) detecte(s)
      </div>` : ''}
      <div class="table-wrap">
        <table style="font-size:12px">
          <thead><tr><th>Nom</th><th>PID</th><th>RAM (Mo)</th><th>Suspect</th><th>Chemin</th></tr></thead>
          <tbody>
            ${procs.slice(0,50).map(p => `<tr class="${p.suspect?'row-danger':''}">
              <td class="td-main">${esc(p.nom)}</td>
              <td class="td-sub">${p.pid||''}</td>
              <td>${p.mem_mb||0}</td>
              <td>${p.suspect ? `<span class="badge badge-critique">Suspect</span>` : '-'}</td>
              <td class="td-mono" style="max-width:200px" title="${esc(p.chemin||'')}">${esc(p.chemin||'-')}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
      <div id="dm-processus-edit-area" style="margin-top:8px"></div>
      <div style="margin-top:6px"><button class="btn btn-primary btn-sm" onclick="window.editMachineSection('processus')">Modifier</button></div>
    `;

    const persist = d.persistance || {};
    const run = persist.run || [];
    const tasks = persist.taches_planifiees || [];
    document.getElementById('dm-persistance').innerHTML = `
      <div style="font-size:12px;margin-bottom:8px"><strong>${run.length}</strong> cles Run &bull; <strong>${tasks.length}</strong> taches planifiees</div>
      ${run.length ? `<div style="font-weight:600;font-size:12px;margin-bottom:6px">Cles Run (Autostart)</div>
        <div class="table-wrap"><table style="font-size:11.5px">
          <thead><tr><th>Nom</th><th>Provenance</th><th>Valeur</th></tr></thead>
          <tbody>${run.map(r => `<tr><td>${esc(r.nom)}</td><td>${esc(r.provenance)}</td><td class="td-mono" title="${esc(r.valeur||'')}">${esc((r.valeur||'').substring(0,50))}</td></tr>`).join('')}</tbody>
        </table></div>` : ''}
      ${tasks.length ? `<hr class="section-sep"><div style="font-weight:600;font-size:12px;margin-bottom:6px">Taches Planifiees</div>
        <div class="table-wrap"><table style="font-size:11.5px">
          <thead><tr><th>Nom</th><th>Etat</th><th>Description</th></tr></thead>
          <tbody>${tasks.map(t => `<tr><td>${esc(t.nom)}</td><td>${esc(t.etat)}</td><td class="td-sub">${esc((t.description||'').substring(0,60))}</td></tr>`).join('')}</tbody>
        </table></div>` : ''}
      <div id="dm-persistance-edit-area" style="margin-top:8px"></div>
      <div style="margin-top:6px"><button class="btn btn-primary btn-sm" onclick="window.editMachineSection('persistance')">Modifier</button></div>
    `;

    const hist = d.historique_scans || [];
    document.getElementById('dm-historique').innerHTML = `
      ${renderDiff(d.diff)}
      <hr class="section-sep">
      <div style="font-weight:600;font-size:12px;margin-bottom:10px">Historique des scans (${hist.length})</div>
      <div class="history-list">
        ${hist.map(h => `<div class="history-item">
          <div class="history-date">${esc(h.date_scan)}<br><span style="font-size:10px">${esc(h.heure_scan)||''}</span></div>
          <div class="history-content">${h.nb_logiciels||0} logiciels &bull; ${h.duree_s||0}s</div>
        </div>`).join('')}
      </div>
      <div id="dm-historique-edit-area" style="margin-top:8px"></div>
      <div style="margin-top:6px"><button class="btn btn-primary btn-sm" onclick="window.editMachineSection('historique')">Modifier</button></div>
    `;

  } catch(e) {
    document.getElementById('dm-info').innerHTML = `<div class="empty-state">Erreur : ${esc(e.message)}</div>`;
  }
};

function renderPorts(ports) {
  if (!ports || !ports.length) return '';
  const crits = ports.filter(p => p.risque === 'Critique');
  return `<hr class="section-sep">
    ${crits.length ? `<div class="alert alert-danger">${crits.length} port(s) critique(s) ouvert(s)</div>` : ''}
    <div style="font-weight:600;font-size:12px;margin-bottom:8px">Ports en ecoute (${ports.length})</div>
    <div class="table-wrap"><table style="font-size:12px">
      <thead><tr><th>Port</th><th>Risque</th><th>Description</th><th>Processus</th></tr></thead>
      <tbody>${ports.map(p => `<tr class="${p.risque==='Critique'?'row-danger':p.risque==='Eleve'?'row-warning':''}">
        <td><strong>${p.port}</strong></td>
        <td>${badge(p.risque==='Information'?'Faible':p.risque)}</td>
        <td>${esc(p.description)||'-'}</td>
        <td class="td-mono">${esc(p.processus)||'-'}</td>
      </tr>`).join('')}</tbody>
    </table></div>`;
}

function renderDiff(diff) {
  if (!diff) return '';
  const { added=[], removed=[], changed=[] } = diff;
  if (!added.length && !removed.length && !changed.length) return '';
  return `<hr class="section-sep">
    <div style="font-weight:600;font-size:12px;margin-bottom:10px">Changements depuis le dernier scan</div>
    ${added.length ? `<div style="margin-bottom:8px">${added.map(a => `<div style="font-size:12px;padding:4px 0;color:var(--success)">+ ${esc(a.nom)} (v${esc(a.version)})</div>`).join('')}</div>` : ''}
    ${removed.length ? `<div style="margin-bottom:8px">${removed.map(r => `<div style="font-size:12px;padding:4px 0;color:var(--danger)">- ${esc(r.nom)} (v${esc(r.version)})</div>`).join('')}</div>` : ''}
    ${changed.length ? `<div>${changed.map(c => `<div style="font-size:12px;padding:4px 0;color:var(--accent)">~ ${esc(c.nom)}: v${esc(c.ancienne)} -&gt; v${esc(c.nouvelle)}</div>`).join('')}</div>` : ''}`;
}

function renderHotfixes(hf) {
  if (!hf || !hf.length) return '';
  return `<hr class="section-sep">
    <div style="font-weight:600;font-size:12px;margin-bottom:8px">Mises a jour Windows (${hf.length})</div>
    <div class="table-wrap"><table style="font-size:12px">
      <thead><tr><th>KB</th><th>Date</th></tr></thead>
      <tbody>${hf.slice(0,20).map(h => `<tr><td class="td-mono">${esc(h.kb)}</td><td>${esc(h.date)}</td></tr>`).join('')}</tbody>
    </table></div>`;
}

function fld(label, value, mono=false) {
  const isEmpty = value === null || value === undefined || value === '';
  return `<div class="field-item">
    <div class="field-label">${esc(label)}</div>
    <div class="field-value ${mono?'mono':''} ${isEmpty?'empty':''}">${isEmpty ? 'N/A' : esc(String(value))}</div>
  </div>`;
}

function fldHtml(label, html) {
  return `<div class="field-item">
    <div class="field-label">${esc(label)}</div>
    <div class="field-value">${html || '<span class="empty">N/A</span>'}</div>
  </div>`;
}

function ageText(dateStr) {
  if (!dateStr) return null;
  const d = new Date(dateStr);
  if (isNaN(d)) return null;
  const now = new Date();
  const months = (now.getFullYear() - d.getFullYear()) * 12 + (now.getMonth() - d.getMonth());
  const years = Math.floor(months / 12);
  const remMonths = months % 12;
  if (years >= 1) return `${years}a ${remMonths}m`;
  return `${months}m`;
}

function versionStatusBadge(currentVer, latestVer) {
  if (!latestVer) return '<span class="badge badge-inconnu">Inconnue</span>';
  if (currentVer === latestVer) return '<span class="badge badge-ok">A jour</span>';
  return '<span class="badge badge-warning">En retard</span>';
}

window.showLogiciel = async function(nom) {
  currentSwNom = nom;
  openDrawer('sw');
  document.querySelectorAll('#drawer-sw .inner-pane').forEach(p => p.innerHTML = '<div class="loading-state"><div class="spinner"></div></div>');
  document.getElementById('dsw-title').textContent = nom;
  document.getElementById('dsw-sub').textContent = 'Chargement...';
  document.querySelectorAll('.inner-tab[data-drawer="sw"]').forEach((t,i) => t.classList.toggle('active', i===0));
  document.querySelectorAll('#drawer-sw .inner-pane').forEach((p,i) => p.classList.toggle('active', i===0));

  const enrichBtn = document.getElementById('btn-enrich-cve');
  enrichBtn.innerHTML = 'Enrichir CVE <span style="font-size:10px;opacity:0.7">(NVD+CISA+MSRC)</span>';
  enrichBtn.onclick = async () => {
    enrichBtn.textContent = '...';
    enrichBtn.disabled = true;
    try {
      const r = await api('/api/cve/multi-enrich/' + encodeURIComponent(nom), {method:'POST'});
      enrichBtn.innerHTML = 'Enrichir CVE <span style="font-size:10px;opacity:0.7">(NVD+CISA+MSRC)</span>';
      enrichBtn.disabled = false;
      if (r.cve_count > 0) { showLogiciel(nom); }
      else alert('Aucune CVE trouvee sur aucune source.');
    } catch(e) {
      enrichBtn.innerHTML = 'Enrichir CVE <span style="font-size:10px;opacity:0.7">(NVD+CISA+MSRC)</span>';
      enrichBtn.disabled = false;
      alert('Erreur enrichment : ' + e.message);
    }
  };

  try {
    const d = await api('/api/logiciel/' + encodeURIComponent(nom));
    window._currentSwData = d;
    const cat = d.catalogue || {};
    const st = d.stats || {};
    const cves = d.cves || [];
    const installations = d.installations || [];
    const inst0 = installations[0] || {};

    const edInfo = d.editeur_info || {};
    const paysFlag = edInfo.pays ? ` <span class="badge badge-info" style="font-size:11px;padding:2px 6px">${esc(edInfo.pays)}</span>` : '';
    const metBadge = d.metier ? ' ' + badgeMetier(d.metier) : '';
    document.getElementById('dsw-sub').innerHTML = `${metBadge} ${esc(inst0.editeur || '-')}${paysFlag} | ${st.nb_postes||0} poste(s) | ${cves.length} CVE(s)`;

    const lic = d.licence || {};
    const licAuto = d.licence_auto || {};
    const autoCat = licAuto.type_licence;
    const hasManual = !!(d.licence && d.licence.id != null);
    const licCat = lic.type_licence || autoCat || null;
    const licSous = lic.sous_type_licence || licAuto.sous_type_licence || null;
    const licInstallType = inst0.type_logiciel || inst0.categorie || null;

    const govAuto = d.gouvernance_auto || {};

    function autoLabel(key) {
      return govAuto[key] ? ' <span class="badge-autodetected">auto</span>' : '';
    }
    function orAuto(catVal, key) {
      return catVal || govAuto[key] || null;
    }

    document.getElementById('dsw-gouvernance').innerHTML = `
      <div class="field-grid" style="grid-template-columns:1fr;gap:6px;margin-bottom:12px">
        <div class="stats-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:6px">
          <div class="stat-card accent"><div class="stat-val accent">${st.nb_postes||0}</div><div class="stat-lbl">Deploiements</div></div>
          <div class="stat-card warning"><div class="stat-val">${st.nb_versions||1}</div><div class="stat-lbl">Versions</div></div>
          <div class="stat-card ${cves.length?'danger':'success'}"><div class="stat-val ${cves.length?'danger':'success'}">${cves.length}</div><div class="stat-lbl">CVE detectees</div></div>
          <div class="stat-card info"><div class="stat-val">${hasManual?'Manuelle':'Automatique'}</div><div class="stat-lbl">Origine licence</div></div>
        </div>
        ${licCat ? `<div style="display:flex;align-items:center;gap:10px;padding:10px 12px;background:var(--surface-alt);border-radius:var(--radius-md)">
          <div>${badgeLic(licCat)}</div>
          ${licSous ? `<span style="font-size:12px;color:var(--text-muted)">Sous-type : <strong>${esc(licSous)}</strong></span>` : ''}
          ${licInstallType ? `<span style="font-size:12px;color:var(--text-muted)">Type installation : <strong>${esc(licInstallType)}</strong></span>` : ''}
          ${hasManual ? '' : '<span style="font-size:11px;color:var(--accent)">(detecte automatiquement)</span>'}
        </div>` : ''}
      </div>
      <div style="font-size:13px;font-weight:600;margin-bottom:10px">Licence</div>
      <div class="field-grid">
        ${fldHtml('Type de licence', licCat ? badgeLic(licCat) : '<span class="empty">Ajouter dans l\'onglet Licences</span>')}
        ${fld('Sous-type', licSous || 'Non renseigne')}
        ${fld('Nombre de licences', lic.nombre_licences != null ? lic.nombre_licences : 'Non renseigne')}
        ${fld('Date d\'expiration', lic.date_expiration || 'Non renseignee')}
        ${fld('Cout annuel', lic.cout_annuel ? lic.cout_annuel + ' EUR' : 'Non renseigne')}
        ${fld('Fournisseur', lic.fournisseur || 'Non renseigne')}
        ${fld('Contact', lic.contact || 'Non renseigne')}
        ${fld('Notes', lic.notes || 'Non renseigne')}
      </div>
      <hr class="section-sep">
      <div style="font-size:13px;font-weight:600;margin-bottom:10px">Classification${Object.keys(govAuto).length ? ' <span style="font-weight:400;font-size:11px;color:var(--text-muted)">(certains champs pre-remplis automatiquement)</span>' : ''}</div>
      <div class="field-grid">
        ${fld('Description', orAuto(cat.description, 'description') || inst0.description)}
        ${fldHtml('Fonction metier', (orAuto(cat.fonction_metier, 'fonction_metier') || 'N/A') + autoLabel('fonction_metier'))}
        ${fld('Service proprietaire', cat.service_concerne || 'N/A')}
        ${fld('Referent metier', cat.referent_metier || 'N/A')}
        ${fld('Referent technique', cat.referent_technique || 'N/A')}
        ${fldHtml('Contrat associe', (orAuto(cat.contrat_associe, 'contrat_associe') || 'N/A') + autoLabel('contrat_associe'))}
        ${fldHtml('Fin de support (EOL)', (orAuto(cat.fin_support, 'fin_support') || 'N/A') + autoLabel('fin_support'))}
        ${fldHtml('Criticite metier', (orAuto(cat.criticite_metier, 'criticite_metier') || 'N/A') + autoLabel('criticite_metier'))}
        ${fld('Approuve', cat.approuve == 1 ? 'Oui' : 'Non')}
        ${fldHtml('Provenance autorisee', (orAuto(cat.provenance_autorisee, 'provenance_autorisee') || 'N/A') + autoLabel('provenance_autorisee'))}
      </div>
      <div id="dsw-gov-edit-area"></div>
      <div style="margin-top:12px"><button class="btn btn-primary btn-sm" onclick="window.editGouvernance('${jesc(nom)}')">Modifier la gouvernance</button></div>
    `;

    document.getElementById('dsw-inventaire').innerHTML = `
      <div style="margin-bottom:10px;font-size:12px;color:var(--text-muted)">${installations.length} installation(s) recensee(s)</div>
      <div class="table-wrap">
        <table style="font-size:12px">
          <thead><tr><th>Machine</th><th>Version</th><th>Origine</th><th>Source</th><th>Architecture</th><th>Signature</th><th style="width:50px"></th></tr></thead>
          <tbody>
            ${installations.map(i => `<tr>
              <td class="td-main" onclick="showMachine('${jesc(i.scan_id)}')" style="cursor:pointer">${esc(i.nom_pc||'-')}</td>
              <td class="td-mono">${esc(i.version||'-')}</td>
              <td>${badgeOrigine(i.origine)}</td>
              <td>${esc(i.install_source||'-')}</td>
              <td>${esc(i.architecture||'-')}</td>
              <td>${i.signature?esc(i.signature):'-'}</td>
              <td><button class="btn btn-danger btn-sm" style="font-size:10px;padding:2px 6px" onclick="event.stopPropagation();window.deleteSwTech(${i.id})" title="Supprimer">✕</button></td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>`;

    document.getElementById('dsw-securite').innerHTML = `
      ${cves.length ? `
        <div class="alert alert-danger">${cves.length} CVE connue(s) pour ce logiciel</div>
        ${cves.map(c => {
          const srcBadge = c.source === 'CISA_KEV' ? '<span class="badge badge-critique" style="font-size:9px;margin-right:4px">CISA KEV</span>'
            : c.source === 'MSRC' ? '<span class="badge badge-warn" style="font-size:9px;margin-right:4px">MSRC</span>'
            : '<span class="badge badge-faible" style="font-size:9px;margin-right:4px">NVD</span>';
          const cvssVal = c.cvss_score != null ? c.cvss_score : c.score;
          return `<div class="cve-card ${cvssVal>=7?'':'medium'}">
            <div class="cve-header">
              <span class="cve-id">${esc(c.cve_id)}</span>
              <span style="display:flex;gap:4px;align-items:center">
                ${srcBadge}
                <span class="badge ${cvssVal>=9?'badge-critique':cvssVal>=7?'badge-eleve':'badge-moyen'}">CVSS ${cvssVal}</span>
                ${c.exploit_public || c.exploit_exists ? '<span class="badge badge-critique" style="font-size:9px">EXPLOIT</span>' : ''}
              </span>
            </div>
            <div class="cve-desc">${esc(c.description||'Pas de description disponible.')}</div>
            <div style="display:flex;gap:8px;margin-top:6px;font-size:11px;color:var(--text-muted)">
              ${c.cwe ? `<span>CWE: ${esc(c.cwe)}</span>` : ''}
              ${c.date_publiee ? `<span>Publiee: ${esc(c.date_publiee.slice(0,10))}</span>` : ''}
            </div>
            ${c.remediation ? `<div style="margin-top:6px;padding:6px 8px;background:var(--surface-alt);border-radius:4px;font-size:11px;border-left:3px solid var(--accent)"><strong>Remediation:</strong> ${esc(c.remediation)}</div>` : ''}
          </div>`;
        }).join('')}
      ` : '<div class="empty-state">Aucune CVE connue. Cliquez sur "Enrichir CVE" pour interroger NVD + CISA KEV + MSRC.</div>'}
    `;

    const swEditFields = [
      {label:'Editeur', key:'editeur', type:'text', val:inst0.editeur},
      {label:'Version detectee', key:'version', type:'text', val:inst0.version},
      {label:'Architecture', key:'architecture', type:'text', val:inst0.architecture},
      {label:'Categorie', key:'categorie', type:'text', val:inst0.categorie},
      {label:'Type', key:'type_logiciel', type:'text', val:inst0.type_logiciel},
      {label:'Signature numerique', key:'signature', type:'text', val:inst0.signature},
      {label:'Certificat editeur', key:'cert_editeur', type:'text', val:inst0.cert_editeur},
      {label:'Hash SHA256', key:'hash_sha256', type:'text', val:inst0.hash_sha256},
      {label:'Chemin installation', key:'chemin', type:'text', val:inst0.chemin},
      {label:'Installation source', key:'install_source', type:'text', val:inst0.install_source},
      {label:'Build', key:'build', type:'text', val:inst0.build},
      {label:'Version date', key:'version_date', type:'text', val:inst0.version_date},
      {label:'Date compilation', key:'date_compilation', type:'text', val:inst0.date_compilation},
      {label:'Derniere version', key:'derniere_version', type:'text', val:inst0.derniere_version},
      {label:'Derniere execution', key:'derniere_execution', type:'text', val:inst0.derniere_execution},
      {label:'Portable', key:'portable', type:'select', val:inst0.portable, opts:[{v:'1',l:'Oui'},{v:'0',l:'Non'}]},
    ];
    document.getElementById('dsw-technique').innerHTML = `
      <div class="field-grid" id="dsw-technique-view">
        ${fld('Editeur', inst0.editeur)}
        ${fld('Version detectee', inst0.version)}
        ${fld('Architecture', inst0.architecture)}
        ${fld('Categorie', inst0.categorie)}
        ${fld('Taille', (inst0.taille_kb && inst0.taille_kb !== 'Inconnue' && !isNaN(parseFloat(inst0.taille_kb))) ? inst0.taille_kb + ' Ko' : inst0.taille_kb || null)}
        ${inst0.derniere_version ? fldHtml('Derniere version', `${esc(inst0.derniere_version)} ${versionStatusBadge(inst0.version, inst0.derniere_version)}`) : fld('Derniere version', null)}
        ${fld('Type', inst0.type_logiciel)}
        ${fld('Signature numerique', inst0.signature)}
        ${fld('Certificat editeur', inst0.cert_editeur, true)}
        ${fld('Hash SHA256', inst0.hash_sha256, true)}
        ${fld('Chemin d\'installation', inst0.chemin, true)}
        ${fld('Date installation', inst0.date_installation)}
        ${fld('Source installation', inst0.install_source)}
        ${fld('Date version', inst0.version_date)}
        ${fldHtml('Age version', inst0.version_date ? ageText(inst0.version_date) : 'N/A')}
        ${fld('Date compilation', inst0.date_compilation)}
        ${fldHtml('Age compilation', inst0.date_compilation ? ageText(inst0.date_compilation) : 'N/A')}
        ${fld('Build', inst0.build)}
        ${fld('Derniere execution', inst0.derniere_execution)}
        ${fld('Portable', inst0.portable ? 'Oui' : 'Non')}
      </div>
      <hr class="section-sep">
      <div style="font-size:13px;font-weight:600;margin-bottom:10px">Obsolescence & EOL</div>
      <div class="field-grid">
        ${fldHtml('Statut EOL', inst0.eol === 'OUI' || inst0.eol == 1 ? '<span class="badge badge-eol">Obsolète (EOL)</span>' : inst0.eol === 'NON' || inst0.eol === '' ? '<span class="badge badge-ok">Supporté</span>' : '<span class="badge badge-inconnu">Inconnu</span>')}
        ${inst0.version_date ? fldHtml('Ancienneté version', ageText(inst0.version_date)) : ''}
        ${inst0.date_compilation ? fldHtml('Ancienneté binaire', ageText(inst0.date_compilation)) : ''}
        ${inst0.risque_auto ? fld('Risque automatique', inst0.risque_auto) : ''}
      </div>
      <div style="margin-top:12px" id="dsw-technique-edit-area"></div>
      <div style="margin-top:8px"><button class="btn btn-primary btn-sm" onclick="window.editSwTech()">Modifier</button></div>
    `;
    window.__swTechInstallId = installations.length ? installations[0].id : null;
    window.__swTechFields = swEditFields;

    // Droits du logiciel
    document.getElementById('dsw-droits').innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Chargement des droits...</span></div>';
    try {
      const droitsData = await api('/api/droits/logiciel/' + encodeURIComponent(nom));
      const machinesD = droitsData.machines || [];
      let droitHtml = `<div style="margin-bottom:10px;font-size:12px;color:var(--text-muted)">${droitsData.nb_machines} machine(s) | Analyse des droits et permissions</div>`;
      function badgeNiveauD(n) {
        const map = {'Windows Base':'badge-danger','Installé par Administrateur':'badge-warning','Installé par Utilisateur courant':'badge-user','Inconnu':'badge-inconnu'};
        return `<span class="badge ${map[n]||'badge-inconnu'}" style="font-size:10px">${esc(n)}</span>`;
      }
      for (const m of machinesD) {
        const insts = m.installations || [];
        const highestNiveau = insts.reduce((max, i) => {
          const order = {'Windows Base':3,'Installé par Administrateur':2,'Installé par Utilisateur courant':1,'Inconnu':0};
          return Math.max(max, order[i.niveau]||0);
        }, 0);
        const abusive = highestNiveau >= 3;
        droitHtml += `<div style="background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-md);margin-bottom:10px;overflow:hidden">
          <div style="display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--surface-alt);border-bottom:1px solid var(--border)">
            <strong style="font-size:12px">${esc(m.nom_pc)}</strong>
            <span style="font-size:11px;color:var(--text-muted)">${esc(m.utilisateur)} | ${esc(m.domaine)}</span>
            ${abusive ? '<span class="badge badge-critique" style="font-size:9px">Droit abusif</span>' : ''}
          </div>
          <div class="table-wrap">
            <table style="font-size:11.5px;width:100%">
              <thead><tr>
                <th style="padding:6px 10px">Version</th>
                <th style="padding:6px 10px">Niveau acces</th>
                <th style="padding:6px 10px">Type</th>
                <th style="padding:6px 10px">Source</th>
                <th style="padding:6px 10px">Architecture</th>
                <th style="padding:6px 10px">Signature</th>
                <th style="padding:6px 10px">Note</th>
              </tr></thead>
              <tbody>`;
        for (const inst of insts) {
          droitHtml += `<tr>
            <td style="padding:6px 10px">${esc(inst.version||'-')}</td>
            <td style="padding:6px 10px">${badgeNiveauD(inst.niveau)}</td>
            <td style="padding:6px 10px;font-size:10px">${esc(inst.type_logiciel||'-')}</td>
            <td style="padding:6px 10px">${esc(inst.install_source||'-')}</td>
            <td style="padding:6px 10px;font-size:10px">${esc(inst.architecture||'-')}</td>
            <td style="padding:6px 10px;font-size:10px;max-width:120px;overflow:hidden;text-overflow:ellipsis" title="${esc(inst.signature||'')}">${esc(inst.signature||'-')}</td>
            <td style="padding:6px 10px;font-size:10px;max-width:100px">${inst.notes ? '<span title="'+esc(inst.notes)+'">📝</span>' : '-'}</td>
          </tr>`;
        }
        droitHtml += `</tbody></table></div></div>`;
      }
      if (!machinesD.length) droitHtml += '<div class="empty-state">Aucune donnee de droits disponible.</div>';
      document.getElementById('dsw-droits').innerHTML = droitHtml;
    } catch(e) {
      document.getElementById('dsw-droits').innerHTML = `<div class="empty-state">Erreur chargement droits : ${esc(e.message)}</div>`;
    }

  } catch(e) {
    document.getElementById('dsw-gouvernance').innerHTML = `<div class="empty-state">Erreur : ${esc(e.message)}</div>`;
  }
};

window.saveGouvernance = async function(nom) {
  const payload = {
    description: document.getElementById('gov-desc').value,
    fonction_metier: document.getElementById('gov-func').value,
    referent_metier: document.getElementById('gov-refmet').value,
    referent_technique: document.getElementById('gov-reftech').value,
    service_concerne: document.getElementById('gov-svc').value,
    contrat_associe: document.getElementById('gov-contrat').value,
    fin_support: document.getElementById('gov-eol').value,
    criticite_metier: document.getElementById('gov-crit').value,
    approuve: parseInt(document.getElementById('gov-app').value),
    provenance_autorisee: document.getElementById('gov-prov').value,
    historique_failles: document.getElementById('gov-failles').value,
    fuites_donnees: document.getElementById('gov-fuites').value,
  };
  try {
    await api('/api/logiciel/' + encodeURIComponent(nom), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    alert('Informations sauvegardees.');
  } catch(e) {
    alert('Erreur : ' + e.message);
  }
};

window.editSwTech = function() {
  const f = window.__swTechFields || [];
  const id = window.__swTechInstallId;
  const area = document.getElementById('dsw-technique-edit-area');
  if (!area) return;
  area.innerHTML = `
    <div class="field-grid" style="grid-template-columns:1fr 1fr;gap:10px;padding:12px;background:var(--surface-alt);border-radius:var(--radius-md)">
      ${f.map(fi => {
        if (fi.type === 'select') {
          const opts = (fi.opts||[]).map(o => `<option value="${o.v}" ${String(fi.val)===o.v?'selected':''}>${esc(o.l)}</option>`).join('');
          return `<div class="form-group"><label class="form-label">${esc(fi.label)}</label><select id="swt-${fi.key}">${opts}</select></div>`;
        }
        return `<div class="form-group"><label class="form-label">${esc(fi.label)}</label><input type="text" id="swt-${fi.key}" value="${esc(fi.val||'')}"></div>`;
      }).join('')}
      <div style="grid-column:1/-1;margin-top:8px">
        <button class="btn btn-primary" onclick="window.saveSwTech()">Enregistrer</button>
        <button class="btn btn-secondary" onclick="window.cancelSwTech()">Annuler</button>
        ${id ? `<button class="btn btn-danger" style="float:right" onclick="window.deleteSwTech(${id})">Supprimer cette installation</button>` : ''}
      </div>
    </div>`;
};

window.saveSwTech = async function() {
  const id = window.__swTechInstallId;
  if (!id) { alert('Aucune installation selectionnee'); return; }
  const f = window.__swTechFields || [];
  const payload = {};
  f.forEach(fi => {
    const el = document.getElementById('swt-'+fi.key);
    if (el) payload[fi.key] = fi.type === 'select' ? parseInt(el.value) : el.value;
  });
  try {
    await api('/api/logiciel/row/' + id, {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    alert('Installation mise a jour.');
    window.cancelSwTech();
    if (window.currentSwNom) window.showLogiciel(window.currentSwNom);
  } catch(e) {
    alert('Erreur: ' + e.message);
  }
};

window.cancelSwTech = function() {
  const area = document.getElementById('dsw-technique-edit-area');
  if (area) area.innerHTML = '';
};

window.editGouvernance = function(nom) {
  const area = document.getElementById('dsw-gov-edit-area');
  if (!area) return;
  const cat = (window._currentSwData && window._currentSwData.catalogue) || {};
  const govAuto = (window._currentSwData && window._currentSwData.gouvernance_auto) || {};
  const inst0 = ((window._currentSwData && window._currentSwData.installations) || [])[0] || {};
  area.innerHTML = `
    <hr class="section-sep">
    <div style="font-size:13px;font-weight:600;margin-bottom:12px">Modifier la gouvernance</div>
    <div class="field-grid col1" style="gap:10px">
      <div class="form-group"><label class="form-label">Description fonctionnelle</label><textarea id="gov-desc" rows="2">${esc(cat.description || govAuto.description || inst0.description || '')}</textarea></div>
      <div class="form-group"><label class="form-label">Fonction metier</label><input type="text" id="gov-func" value="${esc(cat.fonction_metier || govAuto.fonction_metier || '')}"></div>
      <div class="form-group"><label class="form-label">Referent metier</label><input type="text" id="gov-refmet" value="${esc(cat.referent_metier||'')}"></div>
      <div class="form-group"><label class="form-label">Referent technique</label><input type="text" id="gov-reftech" value="${esc(cat.referent_technique||'')}"></div>
      <div class="form-group"><label class="form-label">Service concerne</label><input type="text" id="gov-svc" value="${esc(cat.service_concerne||'')}"></div>
      <div class="form-group"><label class="form-label">Contrat associe</label><input type="text" id="gov-contrat" value="${esc(cat.contrat_associe || govAuto.contrat_associe || '')}"></div>
      <div class="form-group"><label class="form-label">Fin de support</label><input type="date" id="gov-eol" value="${esc(cat.fin_support || govAuto.fin_support || '')}"></div>
      <div class="form-group"><label class="form-label">Criticite metier</label>
        <select id="gov-crit">
          <option value="">--</option>
          <option ${(cat.criticite_metier || govAuto.criticite_metier)==='Critique'?'selected':''} value="Critique">Critique</option>
          <option ${(cat.criticite_metier || govAuto.criticite_metier)==='Haute'?'selected':''} value="Haute">Haute</option>
          <option ${(cat.criticite_metier || govAuto.criticite_metier)==='Moyen'?'selected':''} value="Moyen">Moyen</option>
          <option ${(cat.criticite_metier || govAuto.criticite_metier)==='Faible'?'selected':''} value="Faible">Faible</option>
        </select>
      </div>
      <div class="form-group"><label class="form-label">Approbation securite</label>
        <select id="gov-app">
          <option value="0" ${cat.approuve!=1?'selected':''}>Non approuve</option>
          <option value="1" ${cat.approuve==1?'selected':''}>Approuve</option>
        </select>
      </div>
      <div class="form-group"><label class="form-label">Provenance autorisee</label><input type="text" id="gov-prov" value="${esc(cat.provenance_autorisee||'')}"></div>
      <div class="form-group"><label class="form-label">Historique failles internes</label><textarea id="gov-failles" rows="2">${esc(cat.historique_failles||'')}</textarea></div>
      <div class="form-group"><label class="form-label">Fuites de donnees</label><textarea id="gov-fuites" rows="2">${esc(cat.fuites_donnees||'')}</textarea></div>
    </div>
    <div style="margin-top:14px;display:flex;gap:8px">
      <button class="btn btn-primary" onclick="saveGouvernance('${jesc(nom)}')">Enregistrer</button>
      <button class="btn btn-secondary" onclick="window.cancelGouvernance()">Annuler</button>
    </div>`;
};

window.cancelGouvernance = function() {
  const area = document.getElementById('dsw-gov-edit-area');
  if (area) area.innerHTML = '';
};

window.deleteConformiteRule = async function(ruleId) {
  if (!confirm('Supprimer definitivement cette regle de conformite ?')) return;
  try {
    await api('/api/conformite/rule/' + ruleId, { method: 'DELETE' });
    loadConformite();
  } catch(e) {
    alert('Erreur: ' + e.message);
  }
};

window.deleteSwTech = async function(id) {
  if (!confirm('Supprimer definitivement cette installation ?')) return;
  try {
    await api('/api/logiciel/row/' + id, { method: 'DELETE' });
    alert('Installation supprimee.');
    if (window.currentSwNom) window.showLogiciel(window.currentSwNom);
  } catch(e) {
    alert('Erreur: ' + e.message);
  }
};

window.toggleExport = function(prefix) {
  const menu = document.getElementById('export-menu-' + prefix);
  if (!menu) return;
  const visible = menu.classList.contains('visible');
  document.querySelectorAll('.export-menu').forEach(m => m.classList.remove('visible'));
  if (!visible) menu.classList.add('visible');
};

document.addEventListener('click', function(e) {
  if (!e.target.closest('.export-dropdown')) {
    document.querySelectorAll('.export-menu').forEach(m => m.classList.remove('visible'));
  }
});

window.exportData = function(type, format) {
  const url = `/api/export/${type}.${format}`;
  const a = document.createElement('a');
  a.href = url;
  a.download = '';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  document.querySelectorAll('.export-menu').forEach(m => m.classList.remove('visible'));
};

const MACHINE_SECTION_FIELDS = {
  info: [
    {label:'Fabricant', key:'fabricant', val:''}, {label:'Modele', key:'modele', val:''},
    {label:'Type machine', key:'type_machine', val:''}, {label:'OS', key:'os_nom', val:''},
    {label:'Architecture', key:'os_arch', val:''}, {label:'CPU', key:'cpu_nom', val:''},
    {label:'Coeurs CPU', key:'cpu_coeurs', val:''}, {label:'RAM (Go)', key:'ram_gb', val:''},
    {label:'Disque total (Go)', key:'disque_taille_gb', val:''},
    {label:'Disque libre (Go)', key:'disque_libre_gb', val:''},
    {label:'Domaine', key:'domaine', val:''}, {label:'Utilisateur', key:'utilisateur', val:''},
    {label:'Version BIOS', key:'version_bios', val:''},
    {label:'Uptime (jours)', key:'uptime_jours', val:''},
  ],
  processus: [
    {label:'Notes analyse processus', key:'notes', val:'', multiline:true},
  ],
  persistance: [
    {label:'Notes analyse persistance', key:'notes', val:'', multiline:true},
  ],
  historique: [
    {label:'Notes analyse historique', key:'notes', val:'', multiline:true},
  ],
  securite: [
    {label:'Antivirus', key:'antivirus_nom', val:''},
    {label:'AV Actif', key:'antivirus_actif', type:'select', val:'', opts:[{v:'true',l:'Oui'},{v:'false',l:'Non'}]},
    {label:'Protection temps reel', key:'antivirus_temps_reel', type:'select', val:'', opts:[{v:'true',l:'Active'},{v:'false',l:'Inactive'}]},
    {label:'Pare-feu', key:'firewall_actif', type:'select', val:'', opts:[{v:'true',l:'Actif'},{v:'false',l:'Inactif'}]},
    {label:'BitLocker', key:'bitlocker_present', type:'select', val:'', opts:[{v:'true',l:'Present'},{v:'false',l:'Absent'}]},
    {label:'Secure Boot', key:'secure_boot', type:'select', val:'', opts:[{v:'true',l:'Actif'},{v:'false',l:'Inactif'}]},
    {label:'RDP expose', key:'rdp', type:'select', val:'', opts:[{v:'true',l:'Oui'},{v:'false',l:'Non'}]},
    {label:'SMB actif', key:'smb', type:'select', val:'', opts:[{v:'true',l:'Oui'},{v:'false',l:'Non'}]},
  ],
  reseau: [
    {label:'IP principale', key:'ip', val:''}, {label:'MAC', key:'mac', val:''},
    {label:'Type reseau', key:'type_reseau', val:''}, {label:'Passerelle', key:'passerelle', val:''},
    {label:'DNS', key:'dns', val:''},
    {label:'VPN actif', key:'vpn', type:'select', val:'', opts:[{v:'true',l:'Oui'},{v:'false',l:'Non'}]},
    {label:'Proxy', key:'proxy', type:'select', val:'', opts:[{v:'true',l:'Oui'},{v:'false',l:'Non'}]},
  ],
};

function getMachineSectionValues(section) {
  const view = document.getElementById('dm-' + section + '-view');
  if (!view) return {};
  const labels = view.querySelectorAll('.field-label');
  const values = view.querySelectorAll('.field-value');
  const result = {};
  labels.forEach((lbl, i) => {
    const key = (lbl.textContent||'').trim().toLowerCase().replace(/[\s\/]/g,'_').replace(/[^a-z0-9_]/g,'');
    const val = values[i] ? values[i].textContent.replace(/^(N\/A|Non renseigne|Inconnu|-) ?/,'').trim() : '';
    result[key] = val;
  });
  return result;
}

function setMachineSectionValues(section, values) {
  const view = document.getElementById('dm-' + section + '-view');
  if (!view) return;
  const labels = view.querySelectorAll('.field-label');
  const vals = view.querySelectorAll('.field-value');
  labels.forEach((lbl, i) => {
    const key = (lbl.textContent||'').trim().toLowerCase().replace(/[\s\/]/g,'_').replace(/[^a-z0-9_]/g,'');
    if (values[key] !== undefined) {
      const v = values[key];
      vals[i].textContent = v || 'N/A';
      vals[i].className = 'field-value' + (v ? '' : ' empty');
    }
  });
}

window.editMachineSection = function(section) {
  const area = document.getElementById('dm-' + section + '-edit-area');
  if (!area) return;
  const f = MACHINE_SECTION_FIELDS[section] || [];
  const currentVals = getMachineSectionValues(section);
  const fields = f.map(fi => {
    const key = fi.label.toLowerCase().replace(/[\s\/]/g,'_').replace(/[^a-z0-9_]/g,'');
    const curVal = currentVals[key] !== undefined ? currentVals[key] : (fi.val||'');
    const labelStr = esc(fi.label);
    const inputId = 'dmes-' + section + '-' + fi.key;
    if (fi.type === 'select') {
      const curValStr = String(curVal||'').toLowerCase();
      const opts = (fi.opts||[]).map(o => `<option value="${o.v}" ${curValStr===o.v||curValStr===o.l.toLowerCase()?'selected':''}>${esc(o.l)}</option>`).join('');
      return `<div class="form-group"><label class="form-label">${labelStr}</label><select id="${inputId}">${opts}</select></div>`;
    }
    if (fi.multiline) {
      return `<div class="form-group" style="grid-column:1/-1"><label class="form-label">${labelStr}</label><textarea id="${inputId}" rows="3" style="width:100%">${esc(String(curVal||''))}</textarea></div>`;
    }
    const inputVal = typeof curVal === 'string' ? curVal.replace(/^(Go|Mb\/s) /,'') : curVal;
    return `<div class="form-group"><label class="form-label">${labelStr}</label><input type="text" id="${inputId}" value="${esc(String(inputVal))}"></div>`;
  }).join('');
  area.innerHTML = `
    <div class="field-grid" style="grid-template-columns:1fr 1fr;gap:10px;padding:12px;background:var(--surface-alt);border-radius:var(--radius-md)">
      ${fields}
      <div style="grid-column:1/-1;margin-top:8px">
        <button class="btn btn-primary" onclick="window.saveMachineSection('${section}')">Enregistrer</button>
        <button class="btn btn-secondary" onclick="window.cancelMachineSection('${section}')">Annuler</button>
      </div>
    </div>`;
};

window.saveMachineSection = async function(section) {
  const f = MACHINE_SECTION_FIELDS[section] || [];
  const values = {};
  f.forEach(fi => {
    const el = document.getElementById('dmes-' + section + '-' + fi.key);
    if (el) values[fi.key] = fi.type === 'select' ? (el.value === 'true') : el.value;
  });
  try {
    await api('/api/machine/' + encodeURIComponent(currentScanId) + '/meta', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({section: section, values: values})
    });
    window.cancelMachineSection(section);
    if (currentScanId) window.showMachine(currentScanId);
  } catch(e) {
    alert('Erreur: ' + e.message);
  }
};

window.cancelMachineSection = function(section) {
  const area = document.getElementById('dm-' + section + '-edit-area');
  if (area) area.innerHTML = '';
};

function openDrawer(type) {
  document.getElementById('overlay-' + type).classList.add('active');
  document.getElementById('drawer-' + type).classList.add('open');
}

window.closeDrawer = function(type) {
  document.getElementById('overlay-' + type).classList.remove('active');
  document.getElementById('drawer-' + type).classList.remove('open');
};

window.triggerNewScan = function() {
  const cmd = `$env:SRV='${window.location.origin}'; iex (irm ($env:SRV+'/collect.ps1'))`;
  const div = document.createElement('div');
  div.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:300;display:flex;align-items:center;justify-content:center;';
  div.innerHTML = `<div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:28px;max-width:580px;width:90%;box-shadow:var(--shadow-lg)">
    <div style="font-size:15px;font-weight:700;margin-bottom:12px">Lancer une collecte</div>
    <div style="font-size:12px;color:var(--text-muted);margin-bottom:14px">Executer cette commande en PowerShell Administrateur sur le poste cible :</div>
    <div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);padding:12px;font-family:Consolas,monospace;font-size:12px;word-break:break-all;color:var(--success);user-select:all">${esc(cmd)}</div>
    <div style="margin-top:16px;text-align:right"><button class="btn btn-secondary" onclick="this.closest('div[style]').remove()">Fermer</button></div>
  </div>`;
  document.body.appendChild(div);
};

window.triggerImportJson = function() {
  const existing = document.getElementById('modal-import-json');
  if (existing) existing.remove();
  const div = document.createElement('div');
  div.id = 'modal-import-json';
  div.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:300;display:flex;align-items:center;justify-content:center;';
  div.innerHTML = `<div style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);padding:28px;max-width:560px;width:90%;box-shadow:var(--shadow-lg)">
    <div style="font-size:15px;font-weight:700;margin-bottom:4px">Importer un fichier JSON</div>
    <div style="font-size:12px;color:var(--text-muted);margin-bottom:16px">Importez le résultat d'une collecte agent (fichiers <code>inventaire_*.json</code>)</div>
    <div id="import-dropzone" style="border:2px dashed var(--border);border-radius:var(--radius);padding:36px 16px;text-align:center;cursor:pointer;transition:all .2s">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="opacity:.5;margin-bottom:8px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
      <div style="font-size:13px;color:var(--text);margin-bottom:4px">Glissez vos fichiers JSON ici</div>
      <div style="font-size:11px;color:var(--text-muted)">ou cliquez pour parcourir</div>
    </div>
    <input type="file" id="import-file-input" accept=".json" multiple style="display:none">
    <div id="import-status" style="display:none;text-align:center;padding:14px;color:var(--text-muted);font-size:12px">
      <span class="spinner" style="display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;margin-right:6px;vertical-align:middle"></span> Import en cours...
    </div>
    <div id="import-results" style="display:none;background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:12px;margin-top:12px;font-size:12px;max-height:200px;overflow-y:auto"></div>
    <div style="margin-top:16px;text-align:right">
      <button class="btn btn-secondary" onclick="document.getElementById('modal-import-json').remove()">Fermer</button>
    </div>
  </div>`;
  document.body.appendChild(div);

  const dropzone = document.getElementById('import-dropzone');
  const fileInput = document.getElementById('import-file-input');
  const statusEl = document.getElementById('import-status');
  const resultsEl = document.getElementById('import-results');

  dropzone.addEventListener('click', () => fileInput.click());
  ['dragenter','dragover'].forEach(evt => {
    dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.style.borderColor='var(--accent)'; dropzone.style.background='rgba(79,140,255,.06)'; });
  });
  ['dragleave','drop'].forEach(evt => {
    dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.style.borderColor='var(--border)'; dropzone.style.background=''; });
  });
  dropzone.addEventListener('drop', e => {
    if (e.dataTransfer.files.length) doImportFiles(e.dataTransfer.files);
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) doImportFiles(fileInput.files);
  });

  function doImportFiles(files) {
    const fd = new FormData();
    for (let i = 0; i < files.length; i++) fd.append('file', files[i]);
    statusEl.style.display = 'block';
    resultsEl.style.display = 'none';
    resultsEl.innerHTML = '';
    fetch('/api/import-json', { method: 'POST', body: fd })
      .then(r => r.json().then(data => ({ ok: r.ok, status: r.status, data })))
      .then(({ ok, status, data }) => {
        statusEl.style.display = 'none';
        let html = '';
        if (!ok || data.error) {
          html += '<div style="color:#f87171;font-weight:600;margin-bottom:6px">Erreur ' + status + ' : ' + esc(data.error || 'R\u00e9ponse invalide') + '</div>';
        } else {
          if (data.imported > 0) {
            html += '<div style="color:var(--success);font-weight:600;margin-bottom:6px">' + data.imported + ' fichier(s) import\u00e9(s)</div>';
            for (let i = 0; i < data.results.length; i++) {
              const r = data.results[i];
              html += '<div style="display:flex;align-items:center;gap:6px;padding:3px 0;border-bottom:1px solid var(--border)"><span style="color:var(--success);font-weight:700">\u2713</span> ' +
                esc(r.machine || r.file) + ' <span style="color:var(--text-muted)">(' + r.logiciels + ' logiciels)</span></div>';
            }
          }
          if (data.errors > 0) {
            html += '<div style="color:#f87171;font-weight:600;margin-bottom:6px">' + data.errors + ' erreur(s)</div>';
            for (let i = 0; i < data.error_details.length; i++) {
              const e = data.error_details[i];
              html += '<div style="display:flex;align-items:center;gap:6px;padding:3px 0;border-bottom:1px solid var(--border)"><span style="color:#f87171;font-weight:700">\u2717</span> ' +
                esc(e.file) + ' <span style="color:var(--text-muted)">' + esc(e.error) + '</span></div>';
            }
          }
          if (data.imported === 0 && data.errors === 0) {
            html = '<div style="color:var(--text-muted)">Aucun fichier trait\u00e9</div>';
          }
        }
        resultsEl.innerHTML = html;
        resultsEl.style.display = 'block';
        fileInput.value = '';
        if (data && data.imported > 0) {
          setTimeout(() => loadDashboard(), 500);
        }
      })
      .catch(err => {
        statusEl.style.display = 'none';
        resultsEl.innerHTML = '<div style="color:#f87171">Erreur r\u00e9seau : ' + esc(err.message) + '</div>';
        resultsEl.style.display = 'block';
      });
  }
};
window._expandedDroits = {};

window.loadDroits = async function() {
  const table = document.getElementById('droits-table');
  table.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Chargement...</span></div>';
  try {
    const data = await api('/api/droits');
    window._droitsData = data;
    window._expandedDroits = {};
    window.filterDroits();
  } catch(e) {
    table.innerHTML = `<div class="empty-state">Erreur : ${esc(e.message)}</div>`;
  }
};

function toggleDroitDetail(nomPc) {
  window._expandedDroits[nomPc] = !window._expandedDroits[nomPc];
  window.filterDroits();
}

window.filterDroits = function() {
  const data = window._droitsData || [];
  const q = document.getElementById('droits-search').value.toLowerCase();
  const domaine = document.getElementById('droits-domaine').value;
  const actif = document.getElementById('droits-actif').value;
  const metierF = document.getElementById('droits-metier').value;
  const niveauF = document.getElementById('droits-niveau').value;
  const f = data.filter(d => {
    if (q && !((d.nom_pc||'').toLowerCase().includes(q) || (d.utilisateur||'').toLowerCase().includes(q))) return false;
    if (domaine === 'WORKGROUP' && d.domaine !== 'WORKGROUP' && (d.domaine||'') !== '') return false;
    if (domaine === 'DOMAINE' && (!d.domaine || d.domaine === 'WORKGROUP')) return false;
    if (actif !== '' && d.actif != actif) return false;
    if (metierF && (!d.metier_summary || !d.metier_summary[metierF])) return false;
    if (niveauF) {
      const hasNiveau = Object.values(d.metiers || {}).some(sws => sws.some(s => s.niveau === niveauF));
      if (!hasNiveau) return false;
    }
    return true;
  });
  document.getElementById('droits-count').textContent = `${f.length} machine(s)`;
  if (!f.length) {
    document.getElementById('droits-table').innerHTML = '<div class="empty-state">Aucune machine trouvee.</div>';
    return;
  }
  let html = '<div class="droit-cards">';
  for (const d of f) {
    const swTip = (d.top_privilegies || []).map(s => `${esc(s.nom)} (${esc(s.editeur||'-')})`).join('<br>');
    const expanded = window._expandedDroits[d.nom_pc];
    const metierKeys = Object.keys(d.metiers || {}).sort();
    const metierBadges = metierKeys.map(m => {
      const cnt = d.metier_summary[m] || 0;
      return `<span class="badge badge-info" style="font-size:10px;cursor:pointer" title="${esc(m)}: ${cnt} logiciel(s)">${esc(m)} (${cnt})</span>`;
    }).join(' ');
    html += `<div class="droit-card" style="background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-lg);margin-bottom:12px;overflow:hidden">
      <div class="droit-card-header" onclick="toggleDroitDetail('${jesc(d.nom_pc)}')" style="display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;border-bottom:${expanded?'1px solid var(--border)':'none'}">
        <span style="flex-shrink:0;transition:transform .2s;transform:${expanded?'rotate(90deg)':'rotate(0deg)'}">&#9654;</span>
        <div style="flex:1;min-width:0">
          <div style="font-weight:600">${esc(d.nom_pc)}</div>
          <div style="font-size:11px;color:var(--text-muted)">
            ${esc(d.utilisateur||'-')} | ${esc(d.domaine||'-')} | ${esc(d.ip||'-')} | ${esc(d.os||'-')}
          </div>
        </div>
        <div style="text-align:right;flex-shrink:0">
          <div style="font-size:12px"><strong>${d.nb_logiciels||0}</strong> logiciels</div>
          <div style="font-size:10px;color:var(--text-muted)">
            ${d.nb_systeme||0} systeme ${d.nb_services?'(+'+d.nb_services+' svc)':''} | ${d.nb_startup||0} startup | ${d.nb_portables||0} portable
          </div>
        </div>
        <div style="text-align:right;flex-shrink:0;max-width:200px">
          ${metierBadges}
        </div>
        <div>${d.actif == 1 ? '<span class="badge badge-success">Actif</span>' : '<span class="badge badge-eol">Inactif</span>'}</div>
      </div>`;
    if (d.droits_abusifs) {
      html += `<div style="padding:8px 16px;background:rgba(239,68,68,0.1);border-bottom:1px solid var(--border)">
        <span class="badge badge-critique" style="font-size:10px">⚠ Droits abusifs</span>
        ${(d.alertes_droits||[]).map(a => `<div style="font-size:11px;color:var(--color-danger-text);margin-top:4px">• ${esc(a)}</div>`).join('')}
      </div>`;
    }
    if (expanded) {
      const locaux = (d.utilisateurs_locaux || []).map(u => esc(u)).join(', ') || 'Aucun';
      const admins = (d.administrateurs_locaux || []).map(u => esc(u)).join(', ') || 'Aucun';
      html += `<div style="padding:12px 16px;background:var(--surface-alt);border-bottom:1px solid var(--border)">
        <div style="font-weight:600;font-size:12px;margin-bottom:6px;color:var(--accent)">Accès & Comptes Locaux</div>
        <div style="font-size:11px;margin-bottom:4px"><strong>Administrateurs :</strong> <span style="color:var(--color-danger-text)">${admins}</span></div>
        <div style="font-size:11px"><strong>Utilisateurs standards :</strong> <span style="color:var(--text-muted)">${locaux}</span></div>
      </div>`;
      if (metierKeys.length) {
        html += `<div style="padding:0">
          <table style="width:100%;border-collapse:collapse;font-size:12px">
            <thead><tr style="background:var(--surface-alt)">
            <th style="padding:8px 12px;text-align:left;border-bottom:1px solid var(--border)">Logiciel</th>
            <th style="padding:8px 12px;text-align:left;border-bottom:1px solid var(--border)">Editeur</th>
            <th style="padding:8px 12px;text-align:left;border-bottom:1px solid var(--border)">Version</th>
            <th style="padding:8px 12px;text-align:left;border-bottom:1px solid var(--border)">Provenance</th>
            <th style="padding:8px 12px;text-align:left;border-bottom:1px solid var(--border)">Niveau</th>
            <th style="padding:8px 12px;text-align:left;border-bottom:1px solid var(--border)">Risque</th>
            <th style="padding:8px 12px;text-align:left;border-bottom:1px solid var(--border)">Chemin</th>
          </tr></thead><tbody>`;
      function badgeNiveau(n) {
        const map = {'Windows Base':'badge-danger','Installé par Administrateur':'badge-warning','Installé par Utilisateur courant':'badge-user','Inconnu':'badge-inconnu'};
        const cls = map[n] || 'badge-inconnu';
        return `<span class="badge ${cls}" style="font-size:10px">${esc(n)}</span>`;
      }
      for (const met of metierKeys) {
        const sws = d.metiers[met] || [];
        html += `<tr style="background:var(--surface-alt)"><td colspan="7" style="padding:6px 12px;font-weight:600;font-size:11px;color:var(--accent)">${esc(met)} (${sws.length})</td></tr>`;
        for (const s of sws) {
          const srcBadge = badgeSource(s.source);
          html += `<tr>
            <td style="padding:6px 12px;border-bottom:1px solid var(--border)">${esc(s.nom)}</td>
            <td style="padding:6px 12px;border-bottom:1px solid var(--border);color:var(--text-muted)">${esc(s.editeur)||'-'}</td>
            <td style="padding:6px 12px;border-bottom:1px solid var(--border);color:var(--text-muted)">${esc(s.version)||'-'}</td>
            <td style="padding:6px 12px;border-bottom:1px solid var(--border)">${srcBadge}</td>
            <td style="padding:6px 12px;border-bottom:1px solid var(--border)">${badgeNiveau(s.niveau)}</td>
            <td style="padding:6px 12px;border-bottom:1px solid var(--border)">${badge(s.risque)}</td>
            <td style="padding:6px 12px;border-bottom:1px solid var(--border);color:var(--text-muted);font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(s.chemin)||'-'}</td>
          </tr>`;
        }
      }
      html += '</tbody></table></div>';
    }
  }
  html += '</div>';
  }
  html += '</div>';
  document.getElementById('droits-table').innerHTML = html;
};

// ─── Droits Logiciels ────────────────────────────────────────────

function badgeNiveauDL(n) {
  const map = {'Windows Base':'badge-danger', 'Installé par Administrateur':'badge-warning', 'Installé par Utilisateur courant':'badge-user'};
  let icon = '';
  if (n === 'Windows Base') icon = '⚙️ ';
  else if (n === 'Installé par Administrateur') icon = '🛡️ ';
  else if (n === 'Installé par Utilisateur courant') icon = '👤 ';
  return `<span class="badge ${map[n] || 'badge-inconnu'}" style="font-size:10px">${icon}${esc(n)}</span>`;
}

window.loadDroitsLogiciels = async function() {
  const table = document.getElementById('dl-table');
  table.innerHTML = '<div class="loading-state"><div class="spinner"></div><span>Chargement...</span></div>';
  try {
    const data = await api('/api/droits/logiciels');
    window._dlData = data;
    window.filterDroitsLogiciels();
  } catch(e) {
    table.innerHTML = `<div class="empty-state">Erreur : ${esc(e.message)}</div>`;
  }
};

window.filterDroitsLogiciels = function() {
  const data = window._dlData || [];
  const q = document.getElementById('dl-search').value.toLowerCase();
  const niveauF = document.getElementById('dl-niveau').value;
  const metierF = document.getElementById('dl-metier').value;
  const f = data.filter(d => {
    if (q && !((d.nom||'').toLowerCase().includes(q) || (d.editeur||'').toLowerCase().includes(q))) return false;
    if (niveauF && d.niveau !== niveauF) return false;
    if (metierF && d.metier !== metierF) return false;
    return true;
  });
  document.getElementById('dl-count').textContent = `${f.length} logiciel(s)`;
  if (!f.length) {
    document.getElementById('dl-table').innerHTML = '<div class="empty-state">Aucun logiciel trouve.</div>';
    return;
  }
  let html = `<table style="width:100%"><thead><tr>
    <th>Logiciel</th><th>Editeur</th><th>Version</th><th>Niveau</th><th>Privilèges Exacts</th><th>Metier</th><th>Risque</th><th>Machines</th>
  </tr></thead><tbody>`;
  for (const d of f) {
    const machines = (d.machines || []).map(m => esc(m)).join(', ');
    const isMetier = d.metier && !['Systeme', 'Utilitaire', 'Non classe', ''].includes(d.metier);
    const rowClass = isMetier ? 'row-metier' : '';
    
    const privDesc = {
      'Système Windows': 'Composant système (Droits max, intégré à l\'OS)',
      'Administrateur': 'Installé par un Administrateur (Modifie HKLM/Program Files)',
      'Utilisateur': 'Installé par l\'utilisateur courant (Accès limité)'
    }[d.niveau] || 'Non déterminé';

    html += `<tr class="${rowClass}">
      <td><strong>${esc(d.nom)}</strong></td>
      <td style="color:var(--text-muted)">${esc(d.editeur)||'-'}</td>
      <td style="color:var(--text-muted);font-size:11px">${esc(d.version)||'-'}</td>
      <td>${badgeNiveauDL(d.niveau)}</td>
      <td style="font-size:11px;color:var(--text-muted)">${privDesc}</td>
      <td>${badgeMetier(d.metier)}</td>
      <td>${badge(d.risque_niveau)}</td>
      <td style="font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis" title="${machines}">${d.nb_machines} machine(s)</td>
    </tr>`;
  }
  html += '</tbody></table>';
  document.getElementById('dl-table').innerHTML = html;
};

window.enrichSouverainete = async function() {
  const btn = document.getElementById('cat-enrich-sov');
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = '⏳ En cours...';
  try {
    const r = await api('/api/enrich-souverainete', {method:'POST'});
    alert(`Enrichissement termine: ${r.enriched} editeur(s) enrichis sur ${r.total}`);
    await loadCatalogue();
  } catch(e) {
    alert('Erreur: ' + e.message);
  }
  btn.disabled = false;
  btn.textContent = orig;
};

loadDashboard();

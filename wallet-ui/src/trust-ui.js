/**
 * Trust UI Components
 *
 * UI components for displaying and interacting with blockchain trust graph
 */

import {
  TrustLevel,
  TrustLevelNames,
  scanBitcoinTrustTransactions,
  scanSolanaTrustTransactions,
  scanEthereumTrustTransactions,
  buildTrustGraph,
  calculateTrustScore,
  analyzeTrustRelationships,
} from './blockchain-trust.js';

// =============================================================================
// Helpers
// =============================================================================

export function truncatePubkey(pubkey, prefixLen = 12, suffixLen = 8) {
  if (!pubkey) return '';
  if (pubkey.length <= prefixLen + suffixLen + 3) return pubkey;
  return `${pubkey.slice(0, prefixLen)}...${pubkey.slice(-suffixLen)}`;
}

export function truncateTxHash(txHash, prefixLen = 10, suffixLen = 6) {
  if (!txHash) return '';
  if (txHash.length <= prefixLen + suffixLen + 3) return txHash;
  return `${txHash.slice(0, prefixLen)}...${txHash.slice(-suffixLen)}`;
}

function explorerTxUrl(chain, txHash) {
  switch (chain) {
    case 'btc':
      return `https://blockstream.info/tx/${txHash}`;
    case 'eth':
      return `https://etherscan.io/tx/${txHash}`;
    case 'sol':
      return `https://solscan.io/tx/${txHash}`;
    default:
      return `https://blockstream.info/tx/${txHash}`;
  }
}

const MODAL_CLOSE_BUTTON_HTML = `<button class="modal-close" type="button" aria-label="Close"><svg class="modal-close-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.25" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>`;

function chainBadge(chain) {
  const labels = { btc: 'BTC', eth: 'ETH', sol: 'SOL' };
  const label = labels[chain] || chain?.toUpperCase() || '???';
  return `<span class="chain-badge chain-${chain || 'unknown'}">${label}</span>`;
}

function trustLevelBadge(level) {
  const name = TrustLevelNames[level] || 'Unknown';
  const cls = name.toLowerCase().replace(/\s+/g, '-');
  return `<span class="trust-level-badge trust-level-${cls}">${name}</span>`;
}

function directionIndicator(direction) {
  switch (direction) {
    case 'outbound':
      return '<span class="trust-direction" title="Outbound">&rarr;</span>';
    case 'inbound':
      return '<span class="trust-direction" title="Inbound">&larr;</span>';
    case 'mutual':
      return '<span class="trust-direction" title="Mutual">&harr;</span>';
    default:
      return '<span class="trust-direction">--</span>';
  }
}

function closeModal(modal) {
  modal.classList.remove('active');
  setTimeout(() => modal.remove(), 200);
}

// =============================================================================
// 1. renderTrustList
// =============================================================================

export function renderTrustList(container, relationships, ownAddresses) {
  container.innerHTML = '';

  if (!relationships || relationships.length === 0) {
    container.innerHTML = '<div class="trust-empty">No trust relationships found.</div>';
    return;
  }

  const list = document.createElement('div');
  list.className = 'trust-list';

  for (const rel of relationships) {
    const row = document.createElement('div');
    row.className = 'trust-row';

    const ownSet = new Set(
      Array.isArray(ownAddresses)
        ? ownAddresses
        : Object.values(ownAddresses || {}).flat()
    );

    const isOutbound = ownSet.has(rel.from);
    const isInbound = ownSet.has(rel.to);
    const direction = isOutbound && isInbound ? 'mutual'
      : isOutbound ? 'outbound'
      : isInbound ? 'inbound'
      : 'outbound';

    const displayAddress = direction === 'inbound' ? rel.from : rel.to;
    const chain = rel.chain || rel.network || 'btc';

    // Header
    const header = document.createElement('div');
    header.className = 'trust-row-header';
    header.innerHTML = `
      <span class="trust-row-address" title="${displayAddress}">${truncatePubkey(displayAddress)}</span>
      ${chainBadge(chain)}
      ${trustLevelBadge(rel.level)}
      ${directionIndicator(direction)}
      <span class="trust-row-expand">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </span>
    `;

    // Detail
    const detail = document.createElement('div');
    detail.className = 'trust-row-detail';

    const txs = rel.transactions || (rel.txHash ? [rel] : []);
    const txRows = txs.map(tx => {
      const ts = tx.timestamp ? new Date(tx.timestamp).toLocaleString() : '--';
      const hash = tx.txHash || tx.hash || '';
      const txChain = tx.chain || tx.network || chain;
      const url = explorerTxUrl(txChain, hash);
      return `
        <div class="trust-tx-row">
          <span class="trust-tx-time">${ts}</span>
          <a class="trust-tx-link" href="${url}" target="_blank" rel="noopener">${truncateTxHash(hash)}</a>
        </div>
      `;
    }).join('');

    const revokeBtn = direction !== 'inbound'
      ? `<button class="glass-btn glass-btn-sm trust-revoke-btn" data-address="${displayAddress}">Revoke</button>`
      : '';

    detail.innerHTML = `
      <div class="trust-detail-address">
        <label>Full Address</label>
        <code>${displayAddress}</code>
      </div>
      <div class="trust-detail-txs">
        <label>Transactions</label>
        ${txRows || '<span class="trust-no-txs">No transactions recorded</span>'}
      </div>
      ${revokeBtn ? `<div class="trust-detail-actions">${revokeBtn}</div>` : ''}
    `;

    // Toggle expand
    header.addEventListener('click', () => {
      const wasExpanded = row.classList.contains('expanded');
      // Collapse all others
      list.querySelectorAll('.trust-row.expanded').forEach(r => r.classList.remove('expanded'));
      if (!wasExpanded) row.classList.add('expanded');
    });

    row.appendChild(header);
    row.appendChild(detail);
    list.appendChild(row);
  }

  container.appendChild(list);
}

// =============================================================================
// 2. showEstablishTrustModal
// =============================================================================

// Address format detection
function detectChainFromAddress(address) {
  if (!address) return null;
  const a = address.trim();
  // Bitcoin: starts with 1, 3, or bc1
  if (/^(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(a)) return 'btc';
  if (/^bc1[a-z0-9]{25,90}$/.test(a)) return 'btc';
  // Ethereum: 0x + 40 hex chars
  if (/^0x[0-9a-fA-F]{40}$/.test(a)) return 'eth';
  // Solana: base58, 32-44 chars, no 0/O/I/l
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a)) return 'sol';
  return null;
}

// Simple VCF parser for trust modal
function parseVCFForTrust(vcfText) {
  const lines = vcfText.replace(/\r?\n /g, '').split(/\r?\n/);
  const result = { name: null, email: null, org: null, photo: null, keys: [], addresses: [] };

  for (const line of lines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const prop = line.substring(0, colonIdx).toUpperCase();
    const value = line.substring(colonIdx + 1);

    if (prop === 'FN') {
      result.name = value;
    } else if (prop.startsWith('EMAIL')) {
      result.email = value;
    } else if (prop.startsWith('ORG')) {
      result.org = value.replace(/;/g, ', ');
    } else if (prop.startsWith('PHOTO')) {
      if (prop.includes('VALUE=URI') || value.startsWith('data:') || value.startsWith('http')) {
        result.photo = value;
      } else if (prop.includes('ENCODING=B') || prop.includes('ENCODING=b')) {
        const typeMatch = prop.match(/TYPE=(\w+)/i);
        const imgType = typeMatch ? typeMatch[1].toLowerCase() : 'jpeg';
        result.photo = `data:image/${imgType};base64,${value}`;
      }
    } else if (prop.startsWith('KEY') || prop.startsWith('X-CRYPTO') || prop.startsWith('X-KEY')) {
      result.keys.push(value);
      const chain = detectChainFromAddress(value);
      if (chain) result.addresses.push({ address: value, chain });
    }
  }

  // Also scan NOTE or other fields for addresses
  return result;
}

const TRUST_LEVEL_CONFIG = [
  { value: TrustLevel.NEVER, name: 'Never Trust', desc: 'Block this address from all interactions', color: '#ef4444', border: 'rgba(239, 68, 68, 0.4)' },
  { value: TrustLevel.UNKNOWN, name: 'Unknown', desc: 'No opinion on this address yet', color: '#9ca3af', border: 'rgba(107, 114, 128, 0.4)' },
  { value: TrustLevel.MARGINAL, name: 'Marginal', desc: 'Somewhat trusted, proceed with caution', color: '#fbbf24', border: 'rgba(245, 158, 11, 0.4)' },
  { value: TrustLevel.FULL, name: 'Full Trust', desc: 'Highly trusted, verified relationship', color: '#6ee7b7', border: 'rgba(16, 185, 129, 0.4)' },
  { value: TrustLevel.ULTIMATE, name: 'Ultimate', desc: 'Your own address or absolute trust', color: '#a78bfa', border: 'rgba(139, 92, 246, 0.4)' },
];

export function showEstablishTrustModal(onConfirm) {
  let vcfData = null;

  const modal = document.createElement('div');
  modal.className = 'modal trust-modal establish-trust-modal';

  const levelOptionsHtml = TRUST_LEVEL_CONFIG.map((lvl, i) => `
    <label class="trust-level-option" style="--level-color: ${lvl.color}; --level-border: ${lvl.border}">
      <input type="radio" name="trust-level" value="${lvl.value}" ${i === 2 ? 'checked' : ''}>
      <span class="trust-level-indicator" style="background: ${lvl.color}"></span>
      <span class="trust-level-label">
        <span class="trust-level-name">${lvl.name}</span>
        <span class="trust-level-desc">${lvl.desc}</span>
      </span>
    </label>
  `).join('');

  modal.innerHTML = `
    <div class="modal-glass">
      <div class="modal-header">
        <h3>Establish Trust</h3>
        ${MODAL_CLOSE_BUTTON_HTML}
      </div>
      <div class="modal-body">

        <div class="trust-input-section">
          <label class="trust-section-label">Recipient</label>
          <div class="trust-input-tabs">
            <button class="trust-input-tab active" data-tab="address">Paste Address</button>
            <button class="trust-input-tab" data-tab="vcf">Import vCard</button>
          </div>

          <div class="trust-tab-panel" id="trust-address-panel">
            <input type="text" id="trust-recipient" class="trust-address-input invalid" placeholder="BTC, ETH, or SOL address" autocomplete="off" spellcheck="false" />
            <div class="trust-address-status" id="trust-address-status">
              <span id="trust-address-status-text"></span>
            </div>
          </div>

          <div class="trust-tab-panel" id="trust-vcf-panel" style="display:none">
            <label class="trust-vcf-dropzone" id="trust-vcf-dropzone">
              <input type="file" id="trust-vcf-input" accept=".vcf,.vcard" style="display:none" />
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/>
              </svg>
              <span>Drop .vcf file or click to browse</span>
            </label>
            <div class="trust-vcf-summary" id="trust-vcf-summary" style="display:none"></div>
          </div>
        </div>

        <div class="trust-input-section">
          <label class="trust-section-label">Trust Level</label>
          <div class="trust-level-options">
            ${levelOptionsHtml}
          </div>
        </div>

        <div class="trust-modal-actions">
          <button class="glass-btn" id="trust-cancel">Cancel</button>
          <button class="glass-btn primary" id="trust-confirm">Publish Transaction</button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  requestAnimationFrame(() => modal.classList.add('active'));

  const closeBtn = modal.querySelector('.modal-close');
  const cancelBtn = modal.querySelector('#trust-cancel');
  const confirmBtn = modal.querySelector('#trust-confirm');
  const recipientInput = modal.querySelector('#trust-recipient');
  const addressStatus = modal.querySelector('#trust-address-status');
  const addressStatusText = modal.querySelector('#trust-address-status-text');
  const vcfInput = modal.querySelector('#trust-vcf-input');
  const vcfSummary = modal.querySelector('#trust-vcf-summary');
  const vcfDropzone = modal.querySelector('#trust-vcf-dropzone');
  const addressPanel = modal.querySelector('#trust-address-panel');
  const vcfPanel = modal.querySelector('#trust-vcf-panel');

  let detectedNetwork = null;
  const fees = { btc: '~0.0001 BTC', sol: '~0.000005 SOL', eth: '~0.001 ETH' };
  const chainNames = { btc: 'Bitcoin', eth: 'Ethereum', sol: 'Solana' };

  const close = () => closeModal(modal);
  closeBtn.addEventListener('click', close);
  cancelBtn.addEventListener('click', close);

  // Tab switching
  modal.querySelectorAll('.trust-input-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      modal.querySelectorAll('.trust-input-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const isVcf = tab.dataset.tab === 'vcf';
      addressPanel.style.display = isVcf ? 'none' : '';
      vcfPanel.style.display = isVcf ? '' : 'none';
    });
  });

  // Address auto-detect chain with validation
  recipientInput.addEventListener('input', () => {
    const val = recipientInput.value.trim();
    if (!val) {
      recipientInput.classList.add('invalid');
      recipientInput.classList.remove('valid');
      addressStatus.className = 'trust-address-status';
      addressStatusText.textContent = '';
      detectedNetwork = null;
      return;
    }
    const chain = detectChainFromAddress(val);
    if (chain) {
      detectedNetwork = chain;
      recipientInput.classList.remove('invalid');
      recipientInput.classList.add('valid');
      addressStatus.className = 'trust-address-status detected';
      addressStatusText.textContent = `${chainNames[chain]} (${fees[chain]})`;
    } else {
      detectedNetwork = null;
      recipientInput.classList.add('invalid');
      recipientInput.classList.remove('valid');
      addressStatus.className = 'trust-address-status invalid';
      addressStatusText.textContent = 'Unrecognized address format';
    }
  });

  // VCF file handling
  function handleVCFFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      vcfData = parseVCFForTrust(e.target.result);
      vcfDropzone.style.display = 'none';
      vcfSummary.style.display = 'block';

      let html = '<div class="trust-vcf-card">';
      if (vcfData.photo) {
        html += `<img class="trust-vcf-photo" src="${vcfData.photo}" alt="" />`;
      }
      html += '<div class="trust-vcf-info">';
      if (vcfData.name) html += `<div class="trust-vcf-name">${vcfData.name}</div>`;
      if (vcfData.org) html += `<div class="trust-vcf-org">${vcfData.org}</div>`;
      if (vcfData.email) html += `<div class="trust-vcf-email">${vcfData.email}</div>`;
      html += '</div></div>';

      if (vcfData.addresses.length > 0) {
        html += '<label class="trust-section-label" style="margin-top:12px">Select Address</label>';
        html += '<div class="trust-vcf-addresses">';
        vcfData.addresses.forEach((a, i) => {
          const labels = { btc: 'Bitcoin', eth: 'Ethereum', sol: 'Solana' };
          html += `
            <label class="trust-vcf-addr-option">
              <input type="radio" name="vcf-address" value="${i}" ${i === 0 ? 'checked' : ''} />
              <span class="chain-badge chain-${a.chain}">${a.chain.toUpperCase()}</span>
              <code>${truncatePubkey(a.address)}</code>
            </label>`;
        });
        html += '</div>';
      } else if (vcfData.keys.length > 0) {
        html += `<div class="trust-vcf-note">Found ${vcfData.keys.length} key(s) but no recognized blockchain addresses.</div>`;
      } else {
        html += '<div class="trust-vcf-note">No blockchain addresses found in this vCard.</div>';
      }

      html += `<button class="glass-btn glass-btn-sm trust-vcf-clear" id="trust-vcf-clear">Remove</button>`;
      vcfSummary.innerHTML = html;

      // Set detected network from first address
      if (vcfData.addresses.length > 0) {
        detectedNetwork = vcfData.addresses[0].chain;
      }

      // Handle address radio changes
      vcfSummary.querySelectorAll('input[name="vcf-address"]').forEach(radio => {
        radio.addEventListener('change', () => {
          const addr = vcfData.addresses[parseInt(radio.value, 10)];
          if (addr) detectedNetwork = addr.chain;
        });
      });

      modal.querySelector('#trust-vcf-clear')?.addEventListener('click', () => {
        vcfData = null;
        vcfSummary.style.display = 'none';
        vcfDropzone.style.display = '';
        vcfInput.value = '';
      });
    };
    reader.readAsText(file);
  }

  vcfInput.addEventListener('change', (e) => handleVCFFile(e.target.files[0]));

  vcfDropzone.addEventListener('dragover', (e) => { e.preventDefault(); vcfDropzone.classList.add('dragover'); });
  vcfDropzone.addEventListener('dragleave', () => vcfDropzone.classList.remove('dragover'));
  vcfDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    vcfDropzone.classList.remove('dragover');
    handleVCFFile(e.dataTransfer.files[0]);
  });

  // Confirm
  confirmBtn.addEventListener('click', () => {
    let recipientAddress;
    let network = detectedNetwork;
    const isVcfTab = modal.querySelector('.trust-input-tab.active')?.dataset.tab === 'vcf';

    if (isVcfTab && vcfData && vcfData.addresses.length > 0) {
      const selectedRadio = vcfSummary.querySelector('input[name="vcf-address"]:checked');
      const idx = selectedRadio ? parseInt(selectedRadio.value, 10) : 0;
      recipientAddress = vcfData.addresses[idx].address;
      network = vcfData.addresses[idx].chain;
    } else {
      recipientAddress = recipientInput.value.trim();
    }

    if (!recipientAddress || !network) {
      recipientInput.focus();
      return;
    }
    const level = parseInt(modal.querySelector('input[name="trust-level"]:checked').value, 10);

    onConfirm({ level, network, recipientAddress });
    close();
  });
}

// =============================================================================
// 3. showRevokeTrustModal
// =============================================================================

export function showRevokeTrustModal(originalTxHash, onConfirm) {
  const modal = document.createElement('div');
  modal.className = 'modal trust-modal';
  modal.innerHTML = `
    <div class="modal-glass">
      <div class="modal-header">
        <h3>Revoke Trust</h3>
        ${MODAL_CLOSE_BUTTON_HTML}
      </div>
      <div class="modal-body">
        <div class="trust-warning">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <p>This will publish a revocation transaction on-chain. The original trust relationship will be marked as revoked and will no longer contribute to trust scores.</p>
          <p><strong>This action is permanent and cannot be undone.</strong></p>
        </div>

        <div class="trust-tx-hash">
          <label>Original Transaction</label>
          <code>${truncateTxHash(originalTxHash)}</code>
        </div>

        <div class="trust-actions">
          <button class="glass-btn" id="revoke-cancel">Cancel</button>
          <button class="glass-btn danger" id="revoke-confirm">Publish Revocation</button>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(modal);
  requestAnimationFrame(() => modal.classList.add('active'));

  const closeBtn = modal.querySelector('.modal-close');
  const cancelBtn = modal.querySelector('#revoke-cancel');
  const confirmBtn = modal.querySelector('#revoke-confirm');

  const close = () => closeModal(modal);

  closeBtn.addEventListener('click', close);
  cancelBtn.addEventListener('click', close);

  confirmBtn.addEventListener('click', () => {
    onConfirm({ originalTxHash });
    close();
  });
}

// =============================================================================
// 4. showRulesModal
// =============================================================================

const RULE_CONDITION_TYPES = [
  { value: 'mutual_tx_count', label: 'Mutual Transaction Count' },
  { value: 'last_interaction_days', label: 'Days Since Last Interaction' },
  { value: 'address_blocklist', label: 'Address Blocklist' },
  { value: 'bidirectional_trust', label: 'Bidirectional Trust' },
];

const SEVERITY_OPTIONS = ['info', 'warn', 'block'];

function buildRuleRow(rule, index) {
  const conditionOptions = RULE_CONDITION_TYPES.map(ct =>
    `<option value="${ct.value}" ${rule.type === ct.value ? 'selected' : ''}>${ct.label}</option>`
  ).join('');

  const levelOptions = Object.entries(TrustLevelNames).map(([val, name]) =>
    `<option value="${val}" ${String(rule.resultLevel) === String(val) ? 'selected' : ''}>${name}</option>`
  ).join('');

  const severityOptions = SEVERITY_OPTIONS.map(s =>
    `<option value="${s}" ${rule.severity === s ? 'selected' : ''}>${s}</option>`
  ).join('');

  return `
    <div class="rule-row" data-index="${index}">
      <div class="rule-fields">
        <div class="rule-field">
          <label>Condition</label>
          <select class="glass-select rule-type">${conditionOptions}</select>
        </div>
        <div class="rule-field">
          <label>Threshold</label>
          <input type="number" class="glass-input rule-threshold" value="${rule.params?.threshold ?? 0}" min="0" />
        </div>
        <div class="rule-field">
          <label>Result Level</label>
          <select class="glass-select rule-result-level">${levelOptions}</select>
        </div>
        <div class="rule-field">
          <label>Severity</label>
          <select class="glass-select rule-severity">${severityOptions}</select>
        </div>
        <div class="rule-field rule-field-actions">
          <button class="glass-btn glass-btn-sm rule-delete-btn" data-index="${index}" title="Delete rule">&times;</button>
        </div>
      </div>
    </div>
  `;
}

export function showRulesModal(rules, onSave) {
  let currentRules = (rules || []).map((r, i) => ({
    id: r.id || `rule-${i}`,
    type: r.type || 'mutual_tx_count',
    params: { threshold: r.params?.threshold ?? 0 },
    resultLevel: r.resultLevel ?? TrustLevel.MARGINAL,
    severity: r.severity || 'info',
    description: r.description || '',
  }));

  const modal = document.createElement('div');
  modal.className = 'modal trust-modal rules-modal';

  function renderRules() {
    const rulesHtml = currentRules.map((r, i) => buildRuleRow(r, i)).join('');
    modal.innerHTML = `
      <div class="modal-glass">
        <div class="modal-header">
          <h3>Trust Rules</h3>
          ${MODAL_CLOSE_BUTTON_HTML}
        </div>
        <div class="modal-body">
          <div class="rules-list">
            ${rulesHtml || '<div class="rules-empty">No rules defined. Add a rule below.</div>'}
          </div>
          <div class="rules-toolbar">
            <button class="glass-btn glass-btn-sm" id="rules-add">+ Add Rule</button>
          </div>
          <div class="trust-actions">
            <button class="glass-btn" id="rules-cancel">Cancel</button>
            <button class="glass-btn primary" id="rules-save">Save Rules</button>
          </div>
        </div>
      </div>
    `;
    bindRulesEvents();
  }

  function readRulesFromDom() {
    const rows = modal.querySelectorAll('.rule-row');
    rows.forEach((row, i) => {
      if (currentRules[i]) {
        currentRules[i].type = row.querySelector('.rule-type').value;
        currentRules[i].params.threshold = parseInt(row.querySelector('.rule-threshold').value, 10) || 0;
        currentRules[i].resultLevel = parseInt(row.querySelector('.rule-result-level').value, 10);
        currentRules[i].severity = row.querySelector('.rule-severity').value;
      }
    });
  }

  function bindRulesEvents() {
    const close = () => closeModal(modal);

    modal.querySelector('.modal-close').addEventListener('click', close);
    modal.querySelector('#rules-cancel').addEventListener('click', close);

    modal.querySelector('#rules-add').addEventListener('click', () => {
      readRulesFromDom();
      currentRules.push({
        id: `rule-${Date.now()}`,
        type: 'mutual_tx_count',
        params: { threshold: 0 },
        resultLevel: TrustLevel.MARGINAL,
        severity: 'info',
        description: '',
      });
      renderRules();
    });

    modal.querySelectorAll('.rule-delete-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        readRulesFromDom();
        const idx = parseInt(btn.getAttribute('data-index'), 10);
        currentRules.splice(idx, 1);
        renderRules();
      });
    });

    modal.querySelector('#rules-save').addEventListener('click', () => {
      readRulesFromDom();
      onSave(currentRules);
      close();
    });
  }

  document.body.appendChild(modal);
  renderRules();
  requestAnimationFrame(() => modal.classList.add('active'));
}

// =============================================================================
// 5. scanAllTrustTransactions
// =============================================================================

export async function scanAllTrustTransactions(addresses) {
  const allTxs = [];

  if (addresses.btc) {
    const btcTxs = await scanBitcoinTrustTransactions(addresses.btc);
    allTxs.push(...btcTxs);
  }

  if (addresses.sol) {
    const solTxs = await scanSolanaTrustTransactions(addresses.sol);
    allTxs.push(...solTxs);
  }

  if (addresses.eth) {
    const ethTxs = await scanEthereumTrustTransactions(addresses.eth);
    allTxs.push(...ethTxs);
  }

  return allTxs;
}

// =============================================================================
// 6. exportTrustData
// =============================================================================

export function exportTrustData(trustTransactions, xpub) {
  const payload = {
    exportDate: new Date().toISOString(),
    xpub: xpub || null,
    chainInfo: {
      btc: 'Bitcoin mainnet',
      sol: 'Solana mainnet-beta',
      eth: 'Ethereum mainnet',
    },
    transactions: trustTransactions || [],
  };

  const json = JSON.stringify(payload, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `trust-export-${Date.now()}.trust.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// =============================================================================
// 7. importTrustData
// =============================================================================

export function importTrustData(file) {
  return new Promise((resolve, reject) => {
    if (!file) {
      reject(new Error('No file provided'));
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target.result);
        if (!data.transactions || !Array.isArray(data.transactions)) {
          reject(new Error('Invalid trust data: missing transactions array'));
          return;
        }
        resolve(data.transactions);
      } catch (err) {
        reject(new Error(`Failed to parse trust data: ${err.message}`));
      }
    };
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}

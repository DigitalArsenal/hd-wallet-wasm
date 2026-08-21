/**
 * Trust UI components.
 *
 * Caller values are rendered as text. vCard photos are ignored here because
 * the wallet-origin byte validator owns all local image handling.
 */

import {
  TrustLevel,
  TrustLevelNames,
  scanBitcoinTrustTransactions,
  scanSolanaTrustTransactions,
  scanEthereumTrustTransactions,
  buildTrustGraph,
  buildSdsTrustExport,
  parseSdsTrustImport,
  analyzeTrustRelationships,
} from './blockchain-trust.js';
import { readTextFileForSession } from './legacy-media-session.js';

const RULE_CONDITION_TYPES = Object.freeze([
  Object.freeze({ value: 'mutual_tx_count', label: 'Mutual Transaction Count' }),
  Object.freeze({ value: 'last_interaction_days', label: 'Days Since Last Interaction' }),
  Object.freeze({ value: 'address_blocklist', label: 'Address Blocklist' }),
  Object.freeze({ value: 'bidirectional_trust', label: 'Bidirectional Trust' }),
]);
const SEVERITY_OPTIONS = Object.freeze(['info', 'warn', 'block']);
const TRUST_LEVEL_CONFIG = Object.freeze([
  Object.freeze({ value: TrustLevel.NEVER, name: 'Never Trust', desc: 'Block this address from all interactions' }),
  Object.freeze({ value: TrustLevel.UNKNOWN, name: 'Unknown', desc: 'No opinion on this address yet' }),
  Object.freeze({ value: TrustLevel.MARGINAL, name: 'Marginal', desc: 'Somewhat trusted, proceed with caution' }),
  Object.freeze({ value: TrustLevel.FULL, name: 'Full Trust', desc: 'Highly trusted, verified relationship' }),
  Object.freeze({ value: TrustLevel.ULTIMATE, name: 'Ultimate', desc: 'Your own address or absolute trust' }),
]);
const activeModalClosers = new Set();
let modalSequence = 0;

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = String(text);
  return element;
}

function button(id, className, label) {
  const element = node('button', className, label);
  element.type = 'button';
  if (id) element.id = id;
  return element;
}

function labeledValue(label, value, className = 'trust-detail-address') {
  const container = node('div', className);
  container.append(node('label', null, label), node('code', null, value));
  return container;
}

function isSessionCurrent(isCurrent) {
  try { return isCurrent() === true; } catch { return false; }
}

function staleSessionError() {
  const error = new Error('Wallet session ended');
  error.code = 'STALE_SESSION';
  return error;
}

function focusableElements(modal) {
  return [...modal.querySelectorAll([
    'button:not([disabled])',
    '[href]',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
  ].join(', '))].filter((element) => !element.hidden
    && element.getAttribute?.('aria-hidden') !== 'true'
    && element.tabIndex !== -1);
}

function modalFrame(title, { isCurrent = () => true } = {}) {
  const previouslyFocused = document.activeElement;
  const modal = node('div', 'modal trust-modal');
  const headingId = `trust-modal-title-${++modalSequence}`;
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-modal', 'true');
  modal.setAttribute('aria-labelledby', headingId);
  modal.setAttribute('tabindex', '-1');
  const glass = node('div', 'modal-glass');
  const header = node('div', 'modal-header');
  const close = button(null, 'modal-close', '×');
  close.setAttribute('aria-label', 'Close');
  const heading = node('h3', null, title);
  heading.id = headingId;
  header.append(heading, close);
  const body = node('div', 'modal-body');
  glass.append(header, body);
  modal.append(glass);
  let active = true;
  let cleanup = () => {};
  const isActive = () => active && isSessionCurrent(isCurrent);
  const closeNow = () => {
    if (!active) return;
    active = false;
    activeModalClosers.delete(closeNow);
    modal.removeEventListener('keydown', onKeydown);
    try { cleanup(); } catch { /* sensitive fields are cleared independently below */ }
    modal.classList.remove('active');
    if (previouslyFocused?.isConnected !== false) {
      try { previouslyFocused?.focus?.(); } catch { /* focus restoration is best effort */ }
    }
    setTimeout(() => modal.remove(), 200);
  };
  const onKeydown = (event) => {
    if (event?.isTrusted !== true || !isActive()) return;
    if (event.key === 'Escape') {
      event.preventDefault?.();
      closeNow();
      return;
    }
    if (event.key !== 'Tab') return;
    const focusable = focusableElements(modal);
    if (focusable.length === 0) {
      event.preventDefault?.();
      modal.focus?.();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const focused = document.activeElement;
    if (event.shiftKey && (focused === first || !modal.contains(focused))) {
      event.preventDefault?.();
      last.focus?.();
    } else if (!event.shiftKey && (focused === last || !modal.contains(focused))) {
      event.preventDefault?.();
      first.focus?.();
    }
  };
  modal.addEventListener('keydown', onKeydown);
  const activate = (initialFocus = close) => {
    if (!isActive()) {
      closeNow();
      return;
    }
    document.body.appendChild(modal);
    activeModalClosers.add(closeNow);
    requestAnimationFrame(() => {
      if (!isActive()) {
        closeNow();
        return;
      }
      modal.classList.add('active');
      try { initialFocus?.focus?.(); } catch { /* initial focus is best effort */ }
    });
  };
  return {
    activate,
    body,
    close,
    closeNow,
    isActive,
    modal,
    setCleanup(callback) { cleanup = typeof callback === 'function' ? callback : () => {}; },
  };
}

export function closeActiveTrustModals() {
  for (const close of [...activeModalClosers]) close();
}

function safeChain(value) {
  return ['btc', 'eth', 'sol'].includes(value) ? value : 'unknown';
}

function safeExplorerUrl(chain, transactionHash) {
  if (typeof transactionHash !== 'string' || !/^[A-Za-z0-9]+$/u.test(transactionHash)
      || transactionHash.length > 128) return null;
  const origins = {
    btc: 'https://blockstream.info/tx/',
    eth: 'https://etherscan.io/tx/',
    sol: 'https://solscan.io/tx/',
  };
  return origins[chain] ? origins[chain] + transactionHash : null;
}

function detectChainFromAddress(address) {
  if (typeof address !== 'string') return null;
  const value = address.trim();
  if (/^(?:1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}$/u.test(value)
      || /^bc1[a-z0-9]{25,90}$/u.test(value)) return 'btc';
  if (/^0x[0-9a-fA-F]{40}$/u.test(value)) return 'eth';
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/u.test(value)) return 'sol';
  return null;
}

function parseVCFForTrust(vcfText) {
  if (typeof vcfText !== 'string' || vcfText.length > 256 * 1024) {
    throw new Error('Invalid vCard');
  }
  const result = { name: null, email: null, org: null, keys: [], addresses: [] };
  const lines = vcfText.replace(/\r?\n /gu, '').split(/\r?\n/gu);
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const property = line.slice(0, colon).toUpperCase();
    const value = line.slice(colon + 1);
    if (property === 'FN') result.name = value;
    else if (property.startsWith('EMAIL')) result.email = value;
    else if (property.startsWith('ORG')) result.org = value.replace(/;/gu, ', ');
    else if (property.startsWith('KEY') || property.startsWith('X-CRYPTO')
        || property.startsWith('X-KEY')) {
      result.keys.push(value);
      const chain = detectChainFromAddress(value);
      if (chain) result.addresses.push({ address: value, chain });
    }
    // Photo, URI, data markup, and provider paths are never retained here.
  }
  return result;
}

export function truncatePubkey(pubkey, prefixLen = 12, suffixLen = 8) {
  if (!pubkey) return '';
  if (pubkey.length <= prefixLen + suffixLen + 3) return pubkey;
  return pubkey.slice(0, prefixLen) + '...' + pubkey.slice(-suffixLen);
}

export function truncateTxHash(txHash, prefixLen = 10, suffixLen = 6) {
  if (!txHash) return '';
  if (txHash.length <= prefixLen + suffixLen + 3) return txHash;
  return txHash.slice(0, prefixLen) + '...' + txHash.slice(-suffixLen);
}

export function renderTrustList(container, relationships, ownAddresses) {
  container.replaceChildren();
  if (!Array.isArray(relationships) || relationships.length === 0) {
    container.append(node('div', 'trust-empty', 'No trust relationships found.'));
    return;
  }
  const list = node('div', 'trust-list');
  const ownSet = new Set(
    Array.isArray(ownAddresses) ? ownAddresses : Object.values(ownAddresses || {}).flat(),
  );
  for (const relationship of relationships) {
    const outbound = ownSet.has(relationship.from);
    const inbound = ownSet.has(relationship.to);
    const direction = relationship.direction || (outbound && inbound
      ? 'mutual' : outbound ? 'outbound' : inbound ? 'inbound' : 'outbound');
    const displayAddress = relationship.address
      || (direction === 'inbound' ? relationship.from : relationship.to)
      || '';
    const chain = safeChain(relationship.chain || relationship.network);
    const row = node('div', 'trust-row');
    const header = node('div', 'trust-row-header');
    const address = node('span', 'trust-row-address', truncatePubkey(displayAddress));
    address.title = String(displayAddress || '');
    header.append(
      address,
      node('span', 'chain-badge chain-' + chain, chain === 'unknown' ? '???' : chain.toUpperCase()),
      node('span', 'trust-level-badge', TrustLevelNames[relationship.level] || 'Unknown'),
    );
    if (relationship.drained) {
      const drainBadge = node('span', 'trust-drain-alert', 'DRAIN');
      drainBadge.title = 'Balance on the published bound address dropped past the drain threshold';
      header.append(drainBadge);
    }
    header.append(
      node('span', 'trust-direction', direction === 'outbound' ? '→' : direction === 'inbound' ? '←' : '↔'),
      node('span', 'trust-row-expand', '⌄'),
    );
    const detail = node('div', 'trust-row-detail');
    detail.append(labeledValue('Full Address', displayAddress));
    if (relationship.drained) {
      const drainDetail = node('div', 'trust-drain-detail',
        'Balance on the published bound address fell from '
        + (relationship.previousBalance ?? '--') + ' to ' + (relationship.currentBalance ?? '--')
        + ' (' + ((relationship.dropRatioObserved ?? 0) * 100).toFixed(1) + '% drop) — past the '
        + ((relationship.dropRatio ?? 0) * 100).toFixed(0) + '% drain threshold. Treat this'
        + ' relationship as compromised until re-verified.');
      drainDetail.setAttribute('role', 'alert');
      detail.append(drainDetail);
    }
    const transactionSection = node('div', 'trust-detail-txs');
    transactionSection.append(node('label', null, 'Transactions'));
    const transactions = relationship.transactions || (relationship.txHash ? [relationship] : []);
    if (transactions.length === 0) {
      transactionSection.append(node('span', 'trust-no-txs', 'No transactions recorded'));
    } else {
      for (const transaction of transactions) {
        const transactionRow = node('div', 'trust-tx-row');
        const timestamp = transaction.timestamp ? new Date(transaction.timestamp).toLocaleString() : '--';
        const hash = transaction.txHash || transaction.hash || '';
        const transactionChain = safeChain(transaction.chain || transaction.network || chain);
        const url = safeExplorerUrl(transactionChain, hash);
        transactionRow.append(node('span', 'trust-tx-time', timestamp));
        if (url) {
          const link = node('a', 'trust-tx-link', truncateTxHash(hash));
          link.href = url;
          link.target = '_blank';
          link.rel = 'noopener';
          transactionRow.append(link);
        } else {
          transactionRow.append(node('code', 'trust-tx-link', truncateTxHash(hash)));
        }
        transactionSection.append(transactionRow);
      }
    }
    detail.append(transactionSection);
    if (direction !== 'inbound') {
      const actions = node('div', 'trust-detail-actions');
      const revoke = button(null, 'glass-btn glass-btn-sm trust-revoke-btn', 'Revoke');
      revoke.dataset.address = String(displayAddress || '');
      actions.append(revoke);
      detail.append(actions);
    }
    header.addEventListener('click', () => {
      const expanded = row.classList.contains('expanded');
      list.querySelectorAll('.trust-row.expanded').forEach((candidate) => {
        candidate.classList.remove('expanded');
      });
      if (!expanded) row.classList.add('expanded');
    });
    row.append(header, detail);
    list.append(row);
  }
  container.append(list);
}

export function showEstablishTrustModal(onConfirm, { isCurrent = () => true } = {}) {
  let vcfData = null;
  let detectedNetwork = null;
  let vcfReader = null;
  const frame = modalFrame('Establish Trust', { isCurrent });
  const {
    activate, body, close, closeNow, isActive, modal, setCleanup,
  } = frame;
  modal.classList.add('establish-trust-modal');
  const recipientSection = node('div', 'trust-input-section');
  recipientSection.append(node('label', 'trust-section-label', 'Recipient'));
  const tabs = node('div', 'trust-input-tabs');
  const addressTab = button(null, 'trust-input-tab active', 'Paste Address');
  addressTab.dataset.tab = 'address';
  const vcfTab = button(null, 'trust-input-tab', 'Import vCard');
  vcfTab.dataset.tab = 'vcf';
  tabs.append(addressTab, vcfTab);
  const addressPanel = node('div', 'trust-tab-panel');
  const recipient = node('input', 'trust-address-input invalid');
  recipient.id = 'trust-recipient';
  recipient.type = 'text';
  recipient.autocomplete = 'off';
  recipient.placeholder = 'BTC, ETH, or SOL address';
  const status = node('div', 'trust-address-status');
  addressPanel.append(recipient, status);
  const vcfPanel = node('div', 'trust-tab-panel');
  vcfPanel.hidden = true;
  const vcfInput = node('input');
  vcfInput.type = 'file';
  vcfInput.accept = '.vcf,.vcard';
  const vcfSummary = node('div', 'trust-vcf-summary');
  vcfPanel.append(vcfInput, vcfSummary);
  recipientSection.append(tabs, addressPanel, vcfPanel);

  const levelSection = node('div', 'trust-input-section');
  levelSection.append(node('label', 'trust-section-label', 'Trust Level'));
  const levelOptions = node('div', 'trust-level-options');
  TRUST_LEVEL_CONFIG.forEach((level, index) => {
    const label = node('label', 'trust-level-option');
    const input = node('input');
    input.type = 'radio';
    input.name = 'trust-level';
    input.value = String(level.value);
    input.checked = index === 2;
    label.append(
      input,
      node('span', 'trust-level-name', level.name),
      node('span', 'trust-level-desc', level.desc),
    );
    levelOptions.append(label);
  });
  levelSection.append(levelOptions);
  const actions = node('div', 'trust-modal-actions');
  const cancel = button('trust-cancel', 'glass-btn', 'Cancel');
  const confirm = button('trust-confirm', 'glass-btn primary', 'Publish Transaction');
  actions.append(cancel, confirm);
  body.append(recipientSection, levelSection, actions);

  const showTab = (vcf) => {
    if (!isActive()) return;
    addressTab.classList.toggle('active', !vcf);
    vcfTab.classList.toggle('active', vcf);
    addressPanel.hidden = vcf;
    vcfPanel.hidden = !vcf;
  };
  addressTab.addEventListener('click', () => showTab(false));
  vcfTab.addEventListener('click', () => showTab(true));
  recipient.addEventListener('input', () => {
    if (!isActive()) return;
    detectedNetwork = detectChainFromAddress(recipient.value);
    recipient.classList.toggle('valid', Boolean(detectedNetwork));
    recipient.classList.toggle('invalid', !detectedNetwork);
    status.textContent = detectedNetwork
      ? detectedNetwork.toUpperCase() + ' address'
      : 'Unrecognized address format';
  });
  vcfInput.addEventListener('change', () => {
    if (!isActive()) return;
    const file = vcfInput.files && vcfInput.files[0];
    if (!file) return;
    if (vcfReader) {
      try { vcfReader.abort?.(); } catch { /* stale reader callback is also session-guarded */ }
      vcfReader.onload = null;
      vcfReader.onerror = null;
      vcfReader = null;
    }
    if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > 256 * 1024) {
      vcfData = null;
      detectedNetwork = null;
      vcfSummary.textContent = 'The vCard could not be read.';
      vcfInput.value = '';
      return;
    }
    const reader = new FileReader();
    vcfReader = reader;
    reader.onload = () => {
      if (!isActive() || vcfReader !== reader) return;
      try {
        vcfData = parseVCFForTrust(reader.result);
        vcfSummary.replaceChildren();
        if (vcfData.name) vcfSummary.append(node('div', 'trust-vcf-name', vcfData.name));
        if (vcfData.org) vcfSummary.append(node('div', 'trust-vcf-org', vcfData.org));
        if (vcfData.email) vcfSummary.append(node('div', 'trust-vcf-email', vcfData.email));
        vcfData.addresses.forEach((entry, index) => {
          const label = node('label', 'trust-vcf-addr-option');
          const radio = node('input');
          radio.type = 'radio';
          radio.name = 'vcf-address';
          radio.value = String(index);
          radio.checked = index === 0;
          label.append(
            radio,
            node('span', 'chain-badge chain-' + entry.chain, entry.chain.toUpperCase()),
            node('code', null, entry.address),
          );
          vcfSummary.append(label);
        });
        detectedNetwork = vcfData.addresses[0] ? vcfData.addresses[0].chain : null;
      } catch {
        vcfData = null;
        detectedNetwork = null;
        vcfSummary.textContent = 'The vCard could not be read.';
      }
    };
    reader.onerror = () => {
      if (!isActive() || vcfReader !== reader) return;
      vcfData = null;
      detectedNetwork = null;
      vcfSummary.textContent = 'The vCard could not be read.';
    };
    reader.readAsText(file);
  });
  setCleanup(() => {
    vcfData = null;
    detectedNetwork = null;
    if (vcfReader) {
      try { vcfReader.abort?.(); } catch { /* late callback still observes inactive state */ }
      vcfReader.onload = null;
      vcfReader.onerror = null;
      vcfReader = null;
    }
    recipient.value = '';
    status.textContent = '';
    vcfInput.value = '';
    vcfSummary.replaceChildren();
  });
  close.addEventListener('click', closeNow);
  cancel.addEventListener('click', closeNow);
  confirm.addEventListener('click', () => {
    if (!isActive()) return;
    const vcfActive = vcfTab.classList.contains('active');
    let recipientAddress = recipient.value.trim();
    let network = detectedNetwork;
    if (vcfActive && vcfData && vcfData.addresses.length) {
      const selected = vcfSummary.querySelector('input[name="vcf-address"]:checked');
      const entry = vcfData.addresses[Number.parseInt(selected ? selected.value : '0', 10)];
      recipientAddress = entry ? entry.address : '';
      network = entry ? entry.chain : null;
    }
    if (!recipientAddress || !network) {
      recipient.focus();
      return;
    }
    const selectedLevel = modal.querySelector('input[name="trust-level"]:checked');
    onConfirm({
      level: Number.parseInt(
        selectedLevel ? selectedLevel.value : String(TrustLevel.MARGINAL),
        10,
      ),
      network,
      recipientAddress,
    });
    closeNow();
  });
  activate(recipient);
  return Object.freeze({ close: closeNow });
}

export function showRevokeTrustModal(
  originalTxHash,
  onConfirm,
  { isCurrent = () => true } = {},
) {
  const frame = modalFrame('Revoke Trust', { isCurrent });
  const {
    activate, body, close, closeNow, isActive, modal,
  } = frame;
  const warning = node('div', 'trust-warning');
  warning.append(
    node('p', null, 'This publishes a permanent trust revocation transaction.'),
    node('p', null, 'This action cannot be undone.'),
  );
  const actions = node('div', 'trust-actions');
  const cancel = button('revoke-cancel', 'glass-btn', 'Cancel');
  const confirm = button('revoke-confirm', 'glass-btn danger', 'Publish Revocation');
  actions.append(cancel, confirm);
  body.append(
    warning,
    labeledValue('Original Transaction', truncateTxHash(originalTxHash), 'trust-tx-hash'),
    actions,
  );
  close.addEventListener('click', closeNow);
  cancel.addEventListener('click', closeNow);
  confirm.addEventListener('click', () => {
    if (!isActive()) return;
    onConfirm({ originalTxHash });
    closeNow();
  });
  activate(cancel);
  return Object.freeze({ close: closeNow });
}

function selectControl(className, values, selectedValue) {
  const select = node('select', 'glass-select ' + className);
  for (const entry of values) {
    const option = node('option', null, entry[1]);
    option.value = String(entry[0]);
    option.selected = String(entry[0]) === String(selectedValue);
    select.append(option);
  }
  return select;
}

function ruleRow(rule, index) {
  const row = node('div', 'rule-row');
  row.dataset.index = String(index);
  const fields = node('div', 'rule-fields');
  const addField = (label, control) => {
    const wrapper = node('div', 'rule-field');
    wrapper.append(node('label', null, label), control);
    fields.append(wrapper);
  };
  addField(
    'Condition',
    selectControl(
      'rule-type',
      RULE_CONDITION_TYPES.map((entry) => [entry.value, entry.label]),
      rule.type,
    ),
  );
  const threshold = node('input', 'glass-input rule-threshold');
  threshold.type = 'number';
  threshold.min = '0';
  threshold.value = String(rule.params.threshold);
  addField('Threshold', threshold);
  addField('Result Level', selectControl('rule-result-level', Object.entries(TrustLevelNames), rule.resultLevel));
  addField(
    'Severity',
    selectControl('rule-severity', SEVERITY_OPTIONS.map((value) => [value, value]), rule.severity),
  );
  const remove = button(null, 'glass-btn glass-btn-sm rule-delete-btn', 'Delete');
  remove.dataset.index = String(index);
  fields.append(remove);
  row.append(fields);
  return row;
}

export function showRulesModal(rules, onSave, { isCurrent = () => true } = {}) {
  let currentRules = (rules || []).map((rule, index) => ({
    id: rule.id || 'rule-' + index,
    type: rule.type || 'mutual_tx_count',
    params: { threshold: rule.params && rule.params.threshold !== undefined ? rule.params.threshold : 0 },
    resultLevel: rule.resultLevel !== undefined ? rule.resultLevel : TrustLevel.MARGINAL,
    severity: rule.severity || 'info',
    description: rule.description || '',
  }));
  const frame = modalFrame('Trust Rules', { isCurrent });
  const {
    activate, body, close, closeNow, isActive, modal, setCleanup,
  } = frame;
  modal.classList.add('rules-modal');
  const list = node('div', 'rules-list');
  const toolbar = node('div', 'rules-toolbar');
  const add = button('rules-add', 'glass-btn glass-btn-sm', '+ Add Rule');
  toolbar.append(add);
  const actions = node('div', 'trust-actions');
  const cancel = button('rules-cancel', 'glass-btn', 'Cancel');
  const save = button('rules-save', 'glass-btn primary', 'Save Rules');
  actions.append(cancel, save);
  body.append(list, toolbar, actions);
  const read = () => {
    list.querySelectorAll('.rule-row').forEach((row, index) => {
      if (!currentRules[index]) return;
      currentRules[index].type = row.querySelector('.rule-type').value;
      currentRules[index].params.threshold = Number.parseInt(
        row.querySelector('.rule-threshold').value,
        10,
      ) || 0;
      currentRules[index].resultLevel = Number.parseInt(
        row.querySelector('.rule-result-level').value,
        10,
      );
      currentRules[index].severity = row.querySelector('.rule-severity').value;
    });
  };
  const render = () => {
    list.replaceChildren();
    if (currentRules.length === 0) {
      list.append(node('div', 'rules-empty', 'No rules defined. Add a rule below.'));
    }
    currentRules.forEach((rule, index) => list.append(ruleRow(rule, index)));
    list.querySelectorAll('.rule-delete-btn').forEach((remove) => {
      remove.addEventListener('click', () => {
        read();
        currentRules.splice(Number.parseInt(remove.dataset.index, 10), 1);
        render();
      });
    });
  };
  setCleanup(() => { currentRules = []; });
  close.addEventListener('click', closeNow);
  cancel.addEventListener('click', closeNow);
  add.addEventListener('click', () => {
    if (!isActive()) return;
    read();
    currentRules.push({
      id: 'rule-' + Date.now(),
      type: 'mutual_tx_count',
      params: { threshold: 0 },
      resultLevel: TrustLevel.MARGINAL,
      severity: 'info',
      description: '',
    });
    render();
  });
  save.addEventListener('click', () => {
    if (!isActive()) return;
    read();
    onSave(currentRules);
    closeNow();
  });
  render();
  activate(add);
  return Object.freeze({ close: closeNow });
}

export async function scanAllTrustTransactions(addresses) {
  const transactions = [];
  if (addresses.btc) transactions.push(...await scanBitcoinTrustTransactions(addresses.btc));
  if (addresses.sol) transactions.push(...await scanSolanaTrustTransactions(addresses.sol));
  if (addresses.eth) transactions.push(...await scanEthereumTrustTransactions(addresses.eth));
  return transactions;
}

export function exportTrustData(trustTransactions, xpub) {
  // SDS export grammar (Themis trust program): trust records → TRE edges
  // (WEIGHT = (level-1)/4, never DELETED, additive TX_HASH provenance),
  // revocations → $LOT loss-of-trust events.
  const payload = buildSdsTrustExport(trustTransactions || [], {
    peerId: xpub || undefined,
  });

  const json = JSON.stringify(payload, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `trust-export-${Date.now()}.sds.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// =============================================================================
// 7. importTrustData
// =============================================================================

export async function importTrustData(file, {
  isCurrent = () => true,
  signal = null,
} = {}) {
  if (!isSessionCurrent(isCurrent)) throw staleSessionError();
  const text = await readTextFileForSession(file, {
    isCurrent: () => isSessionCurrent(isCurrent),
    maximumBytes: 2 * 1024 * 1024,
    sessionGeneration: true,
    signal,
  });
  if (!isSessionCurrent(isCurrent)) throw staleSessionError();
  try {
    const data = JSON.parse(text);
    // SDS TRE/$LOT document (trust program export grammar) first;
    // legacy { transactions } shape accepted as fallback.
    if (data && (Array.isArray(data.tre) || Array.isArray(data.lot))) {
      if (!isSessionCurrent(isCurrent)) throw staleSessionError();
      return parseSdsTrustImport(data);
    }
    if (!Array.isArray(data.transactions)) throw new Error('missing transactions array');
    if (!isSessionCurrent(isCurrent)) throw staleSessionError();
    return data.transactions;
  } catch (error) {
    if (error?.code === 'STALE_SESSION') throw error;
    throw new Error('Failed to parse trust data: ' + error.message);
  }
}

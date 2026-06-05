import{TrustLevel as L,scanBitcoinTrustTransactions as q,scanSolanaTrustTransactions as I,scanEthereumTrustTransactions as O,TrustLevelNames as N}from"./blockchain-trust-Bn6I-PK2.js";import"./main-BNqzsCbA.js";function C(s,e=12,t=8){return s?s.length<=e+t+3?s:`${s.slice(0,e)}...${s.slice(-t)}`:""}function M(s,e=10,t=6){return s?s.length<=e+t+3?s:`${s.slice(0,e)}...${s.slice(-t)}`:""}function B(s,e){switch(s){case"btc":return`https://blockstream.info/tx/${e}`;case"eth":return`https://etherscan.io/tx/${e}`;case"sol":return`https://solscan.io/tx/${e}`;default:return`https://blockstream.info/tx/${e}`}}function F(s){const t={btc:"BTC",eth:"ETH",sol:"SOL"}[s]||(s==null?void 0:s.toUpperCase())||"???";return`<span class="chain-badge chain-${s}">${t}</span>`}function U(s){const e=N[s]||"Unknown";return`<span class="trust-level-badge trust-level-${e.toLowerCase().replace(/\s+/g,"-")}">${e}</span>`}function D(s){switch(s){case"outbound":return'<span class="trust-direction" title="Outbound">&rarr;</span>';case"inbound":return'<span class="trust-direction" title="Inbound">&larr;</span>';case"mutual":return'<span class="trust-direction" title="Mutual">&harr;</span>';default:return'<span class="trust-direction">--</span>'}}function A(s){s.classList.remove("active"),setTimeout(()=>s.remove(),200)}function G(s,e,t){if(s.innerHTML="",!e||e.length===0){s.innerHTML='<div class="trust-empty">No trust relationships found.</div>';return}const n=document.createElement("div");n.className="trust-list";for(const i of e){const a=document.createElement("div");a.className="trust-row";const r=new Set(Array.isArray(t)?t:Object.values(t||{}).flat()),l=r.has(i.from),c=r.has(i.to),d=l&&c?"mutual":l?"outbound":c?"inbound":"outbound",g=d==="inbound"?i.from:i.to,f=i.chain||i.network||"btc",p=document.createElement("div");p.className="trust-row-header",p.innerHTML=`
      <span class="trust-row-address" title="${g}">${C(g)}</span>
      ${F(f)}
      ${U(i.level)}
      ${D(d)}
      <span class="trust-row-expand">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </span>
    `;const T=document.createElement("div");T.className="trust-row-detail";const h=(i.transactions||(i.txHash?[i]:[])).map(m=>{const $=m.timestamp?new Date(m.timestamp).toLocaleString():"--",E=m.txHash||m.hash||"",o=m.chain||m.network||f,u=B(o,E);return`
        <div class="trust-tx-row">
          <span class="trust-tx-time">${$}</span>
          <a class="trust-tx-link" href="${u}" target="_blank" rel="noopener">${M(E)}</a>
        </div>
      `}).join(""),w=d!=="inbound"?`<button class="glass-btn glass-btn-sm trust-revoke-btn" data-address="${g}">Revoke</button>`:"";T.innerHTML=`
      <div class="trust-detail-address">
        <label>Full Address</label>
        <code>${g}</code>
      </div>
      <div class="trust-detail-txs">
        <label>Transactions</label>
        ${h||'<span class="trust-no-txs">No transactions recorded</span>'}
      </div>
      ${w?`<div class="trust-detail-actions">${w}</div>`:""}
    `,p.addEventListener("click",()=>{const m=a.classList.contains("expanded");n.querySelectorAll(".trust-row.expanded").forEach($=>$.classList.remove("expanded")),m||a.classList.add("expanded")}),a.appendChild(p),a.appendChild(T),n.appendChild(a)}s.appendChild(n)}function R(s){if(!s)return null;const e=s.trim();return/^(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(e)||/^bc1[a-z0-9]{25,90}$/.test(e)?"btc":/^0x[0-9a-fA-F]{40}$/.test(e)?"eth":/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(e)?"sol":null}function _(s){const e=s.replace(/\r?\n /g,"").split(/\r?\n/),t={name:null,email:null,org:null,photo:null,keys:[],addresses:[]};for(const n of e){const i=n.indexOf(":");if(i===-1)continue;const a=n.substring(0,i).toUpperCase(),r=n.substring(i+1);if(a==="FN")t.name=r;else if(a.startsWith("EMAIL"))t.email=r;else if(a.startsWith("ORG"))t.org=r.replace(/;/g,", ");else if(a.startsWith("PHOTO")){if(a.includes("VALUE=URI")||r.startsWith("data:")||r.startsWith("http"))t.photo=r;else if(a.includes("ENCODING=B")||a.includes("ENCODING=b")){const l=a.match(/TYPE=(\w+)/i),c=l?l[1].toLowerCase():"jpeg";t.photo=`data:image/${c};base64,${r}`}}else if(a.startsWith("KEY")||a.startsWith("X-CRYPTO")||a.startsWith("X-KEY")){t.keys.push(r);const l=R(r);l&&t.addresses.push({address:r,chain:l})}}return t}const j=[{value:L.NEVER,name:"Never Trust",desc:"Block this address from all interactions",color:"#ef4444",border:"rgba(239, 68, 68, 0.4)"},{value:L.UNKNOWN,name:"Unknown",desc:"No opinion on this address yet",color:"#9ca3af",border:"rgba(107, 114, 128, 0.4)"},{value:L.MARGINAL,name:"Marginal",desc:"Somewhat trusted, proceed with caution",color:"#fbbf24",border:"rgba(245, 158, 11, 0.4)"},{value:L.FULL,name:"Full Trust",desc:"Highly trusted, verified relationship",color:"#6ee7b7",border:"rgba(16, 185, 129, 0.4)"},{value:L.ULTIMATE,name:"Ultimate",desc:"Your own address or absolute trust",color:"#a78bfa",border:"rgba(139, 92, 246, 0.4)"}];function Y(s){let e=null;const t=document.createElement("div");t.className="modal trust-modal establish-trust-modal";const n=j.map((o,u)=>`
    <label class="trust-level-option" style="--level-color: ${o.color}; --level-border: ${o.border}">
      <input type="radio" name="trust-level" value="${o.value}" ${u===2?"checked":""}>
      <span class="trust-level-indicator" style="background: ${o.color}"></span>
      <span class="trust-level-label">
        <span class="trust-level-name">${o.name}</span>
        <span class="trust-level-desc">${o.desc}</span>
      </span>
    </label>
  `).join("");t.innerHTML=`
    <div class="modal-glass">
      <div class="modal-header">
        <h3>Establish Trust</h3>
        <button class="modal-close">&times;</button>
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
            ${n}
          </div>
        </div>

        <div class="trust-modal-actions">
          <button class="glass-btn" id="trust-cancel">Cancel</button>
          <button class="glass-btn primary" id="trust-confirm">Publish Transaction</button>
        </div>
      </div>
    </div>
  `,document.body.appendChild(t),requestAnimationFrame(()=>t.classList.add("active"));const i=t.querySelector(".modal-close"),a=t.querySelector("#trust-cancel"),r=t.querySelector("#trust-confirm"),l=t.querySelector("#trust-recipient"),c=t.querySelector("#trust-address-status"),d=t.querySelector("#trust-address-status-text"),g=t.querySelector("#trust-vcf-input"),f=t.querySelector("#trust-vcf-summary"),p=t.querySelector("#trust-vcf-dropzone"),T=t.querySelector("#trust-address-panel"),x=t.querySelector("#trust-vcf-panel");let h=null;const w={btc:"~0.0001 BTC",sol:"~0.000005 SOL",eth:"~0.001 ETH"},m={btc:"Bitcoin",eth:"Ethereum",sol:"Solana"},$=()=>A(t);i.addEventListener("click",$),a.addEventListener("click",$),t.querySelectorAll(".trust-input-tab").forEach(o=>{o.addEventListener("click",()=>{t.querySelectorAll(".trust-input-tab").forEach(k=>k.classList.remove("active")),o.classList.add("active");const u=o.dataset.tab==="vcf";T.style.display=u?"none":"",x.style.display=u?"":"none"})}),l.addEventListener("input",()=>{const o=l.value.trim();if(!o){l.classList.add("invalid"),l.classList.remove("valid"),c.className="trust-address-status",d.textContent="",h=null;return}const u=R(o);u?(h=u,l.classList.remove("invalid"),l.classList.add("valid"),c.className="trust-address-status detected",d.textContent=`${m[u]} (${w[u]})`):(h=null,l.classList.add("invalid"),l.classList.remove("valid"),c.className="trust-address-status invalid",d.textContent="Unrecognized address format")});function E(o){if(!o)return;const u=new FileReader;u.onload=k=>{var S;e=_(k.target.result),p.style.display="none",f.style.display="block";let v='<div class="trust-vcf-card">';e.photo&&(v+=`<img class="trust-vcf-photo" src="${e.photo}" alt="" />`),v+='<div class="trust-vcf-info">',e.name&&(v+=`<div class="trust-vcf-name">${e.name}</div>`),e.org&&(v+=`<div class="trust-vcf-org">${e.org}</div>`),e.email&&(v+=`<div class="trust-vcf-email">${e.email}</div>`),v+="</div></div>",e.addresses.length>0?(v+='<label class="trust-section-label" style="margin-top:12px">Select Address</label>',v+='<div class="trust-vcf-addresses">',e.addresses.forEach((b,y)=>{v+=`
            <label class="trust-vcf-addr-option">
              <input type="radio" name="vcf-address" value="${y}" ${y===0?"checked":""} />
              <span class="chain-badge chain-${b.chain}">${b.chain.toUpperCase()}</span>
              <code>${C(b.address)}</code>
            </label>`}),v+="</div>"):e.keys.length>0?v+=`<div class="trust-vcf-note">Found ${e.keys.length} key(s) but no recognized blockchain addresses.</div>`:v+='<div class="trust-vcf-note">No blockchain addresses found in this vCard.</div>',v+='<button class="glass-btn glass-btn-sm trust-vcf-clear" id="trust-vcf-clear">Remove</button>',f.innerHTML=v,e.addresses.length>0&&(h=e.addresses[0].chain),f.querySelectorAll('input[name="vcf-address"]').forEach(b=>{b.addEventListener("change",()=>{const y=e.addresses[parseInt(b.value,10)];y&&(h=y.chain)})}),(S=t.querySelector("#trust-vcf-clear"))==null||S.addEventListener("click",()=>{e=null,f.style.display="none",p.style.display="",g.value=""})},u.readAsText(o)}g.addEventListener("change",o=>E(o.target.files[0])),p.addEventListener("dragover",o=>{o.preventDefault(),p.classList.add("dragover")}),p.addEventListener("dragleave",()=>p.classList.remove("dragover")),p.addEventListener("drop",o=>{o.preventDefault(),p.classList.remove("dragover"),E(o.dataTransfer.files[0])}),r.addEventListener("click",()=>{var S;let o,u=h;if(((S=t.querySelector(".trust-input-tab.active"))==null?void 0:S.dataset.tab)==="vcf"&&e&&e.addresses.length>0){const b=f.querySelector('input[name="vcf-address"]:checked'),y=b?parseInt(b.value,10):0;o=e.addresses[y].address,u=e.addresses[y].chain}else o=l.value.trim();if(!o||!u){l.focus();return}const v=parseInt(t.querySelector('input[name="trust-level"]:checked').value,10);s({level:v,network:u,recipientAddress:o}),$()})}const H=[{value:"mutual_tx_count",label:"Mutual Transaction Count"},{value:"last_interaction_days",label:"Days Since Last Interaction"},{value:"address_blocklist",label:"Address Blocklist"},{value:"bidirectional_trust",label:"Bidirectional Trust"}],P=["info","warn","block"];function z(s,e){var a;const t=H.map(r=>`<option value="${r.value}" ${s.type===r.value?"selected":""}>${r.label}</option>`).join(""),n=Object.entries(N).map(([r,l])=>`<option value="${r}" ${String(s.resultLevel)===String(r)?"selected":""}>${l}</option>`).join(""),i=P.map(r=>`<option value="${r}" ${s.severity===r?"selected":""}>${r}</option>`).join("");return`
    <div class="rule-row" data-index="${e}">
      <div class="rule-fields">
        <div class="rule-field">
          <label>Condition</label>
          <select class="glass-select rule-type">${t}</select>
        </div>
        <div class="rule-field">
          <label>Threshold</label>
          <input type="number" class="glass-input rule-threshold" value="${((a=s.params)==null?void 0:a.threshold)??0}" min="0" />
        </div>
        <div class="rule-field">
          <label>Result Level</label>
          <select class="glass-select rule-result-level">${n}</select>
        </div>
        <div class="rule-field">
          <label>Severity</label>
          <select class="glass-select rule-severity">${i}</select>
        </div>
        <div class="rule-field rule-field-actions">
          <button class="glass-btn glass-btn-sm rule-delete-btn" data-index="${e}" title="Delete rule">&times;</button>
        </div>
      </div>
    </div>
  `}function J(s,e){let t=(s||[]).map((l,c)=>{var d;return{id:l.id||`rule-${c}`,type:l.type||"mutual_tx_count",params:{threshold:((d=l.params)==null?void 0:d.threshold)??0},resultLevel:l.resultLevel??L.MARGINAL,severity:l.severity||"info",description:l.description||""}});const n=document.createElement("div");n.className="modal trust-modal rules-modal";function i(){const l=t.map((c,d)=>z(c,d)).join("");n.innerHTML=`
      <div class="modal-glass">
        <div class="modal-header">
          <h3>Trust Rules</h3>
          <button class="modal-close">&times;</button>
        </div>
        <div class="modal-body">
          <div class="rules-list">
            ${l||'<div class="rules-empty">No rules defined. Add a rule below.</div>'}
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
    `,r()}function a(){n.querySelectorAll(".rule-row").forEach((c,d)=>{t[d]&&(t[d].type=c.querySelector(".rule-type").value,t[d].params.threshold=parseInt(c.querySelector(".rule-threshold").value,10)||0,t[d].resultLevel=parseInt(c.querySelector(".rule-result-level").value,10),t[d].severity=c.querySelector(".rule-severity").value)})}function r(){const l=()=>A(n);n.querySelector(".modal-close").addEventListener("click",l),n.querySelector("#rules-cancel").addEventListener("click",l),n.querySelector("#rules-add").addEventListener("click",()=>{a(),t.push({id:`rule-${Date.now()}`,type:"mutual_tx_count",params:{threshold:0},resultLevel:L.MARGINAL,severity:"info",description:""}),i()}),n.querySelectorAll(".rule-delete-btn").forEach(c=>{c.addEventListener("click",()=>{a();const d=parseInt(c.getAttribute("data-index"),10);t.splice(d,1),i()})}),n.querySelector("#rules-save").addEventListener("click",()=>{a(),e(t),l()})}document.body.appendChild(n),i(),requestAnimationFrame(()=>n.classList.add("active"))}async function K(s){const e=[];if(s.btc){const t=await q(s.btc);e.push(...t)}if(s.sol){const t=await I(s.sol);e.push(...t)}if(s.eth){const t=await O(s.eth);e.push(...t)}return e}function X(s,e){const t={exportDate:new Date().toISOString(),xpub:e||null,chainInfo:{btc:"Bitcoin mainnet",sol:"Solana mainnet-beta",eth:"Ethereum mainnet"},transactions:s||[]},n=JSON.stringify(t,null,2),i=new Blob([n],{type:"application/json"}),a=URL.createObjectURL(i),r=document.createElement("a");r.href=a,r.download=`trust-export-${Date.now()}.trust.json`,document.body.appendChild(r),r.click(),document.body.removeChild(r),URL.revokeObjectURL(a)}function Z(s){return new Promise((e,t)=>{if(!s){t(new Error("No file provided"));return}const n=new FileReader;n.onload=i=>{try{const a=JSON.parse(i.target.result);if(!a.transactions||!Array.isArray(a.transactions)){t(new Error("Invalid trust data: missing transactions array"));return}e(a.transactions)}catch(a){t(new Error(`Failed to parse trust data: ${a.message}`))}},n.onerror=()=>t(new Error("Failed to read file")),n.readAsText(s)})}export{X as exportTrustData,Z as importTrustData,G as renderTrustList,K as scanAllTrustTransactions,Y as showEstablishTrustModal,J as showRulesModal,C as truncatePubkey,M as truncateTxHash};

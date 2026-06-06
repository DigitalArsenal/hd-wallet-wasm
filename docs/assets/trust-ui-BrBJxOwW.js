import{TrustLevel as L,scanBitcoinTrustTransactions as I,scanSolanaTrustTransactions as O,scanEthereumTrustTransactions as B,TrustLevelNames as C}from"./blockchain-trust-DqgW2SIt.js";import"./main-DvHjeoa1.js";const N='<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';function A(s,t=12,e=8){return s?s.length<=t+e+3?s:`${s.slice(0,t)}...${s.slice(-e)}`:""}function M(s,t=10,e=6){return s?s.length<=t+e+3?s:`${s.slice(0,t)}...${s.slice(-e)}`:""}function D(s,t){switch(s){case"btc":return`https://blockstream.info/tx/${t}`;case"eth":return`https://etherscan.io/tx/${t}`;case"sol":return`https://solscan.io/tx/${t}`;default:return`https://blockstream.info/tx/${t}`}}function F(s){const e={btc:"BTC",eth:"ETH",sol:"SOL"}[s]||(s==null?void 0:s.toUpperCase())||"???";return`<span class="chain-badge chain-${s}">${e}</span>`}function U(s){const t=C[s]||"Unknown";return`<span class="trust-level-badge trust-level-${t.toLowerCase().replace(/\s+/g,"-")}">${t}</span>`}function _(s){switch(s){case"outbound":return'<span class="trust-direction" title="Outbound">&rarr;</span>';case"inbound":return'<span class="trust-direction" title="Inbound">&larr;</span>';case"mutual":return'<span class="trust-direction" title="Mutual">&harr;</span>';default:return'<span class="trust-direction">--</span>'}}function R(s){s.classList.remove("active"),setTimeout(()=>s.remove(),200)}function Y(s,t,e){if(s.innerHTML="",!t||t.length===0){s.innerHTML='<div class="trust-empty">No trust relationships found.</div>';return}const n=document.createElement("div");n.className="trust-list";for(const i of t){const a=document.createElement("div");a.className="trust-row";const r=new Set(Array.isArray(e)?e:Object.values(e||{}).flat()),l=r.has(i.from),c=r.has(i.to),d=l&&c?"mutual":l?"outbound":c?"inbound":"outbound",g=d==="inbound"?i.from:i.to,f=i.chain||i.network||"btc",p=document.createElement("div");p.className="trust-row-header",p.innerHTML=`
      <span class="trust-row-address" title="${g}">${A(g)}</span>
      ${F(f)}
      ${U(i.level)}
      ${_(d)}
      <span class="trust-row-expand">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="6 9 12 15 18 9"/>
        </svg>
      </span>
    `;const T=document.createElement("div");T.className="trust-row-detail";const h=(i.transactions||(i.txHash?[i]:[])).map(b=>{const $=b.timestamp?new Date(b.timestamp).toLocaleString():"--",E=b.txHash||b.hash||"",o=b.chain||b.network||f,u=D(o,E);return`
        <div class="trust-tx-row">
          <span class="trust-tx-time">${$}</span>
          <a class="trust-tx-link" href="${u}" target="_blank" rel="noopener">${M(E)}</a>
        </div>
      `}).join(""),S=d!=="inbound"?`<button class="glass-btn glass-btn-sm trust-revoke-btn" data-address="${g}">Revoke</button>`:"";T.innerHTML=`
      <div class="trust-detail-address">
        <label>Full Address</label>
        <code>${g}</code>
      </div>
      <div class="trust-detail-txs">
        <label>Transactions</label>
        ${h||'<span class="trust-no-txs">No transactions recorded</span>'}
      </div>
      ${S?`<div class="trust-detail-actions">${S}</div>`:""}
    `,p.addEventListener("click",()=>{const b=a.classList.contains("expanded");n.querySelectorAll(".trust-row.expanded").forEach($=>$.classList.remove("expanded")),b||a.classList.add("expanded")}),a.appendChild(p),a.appendChild(T),n.appendChild(a)}s.appendChild(n)}function q(s){if(!s)return null;const t=s.trim();return/^(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(t)||/^bc1[a-z0-9]{25,90}$/.test(t)?"btc":/^0x[0-9a-fA-F]{40}$/.test(t)?"eth":/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(t)?"sol":null}function j(s){const t=s.replace(/\r?\n /g,"").split(/\r?\n/),e={name:null,email:null,org:null,photo:null,keys:[],addresses:[]};for(const n of t){const i=n.indexOf(":");if(i===-1)continue;const a=n.substring(0,i).toUpperCase(),r=n.substring(i+1);if(a==="FN")e.name=r;else if(a.startsWith("EMAIL"))e.email=r;else if(a.startsWith("ORG"))e.org=r.replace(/;/g,", ");else if(a.startsWith("PHOTO")){if(a.includes("VALUE=URI")||r.startsWith("data:")||r.startsWith("http"))e.photo=r;else if(a.includes("ENCODING=B")||a.includes("ENCODING=b")){const l=a.match(/TYPE=(\w+)/i),c=l?l[1].toLowerCase():"jpeg";e.photo=`data:image/${c};base64,${r}`}}else if(a.startsWith("KEY")||a.startsWith("X-CRYPTO")||a.startsWith("X-KEY")){e.keys.push(r);const l=q(r);l&&e.addresses.push({address:r,chain:l})}}return e}const H=[{value:L.NEVER,name:"Never Trust",desc:"Block this address from all interactions",color:"#ef4444",border:"rgba(239, 68, 68, 0.4)"},{value:L.UNKNOWN,name:"Unknown",desc:"No opinion on this address yet",color:"#9ca3af",border:"rgba(107, 114, 128, 0.4)"},{value:L.MARGINAL,name:"Marginal",desc:"Somewhat trusted, proceed with caution",color:"#fbbf24",border:"rgba(245, 158, 11, 0.4)"},{value:L.FULL,name:"Full Trust",desc:"Highly trusted, verified relationship",color:"#6ee7b7",border:"rgba(16, 185, 129, 0.4)"},{value:L.ULTIMATE,name:"Ultimate",desc:"Your own address or absolute trust",color:"#a78bfa",border:"rgba(139, 92, 246, 0.4)"}];function J(s){let t=null;const e=document.createElement("div");e.className="modal trust-modal establish-trust-modal";const n=H.map((o,u)=>`
    <label class="trust-level-option" style="--level-color: ${o.color}; --level-border: ${o.border}">
      <input type="radio" name="trust-level" value="${o.value}" ${u===2?"checked":""}>
      <span class="trust-level-indicator" style="background: ${o.color}"></span>
      <span class="trust-level-label">
        <span class="trust-level-name">${o.name}</span>
        <span class="trust-level-desc">${o.desc}</span>
      </span>
    </label>
  `).join("");e.innerHTML=`
    <div class="modal-glass">
      <div class="modal-header">
        <h3>Establish Trust</h3>
        <button class="modal-close" type="button" aria-label="Close">${N}</button>
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
  `,document.body.appendChild(e),requestAnimationFrame(()=>e.classList.add("active"));const i=e.querySelector(".modal-close"),a=e.querySelector("#trust-cancel"),r=e.querySelector("#trust-confirm"),l=e.querySelector("#trust-recipient"),c=e.querySelector("#trust-address-status"),d=e.querySelector("#trust-address-status-text"),g=e.querySelector("#trust-vcf-input"),f=e.querySelector("#trust-vcf-summary"),p=e.querySelector("#trust-vcf-dropzone"),T=e.querySelector("#trust-address-panel"),x=e.querySelector("#trust-vcf-panel");let h=null;const S={btc:"~0.0001 BTC",sol:"~0.000005 SOL",eth:"~0.001 ETH"},b={btc:"Bitcoin",eth:"Ethereum",sol:"Solana"},$=()=>R(e);i.addEventListener("click",$),a.addEventListener("click",$),e.querySelectorAll(".trust-input-tab").forEach(o=>{o.addEventListener("click",()=>{e.querySelectorAll(".trust-input-tab").forEach(k=>k.classList.remove("active")),o.classList.add("active");const u=o.dataset.tab==="vcf";T.style.display=u?"none":"",x.style.display=u?"":"none"})}),l.addEventListener("input",()=>{const o=l.value.trim();if(!o){l.classList.add("invalid"),l.classList.remove("valid"),c.className="trust-address-status",d.textContent="",h=null;return}const u=q(o);u?(h=u,l.classList.remove("invalid"),l.classList.add("valid"),c.className="trust-address-status detected",d.textContent=`${b[u]} (${S[u]})`):(h=null,l.classList.add("invalid"),l.classList.remove("valid"),c.className="trust-address-status invalid",d.textContent="Unrecognized address format")});function E(o){if(!o)return;const u=new FileReader;u.onload=k=>{var w;t=j(k.target.result),p.style.display="none",f.style.display="block";let v='<div class="trust-vcf-card">';t.photo&&(v+=`<img class="trust-vcf-photo" src="${t.photo}" alt="" />`),v+='<div class="trust-vcf-info">',t.name&&(v+=`<div class="trust-vcf-name">${t.name}</div>`),t.org&&(v+=`<div class="trust-vcf-org">${t.org}</div>`),t.email&&(v+=`<div class="trust-vcf-email">${t.email}</div>`),v+="</div></div>",t.addresses.length>0?(v+='<label class="trust-section-label" style="margin-top:12px">Select Address</label>',v+='<div class="trust-vcf-addresses">',t.addresses.forEach((m,y)=>{v+=`
            <label class="trust-vcf-addr-option">
              <input type="radio" name="vcf-address" value="${y}" ${y===0?"checked":""} />
              <span class="chain-badge chain-${m.chain}">${m.chain.toUpperCase()}</span>
              <code>${A(m.address)}</code>
            </label>`}),v+="</div>"):t.keys.length>0?v+=`<div class="trust-vcf-note">Found ${t.keys.length} key(s) but no recognized blockchain addresses.</div>`:v+='<div class="trust-vcf-note">No blockchain addresses found in this vCard.</div>',v+='<button class="glass-btn glass-btn-sm trust-vcf-clear" id="trust-vcf-clear">Remove</button>',f.innerHTML=v,t.addresses.length>0&&(h=t.addresses[0].chain),f.querySelectorAll('input[name="vcf-address"]').forEach(m=>{m.addEventListener("change",()=>{const y=t.addresses[parseInt(m.value,10)];y&&(h=y.chain)})}),(w=e.querySelector("#trust-vcf-clear"))==null||w.addEventListener("click",()=>{t=null,f.style.display="none",p.style.display="",g.value=""})},u.readAsText(o)}g.addEventListener("change",o=>E(o.target.files[0])),p.addEventListener("dragover",o=>{o.preventDefault(),p.classList.add("dragover")}),p.addEventListener("dragleave",()=>p.classList.remove("dragover")),p.addEventListener("drop",o=>{o.preventDefault(),p.classList.remove("dragover"),E(o.dataTransfer.files[0])}),r.addEventListener("click",()=>{var w;let o,u=h;if(((w=e.querySelector(".trust-input-tab.active"))==null?void 0:w.dataset.tab)==="vcf"&&t&&t.addresses.length>0){const m=f.querySelector('input[name="vcf-address"]:checked'),y=m?parseInt(m.value,10):0;o=t.addresses[y].address,u=t.addresses[y].chain}else o=l.value.trim();if(!o||!u){l.focus();return}const v=parseInt(e.querySelector('input[name="trust-level"]:checked').value,10);s({level:v,network:u,recipientAddress:o}),$()})}const P=[{value:"mutual_tx_count",label:"Mutual Transaction Count"},{value:"last_interaction_days",label:"Days Since Last Interaction"},{value:"address_blocklist",label:"Address Blocklist"},{value:"bidirectional_trust",label:"Bidirectional Trust"}],z=["info","warn","block"];function V(s,t){var a;const e=P.map(r=>`<option value="${r.value}" ${s.type===r.value?"selected":""}>${r.label}</option>`).join(""),n=Object.entries(C).map(([r,l])=>`<option value="${r}" ${String(s.resultLevel)===String(r)?"selected":""}>${l}</option>`).join(""),i=z.map(r=>`<option value="${r}" ${s.severity===r?"selected":""}>${r}</option>`).join("");return`
    <div class="rule-row" data-index="${t}">
      <div class="rule-fields">
        <div class="rule-field">
          <label>Condition</label>
          <select class="glass-select rule-type">${e}</select>
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
          <button class="glass-btn glass-btn-sm rule-delete-btn" data-index="${t}" title="Delete rule" aria-label="Delete rule"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
      </div>
    </div>
  `}function K(s,t){let e=(s||[]).map((l,c)=>{var d;return{id:l.id||`rule-${c}`,type:l.type||"mutual_tx_count",params:{threshold:((d=l.params)==null?void 0:d.threshold)??0},resultLevel:l.resultLevel??L.MARGINAL,severity:l.severity||"info",description:l.description||""}});const n=document.createElement("div");n.className="modal trust-modal rules-modal";function i(){const l=e.map((c,d)=>V(c,d)).join("");n.innerHTML=`
      <div class="modal-glass">
        <div class="modal-header">
          <h3>Trust Rules</h3>
          <button class="modal-close" type="button" aria-label="Close">${N}</button>
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
    `,r()}function a(){n.querySelectorAll(".rule-row").forEach((c,d)=>{e[d]&&(e[d].type=c.querySelector(".rule-type").value,e[d].params.threshold=parseInt(c.querySelector(".rule-threshold").value,10)||0,e[d].resultLevel=parseInt(c.querySelector(".rule-result-level").value,10),e[d].severity=c.querySelector(".rule-severity").value)})}function r(){const l=()=>R(n);n.querySelector(".modal-close").addEventListener("click",l),n.querySelector("#rules-cancel").addEventListener("click",l),n.querySelector("#rules-add").addEventListener("click",()=>{a(),e.push({id:`rule-${Date.now()}`,type:"mutual_tx_count",params:{threshold:0},resultLevel:L.MARGINAL,severity:"info",description:""}),i()}),n.querySelectorAll(".rule-delete-btn").forEach(c=>{c.addEventListener("click",()=>{a();const d=parseInt(c.getAttribute("data-index"),10);e.splice(d,1),i()})}),n.querySelector("#rules-save").addEventListener("click",()=>{a(),t(e),l()})}document.body.appendChild(n),i(),requestAnimationFrame(()=>n.classList.add("active"))}async function X(s){const t=[];if(s.btc){const e=await I(s.btc);t.push(...e)}if(s.sol){const e=await O(s.sol);t.push(...e)}if(s.eth){const e=await B(s.eth);t.push(...e)}return t}function Z(s,t){const e={exportDate:new Date().toISOString(),xpub:t||null,chainInfo:{btc:"Bitcoin mainnet",sol:"Solana mainnet-beta",eth:"Ethereum mainnet"},transactions:s||[]},n=JSON.stringify(e,null,2),i=new Blob([n],{type:"application/json"}),a=URL.createObjectURL(i),r=document.createElement("a");r.href=a,r.download=`trust-export-${Date.now()}.trust.json`,document.body.appendChild(r),r.click(),document.body.removeChild(r),URL.revokeObjectURL(a)}function Q(s){return new Promise((t,e)=>{if(!s){e(new Error("No file provided"));return}const n=new FileReader;n.onload=i=>{try{const a=JSON.parse(i.target.result);if(!a.transactions||!Array.isArray(a.transactions)){e(new Error("Invalid trust data: missing transactions array"));return}t(a.transactions)}catch(a){e(new Error(`Failed to parse trust data: ${a.message}`))}},n.onerror=()=>e(new Error("Failed to read file")),n.readAsText(s)})}export{Z as exportTrustData,Q as importTrustData,Y as renderTrustList,X as scanAllTrustTransactions,J as showEstablishTrustModal,K as showRulesModal,A as truncatePubkey,M as truncateTxHash};

const NAV_ITEMS = [
  {href:'/ui/dashboard.html', label:'Dashboard'},
  {href:'/ui/events.html', label:'Events'},
  {href:'/ui/alerts.html', label:'Alerts'},
  {href:'/ui/cases.html', label:'Cases'},
  {href:'/ui/rules.html', label:'Rules'},
  {href:'/ui/parsers.html', label:'Parsers'},
];

function parseJwt(t){try{const b=t.split('.')[1].replace(/-/g,'+').replace(/_/g,'/');return JSON.parse(atob(b))}catch{return null}}
function clearAuth(){['ts_jwt','ts_username','ts_role','ts_key'].forEach(k=>localStorage.removeItem(k))}

async function logout(){
  const ep=localStorage.getItem('ts_ep')||'http://localhost:8000';
  const jwt=localStorage.getItem('ts_jwt')||'';
  try{await fetch(ep+'/auth/logout',{method:'POST',headers:{Authorization:`Bearer ${jwt}`}})}catch(e){}
  clearAuth();
  window.location.href='/ui/login.html';
}

function toggleTheme(){
  const TH=document.documentElement;
  const t=TH.getAttribute('data-theme')==='dark'?'light':'dark';
  TH.setAttribute('data-theme',t);
  localStorage.setItem('ts_theme',t);
}

function toggleProfileMenu(){
  const dd=document.getElementById('profileDropdown');
  if(dd) dd.classList.toggle('show');
}

function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

function renderNav(){
  const root=document.getElementById('nav-root');
  if(!root) return;
  const username=localStorage.getItem('ts_username')||'';
  const role=localStorage.getItem('ts_role')||'';
  const initial=(username[0]||'?').toUpperCase();
  const path=window.location.pathname;
  const linksHtml=NAV_ITEMS.map(item=>{
    const active=path===item.href?' active':'';
    return `<a href="${item.href}" class="top-nav-link${active}">${esc(item.label)}</a>`;
  }).join('');
  const auditItem=role==='superadmin'
    ? `<a href="/ui/audit.html" class="profile-dropdown-item">Audit Log</a>`
    : '';
  root.innerHTML=`
    <nav class="top-nav">
      <a href="/ui/home.html" class="top-nav-logo">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        TinySIEM
      </a>
      <div class="top-nav-links">${linksHtml}</div>
      <div class="top-nav-right">
        <button class="nav-btn" onclick="toggleTheme()" title="Toggle theme">&#9681;</button>
        <button class="profile-avatar" onclick="toggleProfileMenu()" title="${esc(username)}">${esc(initial)}</button>
        <div class="profile-dropdown" id="profileDropdown">
          <div class="profile-dropdown-header">
            <div class="profile-dropdown-name">${esc(username)}</div>
            <div class="profile-dropdown-role">${esc(role)}</div>
          </div>
          <a href="/ui/settings.html" class="profile-dropdown-item">Settings</a>
          ${auditItem}
          <div class="profile-dropdown-divider"></div>
          <button class="profile-dropdown-item" onclick="logout()">Sign out</button>
        </div>
      </div>
    </nav>
  `;
}

document.addEventListener('click', e=>{
  const dd=document.getElementById('profileDropdown');
  if(!dd || !dd.classList.contains('show')) return;
  if(e.target.closest('.profile-avatar') || e.target.closest('.profile-dropdown')) return;
  dd.classList.remove('show');
});

document.addEventListener('DOMContentLoaded', renderNav);

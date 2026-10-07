(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const TOKEN = document.querySelector('meta[name="t"]').content;
  const MAX_LOG_LINES = 800;

  let S = null;              // last state from the backend
  let since = 0;             // last journal line number we have seen
  let failures = 0;
  let pending = false;       // a connect/disconnect request is in flight
  let listSig = '';
  let armedId = null, armedTimer = null;   // "delete" pressed once, waiting for the second click
  let renamingId = null;
  let offlineToast = null;

  const prefs = {
    get(key, fallback) { try { return localStorage.getItem(key) ?? fallback; } catch (_) { return fallback; } },
    set(key, value) { try { localStorage.setItem(key, value); } catch (_) { /* private mode */ } },
  };

  // ---------- helpers ----------
  async function api(name, args = {}) {
    const res = await fetch('/api/' + name, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Token': TOKEN },
      body: JSON.stringify(args),
    });
    let body = {};
    try { body = await res.json(); } catch (_) { /* keep {} */ }
    if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
    return body;
  }

  // Everything that came from the network is written with textContent only:
  // server names from subscriptions are untrusted.
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function toast(msg, kind = 'ok', ms) {
    const t = el('div', 'toast' + (kind === 'err' ? ' err' : ''));
    t.append(el('p', '', msg));
    const x = el('button', '', '×');
    x.title = 'Закрыть';
    x.addEventListener('click', () => t.remove());
    t.append(x);
    $('toasts').append(t);
    while ($('toasts').childElementCount > 4) $('toasts').firstElementChild.remove();
    const life = ms !== undefined ? ms : (kind === 'err' ? 12000 : 4000);
    if (life) setTimeout(() => t.remove(), life);
    return t;
  }

  async function act(fn) {
    try { return await fn(); }
    catch (e) { toast(e.message || String(e), 'err'); return null; }
  }

  async function copyText(text, okMsg) {
    try { await navigator.clipboard.writeText(text); toast(okMsg); }
    catch (_) { toast('Не получилось скопировать: браузер не дал доступ к буферу обмена.', 'err'); }
  }

  const num = (n, digits) => n.toLocaleString('ru-RU', { minimumFractionDigits: digits, maximumFractionDigits: digits });
  function fmtBytes(n) {
    if (n < 1024) return n + ' Б';
    if (n < 1024 ** 2) return num(n / 1024, 0) + ' КБ';
    if (n < 1024 ** 3) return num(n / 1024 ** 2, 1) + ' МБ';
    return num(n / 1024 ** 3, 2) + ' ГБ';
  }
  function fmtSpeed(bps) {
    if (bps < 1024 ** 2) return [num(bps / 1024, bps < 10240 ? 1 : 0), 'КБ/с'];
    return [num(bps / 1024 ** 2, 1), 'МБ/с'];
  }
  function fmtDur(sec) {
    const h = Math.floor(sec / 3600), m = Math.floor(sec % 3600 / 60), s = sec % 60;
    return [h, m, s].map((n) => String(n).padStart(2, '0')).join(':');
  }
  const fmtDate = (ts) => new Date(ts * 1000).toLocaleDateString('ru-RU');
  const cut = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

  // ---------- server list ----------
  // Two measurements: "delay" is a real request through the tunnel (proves the
  // keys work), "ping" is only a TCP handshake with the server.
  function pingView(s) {
    if (typeof s.delay === 'number') {
      if (s.delay === -1) {
        return s.ping > 0
          ? ['bad', 'не работает', 'Сервер на связи, но запрос через него не проходит: проверь ключ и настройки']
          : ['bad', 'нет ответа', 'Сервер не отвечает'];
      }
      return [s.delay < 700 ? 'good' : s.delay < 1500 ? 'mid' : 'bad', s.delay + ' мс', 'Время запроса через сервер (лучшее из двух)'];
    }
    if (s.ping === -1) return ['bad', 'нет ответа', 'Сервер не отвечает'];
    if (typeof s.ping !== 'number') return ['', '—', 'Ещё не проверялся'];
    return ['tcp', s.ping + ' мс', 'Пока только отклик самого сервера, без проверки туннеля'];
  }
  const speedKey = (s) => (s.delay > 0 ? s.delay : s.delay === -1 ? 1e9 : s.ping > 0 ? 5000 + s.ping : 1e9);

  function subMeta(sub) {
    const parts = [];
    const info = sub.info || {};
    if (info.total > 0) {
      const used = (info.upload || 0) + (info.download || 0);
      const pct = Math.min(100, Math.round(used * 100 / info.total));
      const level = pct > 95 ? 'bad' : pct > 80 ? 'warn' : '';
      const bar = el('span', 'quota ' + level);
      const fill = el('i');
      fill.style.width = pct + '%';
      bar.append(fill);
      bar.title = 'Израсходовано ' + pct + '%';
      parts.push(bar, el('span', 'g-meta ' + level, fmtBytes(used) + ' из ' + fmtBytes(info.total)));
    }
    if (info.expire > 0) {
      const days = Math.floor((info.expire - Date.now() / 1000) / 86400);
      const level = days < 0 ? 'bad' : days < 7 ? 'warn' : '';
      parts.push(el('span', 'g-meta ' + level, days < 0 ? 'срок истёк ' + fmtDate(info.expire) : 'до ' + fmtDate(info.expire)));
    }
    return parts;
  }

  function serverRow(s) {
    const selected = s.id === S.selected;
    const live = selected && S.connected;
    const row = el('div', 'row' + (selected ? ' sel' : '') + (live ? ' live' : ''));
    row.tabIndex = 0;
    row.addEventListener('click', () => { if (!selected) act(() => api('select', { id: s.id }).then(refreshNow)); });
    row.addEventListener('dblclick', () => connectTo(s.id));
    row.addEventListener('keydown', (e) => {
      if (e.target !== row) return;
      if (e.key === 'Enter') connectTo(s.id);
      if (e.key === ' ') { e.preventDefault(); row.click(); }
    });

    row.append(el('span', 'cc', s.country || '··'));

    const main = el('div');
    if (renamingId === s.id) {
      const input = el('input', 'r-rename');
      input.value = s.name;
      input.maxLength = 80;
      const finish = (save) => {
        if (renamingId !== s.id) return;
        renamingId = null;
        const value = input.value.trim();
        if (save && value && value !== s.name) act(() => api('rename', { id: s.id, name: value }).then(refreshNow));
        else { listSig = ''; renderServers(); }
      };
      input.addEventListener('click', (e) => e.stopPropagation());
      input.addEventListener('dblclick', (e) => e.stopPropagation());
      input.addEventListener('keydown', (e) => {
        e.stopPropagation();
        if (e.key === 'Enter') finish(true);
        if (e.key === 'Escape') finish(false);
      });
      input.addEventListener('blur', () => finish(true));
      main.append(input);
      setTimeout(() => { input.focus(); input.select(); }, 0);
    } else {
      const name = el('div', 'r-name', s.name);
      if (live) name.append(el('span', 'badge', 'подключён'));
      main.append(name);
    }
    main.append(el('div', 'r-addr' + (s.error ? ' bad' : ''), s.error ? 'Ссылка не подходит: ' + s.error : s.host + ':' + s.port));
    row.append(main);

    const unprotected = s.security === 'none' && (s.protocol === 'vless' || s.protocol === 'trojan');
    const label = (s.protocol !== 'vless' ? s.protocol + ' ' : '')
      + (s.protocol === 'shadowsocks' ? '' : s.security + ' / ' + s.network);
    const proto = el('span', 'r-proto' + (unprotected ? ' plain' : ''), s.error ? '' : label.trim());
    if (unprotected) proto.title = 'Без шифрования: трафик до сервера виден провайдеру';
    row.append(proto);

    const [cls, txt, tip] = pingView(s);
    const pingEl = el('span', 'r-ping ' + cls, txt);
    pingEl.title = tip;
    row.append(pingEl);

    const actions = el('div', 'r-actions');
    const add = (label, title, cls2, fn) => {
      const b = el('button', cls2, label);
      b.title = title;
      b.addEventListener('click', (e) => { e.stopPropagation(); fn(); });
      b.addEventListener('dblclick', (e) => e.stopPropagation());
      actions.append(b);
    };
    add('Проверить', 'Измерить время запроса через этот сервер', '', () => act(async () => {
      await api('ping', { id: s.id }); await refreshNow();
      if (S.core.installed) { await api('real_ping', { id: s.id }); await refreshNow(); }
    }));
    add('Имя', 'Переименовать', '', () => { renamingId = s.id; listSig = ''; renderServers(); });
    add('QR', 'Показать QR-код, чтобы перенести сервер на телефон', '', () => act(() => showQr(s.id)));
    add('Ссылка', 'Скопировать ссылку vless:// (в ней ключ доступа)', '', () => act(async () => {
      const r = await api('get_link', { id: s.id });
      await copyText(r.link, 'Ссылка скопирована. В ней ключ доступа, не публикуй её.');
    }));
    const armed = armedId === s.id;
    add(armed ? 'Точно удалить?' : 'Удалить', 'Убрать сервер из списка', armed ? 'danger armed' : 'danger', () => {
      if (!armed) {
        armedId = s.id;
        clearTimeout(armedTimer);
        armedTimer = setTimeout(() => { armedId = null; listSig = ''; if (S) renderServers(); }, 3000);
        listSig = ''; renderServers();
        return;
      }
      armedId = null;
      act(() => api('delete', { id: s.id }).then(refreshNow));
    });
    row.append(actions);
    return row;
  }

  function renderServers() {
    if (renamingId !== null && listSig !== '') return;      // do not rebuild under the user's cursor
    const query = $('search').value.trim().toLowerCase();
    const sort = $('sort').value;
    const sig = JSON.stringify([S.servers, S.subs, S.selected, S.connected, query, sort, armedId, renamingId]);
    if (sig === listSig) return;
    listSig = sig;

    const list = $('list');
    const keepScroll = list.scrollTop;
    list.replaceChildren();
    $('empty').classList.toggle('hidden', S.servers.length > 0);
    list.classList.toggle('hidden', S.servers.length === 0);

    const match = (s) => !query || (s.name + ' ' + (s.host || '') + ' ' + s.country).toLowerCase().includes(query);
    const order = (arr) => {
      if (sort === 'name') return [...arr].sort((a, b) => a.name.localeCompare(b.name, 'ru'));
      if (sort === 'ping') {
        return [...arr].sort((a, b) => speedKey(a) - speedKey(b));
      }
      return arr;
    };

    let shown = 0;
    const groups = S.subs.map((sub) => ({ sub, servers: S.servers.filter((s) => s.sub === sub.id) }));
    const manual = S.servers.filter((s) => !s.sub || !S.subs.some((x) => x.id === s.sub));
    if (manual.length) groups.push({ sub: null, servers: manual });

    for (const g of groups) {
      const visible = order(g.servers.filter(match));
      if (!visible.length && query) continue;
      const head = el('div', 'group-h');
      if (g.sub) {
        head.append(el('span', 'g-name', g.sub.name));
        head.append(el('span', 'g-meta', g.servers.length + ' серв.'));
        head.append(...subMeta(g.sub));
        head.append(el('span', 'spacer'));
        const upd = el('button', 'linkbtn', 'Обновить');
        upd.title = g.sub.updated_at ? 'Последнее обновление: ' + new Date(g.sub.updated_at * 1000).toLocaleString('ru-RU') : 'Загрузить список серверов заново';
        upd.addEventListener('click', () => act(async () => {
          upd.disabled = true; upd.textContent = 'Обновляю…';
          try { const r = await api('refresh_subs', { id: g.sub.id }); toast('Подписка обновлена: ' + r.added + ' серверов'); }
          finally { await refreshNow(); }
        }));
        const armed = armedId === 'sub:' + g.sub.id;
        const del = el('button', 'linkbtn danger', armed ? 'Точно удалить?' : 'Удалить');
        del.title = 'Удалить подписку вместе с её серверами';
        del.addEventListener('click', () => {
          if (!armed) {
            armedId = 'sub:' + g.sub.id;
            clearTimeout(armedTimer);
            armedTimer = setTimeout(() => { armedId = null; listSig = ''; if (S) renderServers(); }, 3000);
            listSig = ''; renderServers();
            return;
          }
          armedId = null;
          act(() => api('delete_sub', { id: g.sub.id }).then(refreshNow));
        });
        head.append(upd, del);
      } else if (S.subs.length) {
        head.append(el('span', 'g-name', 'Добавлены вручную'));
        head.append(el('span', 'g-meta', g.servers.length + ' серв.'));
      }
      if (head.childElementCount) list.append(head);
      for (const s of visible) { list.append(serverRow(s)); shown += 1; }
    }
    $('nomatch').classList.toggle('hidden', !(S.servers.length > 0 && shown === 0));
    list.scrollTop = keepScroll;
  }

  // ---------- QR ----------
  const SVG_NS = 'http://www.w3.org/2000/svg';
  async function showQr(id) {
    const r = await api('qr', { id });
    const n = r.rows.length, quiet = 4, total = n + quiet * 2;
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + total + ' ' + total);
    svg.setAttribute('shape-rendering', 'crispEdges');
    let d = '';
    r.rows.forEach((row, y) => {            // one path, a run of dark cells = one rectangle
      let x = 0;
      while (x < n) {
        if (row[x] !== '1') { x += 1; continue; }
        let end = x;
        while (end < n && row[end] === '1') end += 1;
        d += 'M' + (x + quiet) + ' ' + (y + quiet) + 'h' + (end - x) + 'v1h-' + (end - x) + 'z';
        x = end;
      }
    });
    const path = document.createElementNS(SVG_NS, 'path');
    path.setAttribute('d', d);
    path.setAttribute('fill', '#000000');
    svg.append(path);
    $('qr-box').replaceChildren(svg);
    $('qr-title').textContent = 'QR-код: ' + r.name;
    $('dlg-qr').showModal();
  }
  $('qr-close').addEventListener('click', () => { $('dlg-qr').close(); $('qr-box').replaceChildren(); });

  // ---------- route diagram + status ----------
  function renderRoute() {
    const installing = S.core.install.running;
    const busy = pending || S.connecting || installing || S.reconnecting;
    const on = S.connected && !busy;
    const sick = on && S.health.fails >= 3;
    const sel = S.servers.find((s) => s.id === S.selected);

    $('route').setAttribute('class', 'diagram ' + (busy ? 'busy' : on ? 'on' : 'off')
      + (S.mode === 'global' ? ' global' : ' bypass') + (sick ? ' sick' : ''));

    $('rt-server').textContent = sel ? cut((sel.country ? sel.country + ' ' : '') + sel.name, 22) : 'сервер не выбран';
    let serverSub = sel && !sel.error ? cut(sel.host + ':' + sel.port, 22) : '';
    if (on && typeof S.health.ms === 'number') serverSub = 'отклик ' + S.health.ms + ' мс';
    if (sick) serverSub = 'не отвечает';
    $('rt-server-sub').textContent = serverSub;

    $('rt-pc').textContent = on ? (S.settings.sysproxy ? 'системный прокси' : 'только вручную') : '';
    $('rt-net').textContent = on
      ? (S.exit ? cut(S.exit.ip, 18) + ' ' + S.exit.loc : 'узнаю адрес…')
      : 'твой адрес';
    $('rt-tunnel-vol').textContent = on ? fmtBytes(S.traffic.proxy_total) : '';
    $('rt-direct').textContent = !on ? (busy ? '' : 'сейчас весь трафик идёт напрямую')
      : S.mode === 'global' ? 'напрямую только локальная сеть'
        : 'российские сайты напрямую: ' + fmtBytes(S.traffic.direct_total);

    const btn = $('btn-connect');
    btn.className = 'connect' + (busy ? ' busy' : on ? ' on' : '');
    btn.textContent = S.reconnecting ? 'Отменить' : busy ? 'Подключаюсь…' : on ? 'Отключить' : 'Подключить';
    btn.disabled = (busy && !S.reconnecting) || (!on && !busy && !sel);

    renderStatus(installing, busy, on, sick);

    const [d, du] = fmtSpeed(S.traffic.down_bps), [u, uu] = fmtSpeed(S.traffic.up_bps);
    $('sp-down').textContent = d; $('sp-down-u').textContent = du;
    $('sp-up').textContent = u; $('sp-up-u').textContent = uu;
    $('sp-total').textContent = on ? 'за сеанс ' + fmtBytes(S.traffic.down_total + S.traffic.up_total) : '';
    drawChart(S.traffic.history);

    const sb = $('btn-speed'), so = $('speed-out');
    if (sb.dataset.busy !== '1') {
      sb.disabled = !on;
      if (S.speed) {
        so.className = ''; delete so.dataset.err;
        so.replaceChildren(el('b', '', num(S.speed.mbps, 1)), ' Мбит/с на приём');
        so.title = 'Тестовый файл: ' + (S.speed.source || '');
      } else if (!so.dataset.err || !on) { so.className = ''; so.textContent = ''; delete so.dataset.err; }
    }
  }

  function renderStatus(installing, busy, on, sick) {
    const st = $('status');
    let text, cls = '';
    if (installing) text = 'Скачиваю ядро Xray: ' + S.core.install.pct + '%';
    else if (S.reconnecting) text = 'Соединение оборвалось, восстанавливаю…';
    else if (busy) text = 'Запускаю ядро и проверяю сервер…';
    else if (sick) { text = 'Сервер не отвечает на проверки. Попробуй другой.'; cls = 'bad'; }
    else if (on) {
      text = 'Подключено ' + fmtDur(Math.max(0, Math.floor(Date.now() / 1000 - (S.connected_at || 0))));
      cls = 'ok';
    } else if (!S.servers.length) text = 'Добавь сервер, чтобы подключиться';
    else if (!S.core.installed) text = 'Ядро Xray скачается само при первом подключении';
    else text = 'Отключено';
    st.textContent = text;
    st.className = 'status ' + cls;
  }

  function drawChart(history) {
    const c = $('chart'), g = c.getContext('2d'), w = c.width, h = c.height;
    g.clearRect(0, 0, w, h);
    const css = getComputedStyle(document.documentElement);
    const teal = css.getPropertyValue('--tunnel').trim(), fog = css.getPropertyValue('--fog-2').trim();
    const ridge = css.getPropertyValue('--ridge').trim();
    const peak = Math.max(64 * 1024, ...history.map((p) => Math.max(p[0], p[1])));
    const x = (i) => i * (w - 2) / (history.length - 1) + 1;
    const y = (v) => h - 3 - (v / peak) * (h - 10);

    g.strokeStyle = ridge; g.lineWidth = 1;
    g.beginPath(); g.moveTo(0, h - 2.5); g.lineTo(w, h - 2.5); g.stroke();

    const line = (idx) => { g.beginPath(); history.forEach((p, i) => (i ? g.lineTo(x(i), y(p[idx])) : g.moveTo(x(i), y(p[idx])))); };
    line(0); g.lineTo(x(history.length - 1), h - 3); g.lineTo(x(0), h - 3); g.closePath();
    g.fillStyle = teal + '2e'; g.fill();
    line(0); g.strokeStyle = teal; g.lineWidth = 3; g.lineJoin = 'round'; g.stroke();
    line(1); g.strokeStyle = fog; g.lineWidth = 2; g.stroke();
  }

  function renderControls() {
    for (const b of document.querySelectorAll('#seg-mode button')) {
      const active = b.dataset.mode === S.mode;
      b.classList.toggle('active', active);
      b.setAttribute('aria-checked', active);
    }
    $('mode-desc').textContent = S.mode === 'global'
      ? 'Напрямую идёт только твоя локальная сеть.'
      : 'Сайты .ru, .su, .рф и адреса в России идут напрямую.';
    const sysOk = S.platform === 'win32';
    $('sw-sys').checked = !!S.settings.sysproxy;
    $('sw-sys').disabled = !sysOk;
    $('sys-hint').textContent = !sysOk ? 'Работает только в Windows.'
      : S.settings.sysproxy ? 'Браузеры и большинство программ пойдут через клиент сами.'
        : 'Выключено: работают только программы с адресом, указанным вручную.';
    $('cp-socks').textContent = 'SOCKS5 127.0.0.1:' + S.settings.socks_port;
    $('cp-http').textContent = 'HTTP 127.0.0.1:' + S.settings.http_port;
    $('ver').textContent = S.version;
    const root = document.documentElement;
    if (root.dataset.theme !== S.settings.theme) { root.dataset.theme = S.settings.theme; }
    if (root.dataset.accent !== S.settings.accent) { root.dataset.accent = S.settings.accent; }
    for (const b of document.querySelectorAll('#st-theme button')) b.classList.toggle('active', b.dataset.theme === S.settings.theme);
    for (const b of document.querySelectorAll('#st-accent button')) b.classList.toggle('active', b.dataset.accent === S.settings.accent);

    const inst = S.core.install;
    $('st-core').textContent = S.core.installed ? 'версия ' + (S.core.version || '?') : 'не установлено';
    $('st-bar').style.width = (inst.running ? inst.pct : 0) + '%';
    $('st-install').disabled = inst.running || S.connected;
    $('st-install').textContent = inst.running ? 'Скачиваю… ' + inst.pct + '%' : S.core.installed ? 'Обновить ядро' : 'Скачать ядро';
    $('st-dir').textContent = S.data_dir;
    $('btn-best').disabled = $('btn-ping').dataset.busy === '1' || S.servers.length < 2;
    const up = $('btn-update');
    up.classList.toggle('hidden', !S.update);
    if (S.update) up.textContent = 'Доступна версия ' + S.update.version;
  }

  function render() { renderServers(); renderRoute(); renderControls(); }

  // ---------- journal ----------
  function appendLogs(lines) {
    if (!lines.length) return;
    const box = $('log');
    const stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 24;
    let last = null;
    for (const l of lines) {
      since = Math.max(since, l.n);
      let level = '';
      if (/\[error\]|failed to start|не удалось|ошибка|не отвечает|завершился/i.test(l.text)) level = ' err';
      else if (/\[warning\]/i.test(l.text) && !/core: Xray .* started/.test(l.text)) level = ' warn';
      const row = el('span', 'ln ' + l.src + level);
      row.append(el('span', 'ts', l.ts));
      const tx = el('span', 'tx');
      // colour the route of each connection the same way as the diagram
      const m = l.text.match(/^(.*)(\[[^\]]*(>>|->) (proxy|direct)\])(.*)$/);
      if (m) {
        tx.append(m[1], el('span', m[4] === 'proxy' ? 'via-proxy' : 'via-direct', m[2]), m[5]);
      } else tx.textContent = l.text;
      row.append(tx);
      box.append(row);
      if (l.src !== 'xray' || level) last = { text: l.text, err: level === ' err' };
    }
    while (box.childElementCount > MAX_LOG_LINES) box.firstElementChild.remove();
    if (stick) box.scrollTop = box.scrollHeight;
    if (last) {
      $('j-last').textContent = last.text;
      $('j-last').classList.toggle('err', last.err);
    }
  }

  function setJournal(open) {
    $('journal').classList.toggle('open', open);
    $('j-toggle').setAttribute('aria-expanded', open);
    prefs.set('journal', open ? '1' : '0');
    if (open) $('log').scrollTop = $('log').scrollHeight;
  }

  // ---------- polling (also acts as the heartbeat) ----------
  async function refreshNow() {
    const r = await api('poll', { since });
    S = r.state; appendLogs(r.logs); render();
  }

  async function poll() {
    try {
      await refreshNow();
      failures = 0;
      if (offlineToast) { offlineToast.remove(); offlineToast = null; }
    } catch (e) {
      failures += 1;
      if (failures === 3 && !offlineToast) {
        offlineToast = toast('Программа не отвечает. Скорее всего, она закрыта. Закрой это окно и запусти её заново.', 'err', 0);
      }
    }
    setTimeout(poll, 1000);
  }

  // ---------- actions ----------
  async function withPending(fn) {
    pending = true; if (S) render();
    try { await fn(); } finally { pending = false; }
    await refreshNow();
  }

  function connectTo(id) {
    if (pending || (S.connected && S.selected === id)) return;
    act(() => withPending(() => api('connect', { id })));
  }

  $('btn-connect').addEventListener('click', () => act(() => {
    if (S.reconnecting || S.connected) return withPending(() => api('disconnect'));
    return withPending(() => api('connect'));
  }));

  for (const b of document.querySelectorAll('#seg-mode button')) {
    b.addEventListener('click', () => act(() => {
      if (b.dataset.mode === S.mode) return null;
      return S.connected ? withPending(() => api('set_mode', { mode: b.dataset.mode }))
        : api('set_mode', { mode: b.dataset.mode }).then(refreshNow);
    }));
  }

  $('sw-sys').addEventListener('change', (e) => act(async () => {
    try { await api('set_settings', { sysproxy: e.target.checked }); }
    finally { await refreshNow(); }
  }));

  $('btn-speed').addEventListener('click', async () => {
    const b = $('btn-speed'), out = $('speed-out');
    b.disabled = true; b.dataset.busy = '1'; out.className = ''; out.textContent = 'Качаю тестовый файл, около 8 секунд…';
    try { await api('speedtest'); await refreshNow(); }
    catch (e) { out.className = 'bad'; out.textContent = e.message; out.dataset.err = '1'; }
    finally { b.dataset.busy = ''; b.disabled = !S.connected; }
  });

  $('cp-socks').addEventListener('click', () => copyText('127.0.0.1:' + S.settings.socks_port, 'Адрес SOCKS5 скопирован'));
  $('cp-http').addEventListener('click', () => copyText('127.0.0.1:' + S.settings.http_port, 'Адрес HTTP скопирован'));

  async function busyButton(btn, label, fn) {
    const old = btn.textContent;
    btn.disabled = true; btn.dataset.busy = '1'; btn.textContent = label;
    try { return await fn(); }
    finally { btn.disabled = false; btn.dataset.busy = ''; btn.textContent = old; await refreshNow().catch(() => {}); }
  }

  $('btn-ping').addEventListener('click', () => act(() => busyButton($('btn-ping'), 'Проверяю…', async () => {
    await api('ping', { id: 'all' });          // quick: is the server there at all
    await refreshNow();
    if (S.core.installed) await api('real_ping', { id: 'all' });   // slower: does the tunnel work
    else toast('Пока измерен только отклик серверов. Проверка через туннель заработает после первого подключения.');
  })));
  $('btn-best').addEventListener('click', () => act(() => busyButton($('btn-best'), 'Ищу…', async () => {
    const r = await api('select_best');
    toast('Выбран самый быстрый сервер: ' + r.ms + ' мс');
  })));

  $('search').addEventListener('input', () => { if (S) renderServers(); });
  $('sort').value = prefs.get('sort', 'order');
  $('sort').addEventListener('change', () => { prefs.set('sort', $('sort').value); if (S) renderServers(); });

  $('btn-quit').addEventListener('click', async () => {
    try { await api('quit'); } catch (_) { /* the server is going away */ }
    document.body.replaceChildren(el('p', 'empty', 'Программа закрыта. Это окно можно закрыть.'));
  });

  // ---------- import ----------
  async function importText(text, quiet) {
    const r = await api('add_links', { text });
    await refreshNow();
    if (r.added) toast('Добавлено серверов: ' + r.added);
    if (r.skipped.length && !quiet) toast('Пропущено:\n' + r.skipped.slice(0, 6).join('\n'), 'err');
    if (!r.added && !r.skipped.length) toast('В тексте нет ссылок на серверы и адресов подписки.', 'err');
    return r;
  }

  async function pasteFromClipboard() {
    let text = '';
    try { text = await navigator.clipboard.readText(); }
    catch (_) { toast('Браузер не дал прочитать буфер. Нажми Ctrl+V прямо в этом окне.', 'err'); return; }
    if (!/(vless|trojan|ss|vmess):\/\/|https?:\/\//i.test(text)) { toast('В буфере обмена нет ссылки на сервер или адреса подписки.', 'err'); return; }
    await act(() => importText(text));
  }

  document.addEventListener('paste', (e) => {
    const tag = (e.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea') return;
    const text = (e.clipboardData || window.clipboardData).getData('text') || '';
    if (!/(vless|trojan|ss|vmess):\/\/|https?:\/\//i.test(text)) { toast('В буфере обмена нет ссылки на сервер или адреса подписки.', 'err'); return; }
    e.preventDefault();
    act(() => importText(text));
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !/input|textarea|select/i.test(e.target.tagName) && !document.querySelector('dialog[open]')) {
      e.preventDefault(); $('search').focus();
    }
  });

  const dlgAdd = $('dlg-add');
  const openAdd = () => {
    $('add-text').value = '';
    $('add-result').classList.add('hidden');
    dlgAdd.showModal();
    $('add-text').focus();
  };
  $('btn-add').addEventListener('click', openAdd);
  $('empty-manual').addEventListener('click', openAdd);
  $('empty-paste').addEventListener('click', pasteFromClipboard);
  $('add-cancel').addEventListener('click', () => dlgAdd.close());
  $('add-paste').addEventListener('click', async () => {
    try { $('add-text').value = await navigator.clipboard.readText(); }
    catch (_) { toast('Браузер не дал прочитать буфер. Вставь вручную: Ctrl+V.', 'err'); }
  });
  $('add-ok').addEventListener('click', () => act(async () => {
    const text = $('add-text').value;
    if (!text.trim()) return;
    const b = $('add-ok'); b.disabled = true; b.textContent = 'Добавляю…';
    try {
      const r = await importText(text, true);
      if (r.skipped.length) {
        const box = $('add-result');
        box.textContent = 'Добавлено: ' + r.added + '\nПропущено:\n  ' + r.skipped.join('\n  ');
        box.classList.remove('hidden');
      } else if (r.added) dlgAdd.close();
    } finally { b.disabled = false; b.textContent = 'Добавить'; }
  }));

  // ---------- help ----------
  $('btn-help').addEventListener('click', () => {
    $('help-close-note').textContent = S && S.tray && S.settings.close_to_tray
      ? 'Закрытие окна не выключает программу: она остаётся в трее возле часов. Полностью выйти можно кнопкой «Выйти» или из меню значка.'
      : 'Закрытие окна отключает соединение и возвращает настройки прокси Windows.';
    $('dlg-help').showModal();
  });

  $('btn-update').addEventListener('click', () => act(() => api('open_update')));

  // ---------- site check ----------
  const dlgSite = $('dlg-site');
  let siteHost = '';
  const siteLine = (row, out, r, note) => {
    row.classList.remove('ok', 'fail');
    if (!r) { out.textContent = 'не проверялось: ' + (note || 'нет сервера'); return; }
    row.classList.add(r.ok ? 'ok' : 'fail');
    out.textContent = r.ok ? 'отвечает за ' + r.ms + ' мс (код ' + r.status + ')' : r.error;
  };
  async function checkSite(target) {
    const value = (target || $('site-input').value).trim();
    if (!value) { $('site-input').focus(); return; }
    $('site-input').value = value;
    const go = $('site-go');
    go.disabled = true; go.textContent = 'Проверяю…';
    try {
      const r = await api('check_site', { target: value });
      siteHost = r.host;
      siteLine(document.querySelector('.site-line.direct'), $('site-direct'), r.direct);
      siteLine(document.querySelector('.site-line.server'), $('site-server'), r.server, r.server_note);
      $('site-server-name').textContent = r.server_name ? 'Через ' + r.server_name : 'Через сервер';
      const texts = {
        both: 'Сайт открывается обоими путями.',
        server_only: 'Напрямую сайт не открывается, через сервер работает. Чтобы он всегда шёл через сервер, добавь правило.',
        direct_only: 'Напрямую работает, а через сервер нет. Возможно, сайт не пускает этот сервер. Его можно всегда открывать напрямую.',
        none: 'Сайт не отвечает ни напрямую, ни через сервер. Похоже, проблема на стороне сайта.',
        direct: 'Напрямую работает. Через сервер проверить не удалось.',
        direct_fail: 'Напрямую не открывается. Через сервер проверить не удалось.',
      };
      $('site-verdict').textContent = texts[r.verdict] || '';
      $('site-rule-proxy').classList.toggle('primary', r.verdict === 'server_only');
      $('site-rule-direct').classList.toggle('primary', r.verdict === 'direct_only');
      document.querySelector('.site-actions').classList.toggle('hidden', r.verdict === 'none');
      $('site-result').classList.remove('hidden');
    } finally { go.disabled = false; go.textContent = 'Проверить'; }
  }
  $('btn-site').addEventListener('click', () => { dlgSite.showModal(); $('site-input').focus(); });
  $('site-close').addEventListener('click', () => dlgSite.close());
  $('site-go').addEventListener('click', () => act(() => checkSite()));
  $('site-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); act(() => checkSite()); } });
  for (const b of document.querySelectorAll('#site-presets .chip')) {
    b.addEventListener('click', () => act(() => checkSite(b.dataset.site)));
  }
  const addRule = (route, label) => act(async () => {
    if (!siteHost) return;
    await api('add_rule', { host: siteHost, route });
    await refreshNow();
    toast(siteHost + ': теперь всегда ' + label);
  });
  $('site-rule-proxy').addEventListener('click', () => addRule('proxy', 'через сервер'));
  $('site-rule-direct').addEventListener('click', () => addRule('direct', 'напрямую'));
  $('help-close').addEventListener('click', () => $('dlg-help').close());

  // ---------- settings ----------
  const dlgSet = $('dlg-settings');
  $('btn-settings').addEventListener('click', () => {
    if (!S) return;
    const s = S.settings;
    $('st-auto-connect').checked = s.auto_connect;
    $('st-autostart').checked = s.autostart;
    $('st-autostart-row').classList.toggle('hidden', !s.autostart_available);
    $('st-sub-update').checked = s.sub_auto_update;
    $('st-tray').checked = s.close_to_tray;
    $('st-notify').checked = s.notifications;
    $('st-notify-row').classList.toggle('hidden', !S.tray);
    const box = $('st-presets');
    box.replaceChildren();
    for (const [key, title] of Object.entries(S.presets)) {
      const label = el('label', 'check');
      const input = el('input');
      input.type = 'checkbox'; input.dataset.preset = key; input.checked = s.presets.includes(key);
      label.append(input, el('span', '', title));
      box.append(label);
    }
    $('st-tray-row').classList.toggle('hidden', !S.tray);
    $('st-reconnect').checked = s.auto_reconnect;
    $('st-failover').checked = s.failover;
    $('st-direct').value = s.direct_domains.join('\n');
    $('st-proxy').value = s.proxy_domains.join('\n');
    $('st-socks').value = s.socks_port;
    $('st-http').value = s.http_port;
    $('st-level').value = s.loglevel;
    $('st-conns').checked = s.show_connections;
    dlgSet.showModal();
  });
  $('st-cancel').addEventListener('click', () => dlgSet.close());
  // look & feel applies at once, without "Save"
  for (const b of document.querySelectorAll('#st-theme button')) {
    b.addEventListener('click', () => act(() => api('set_settings', { theme: b.dataset.theme }).then(refreshNow)));
  }
  for (const b of document.querySelectorAll('#st-accent button')) {
    b.addEventListener('click', () => act(() => api('set_settings', { accent: b.dataset.accent }).then(refreshNow)));
  }
  $('st-save').addEventListener('click', () => act(async () => {
    const b = $('st-save'); b.disabled = true;
    try {
      const changes = {
        auto_connect: $('st-auto-connect').checked,
        sub_auto_update: $('st-sub-update').checked,
        close_to_tray: $('st-tray').checked,
        notifications: $('st-notify').checked,
        presets: [...document.querySelectorAll('#st-presets input:checked')].map((i) => i.dataset.preset),
        auto_reconnect: $('st-reconnect').checked,
        failover: $('st-failover').checked,
        direct_domains: $('st-direct').value.split('\n'),
        proxy_domains: $('st-proxy').value.split('\n'),
        socks_port: parseInt($('st-socks').value, 10),
        http_port: parseInt($('st-http').value, 10),
        loglevel: $('st-level').value,
        show_connections: $('st-conns').checked,
      };
      if (S.settings.autostart_available && $('st-autostart').checked !== S.settings.autostart) {
        changes.autostart = $('st-autostart').checked;
      }
      await api('set_settings', changes);
      dlgSet.close();
      toast('Настройки сохранены');
    } finally { b.disabled = false; await refreshNow().catch(() => {}); }
  }));
  $('st-install').addEventListener('click', () => act(() => api('install_core').then(refreshNow)));
  $('st-folder').addEventListener('click', () => act(() => api('open_data_dir')));

  // ---------- journal controls ----------
  $('j-toggle').addEventListener('click', () => setJournal(!$('journal').classList.contains('open')));
  $('j-last').addEventListener('click', () => setJournal(true));
  for (const b of document.querySelectorAll('#j-filter button')) {
    b.addEventListener('click', () => {
      for (const x of document.querySelectorAll('#j-filter button')) x.classList.toggle('active', x === b);
      $('log').className = 'logbox' + (b.dataset.f === 'all' ? '' : ' f-' + b.dataset.f);
    });
  }
  $('j-copy').addEventListener('click', () => {
    const text = [...$('log').children].map((r) => r.textContent.replace(/^(\d\d:\d\d:\d\d)/, '$1 ')).join('\n');
    copyText(text, 'Журнал скопирован');
  });
  $('j-clear').addEventListener('click', () => { $('log').replaceChildren(); $('j-last').textContent = ''; });
  setJournal(prefs.get('journal', '0') === '1');

  setInterval(() => { if (S && S.connected && !S.connecting) renderStatus(S.core.install.running, pending || S.reconnecting, true, S.health.fails >= 3); }, 1000);
  poll();
})();

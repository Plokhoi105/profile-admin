const state = {
  accounts: [], countries: new Map(), selected: new Set(), rotating: new Set(), syncing: new Set(), creating: new Set(), deletingVision: new Set(), checkingFraud: new Set(),
  editAccountId: null, deleteAccountId: null, deleteVisionAccountId: null, permanentDeleteAccountId: null, countryAccountId: null, authenticatorAccountId: null,
  proxyAccountId: null, proxyTargetCountry: "", bulkActionIds: [], bulkCreateIds: [], jobId: null, poll: null,
  totpCodes: new Map(), totpPoll: null, codesHidden: localStorage.getItem("profile-admin-codes-hidden") === "1",
};
const $ = (selector) => document.querySelector(selector);
const accountsBody = $("#accounts");

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message; node.classList.add("show"); clearTimeout(node._timer);
  const duration = String(message).startsWith("Предупреждение:") ? 9000 : 3800;
  node._timer = setTimeout(() => node.classList.remove("show"), duration);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (character) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"})[character]);
}

function statusLabel(status) {
  return ({ready:"Не создан",not_created:"Не создан",queued:"В очереди",running:"Создается",created:"Создан",pending_sync:"Ждет синхронизации",rotating:"Смена прокси",deleting:"Удаляется",error:"Ошибка",interrupted:"Прерван"})[status] || status;
}

function countryName(code) { return state.countries.get(String(code).toLowerCase()) || String(code).toUpperCase() || "Без страны"; }
function actualName(account) { return `${account.profile_name} ${countryName(account.country)}`; }
function syncedAt(value) {
  if (!value) return "Не проверен";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : `Проверено ${date.toLocaleString("ru-RU")}`;
}

function visionSyncedAt(value) {
  if (!value) return "Vision · синхронизация не проверена";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? `Vision · ${value}` : `Vision · синхронизировано ${date.toLocaleString("ru-RU")}`;
}

function fraudZone(score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

function fraudScore(account) {
  if (!account.vision_proxy_id && !account.proxy_endpoint) return "";
  const score = Number(account.fraud_score);
  const checked = Number.isInteger(score) && score >= 0 && score <= 100;
  const width = checked ? score : 0;
  const zone = checked ? ` fraud-zone-${fraudZone(score)}` : "";
  return `<div class="fraud-score${checked ? " checked" : ""}">
    <div class="fraud-score-head"><span>Fraud score${account.fraud_ip ? ` · ${escapeHtml(account.fraud_ip)}` : ""}</span><strong class="${zone.trim()}">${checked ? score : "—"}</strong></div>
    <progress class="fraud-track${zone}" aria-label="Fraud score" value="${width}" max="100">${width}%</progress>
    <small>${checked ? `${escapeHtml(account.fraud_risk || "")}${account.fraud_checked_at ? ` · ${escapeHtml(syncedAt(account.fraud_checked_at))}` : ""}` : "Еще не проверен"}</small>
  </div>`;
}

function proxyActionButton({ className, icon, label, disabled = false, working = false }) {
  return `<button class="proxy-icon-action ${className}${working ? " is-working" : ""}" type="button" title="${escapeHtml(label)}" aria-label="${escapeHtml(label)}" ${disabled ? "disabled" : ""}><span aria-hidden="true">${icon}</span></button>`;
}

function filteredAccounts() {
  const query = $("#search").value.trim().toLowerCase();
  const status = $("#status-filter").value;
  return state.accounts.filter((account) => {
    const normalizedStatus = ["ready", "not_created"].includes(account.status) ? "not_created" : account.status;
    const haystack = [actualName(account), account.email, account.country, account.proxy_endpoint].join(" ").toLowerCase();
    return (!query || haystack.includes(query)) && (!status || normalizedStatus === status);
  });
}

function renderMetrics() {
  const count = (statuses) => state.accounts.filter((item) => statuses.includes(item.status)).length;
  $("#metric-created").textContent = count(["created"]);
  $("#metric-pending").textContent = count(["pending_sync"]);
  $("#metric-missing").textContent = count(["ready", "not_created"]);
  $("#metric-errors").textContent = count(["error", "interrupted"]);
}

function render() {
  const visible = filteredAccounts();
  accountsBody.innerHTML = visible.map((account) => {
    const rotating = state.rotating.has(account.id) || account.status === "rotating";
    const syncing = state.syncing.has(account.id);
    const creating = state.creating.has(account.id);
    const deletingVision = state.deletingVision.has(account.id);
    const checkingFraud = state.checkingFraud.has(account.id);
    const busy = ["queued", "running", "rotating", "deleting"].includes(account.status) || deletingVision;
    const canSync = Boolean(account.vision_profile_id) && account.status === "pending_sync" && !busy && !syncing;
    const canCreate = !account.vision_profile_id && ["ready", "not_created"].includes(account.status) && !busy && !creating;
    const canRotate = ["created", "pending_sync"].includes(account.status) && account.vision_profile_id && !rotating && !syncing;
    const hasProxy = Boolean(account.vision_proxy_id || account.proxy_endpoint);
    const totp = state.totpCodes.get(account.id);
    return `<tr data-id="${account.id}" title="${escapeHtml(account.error || "")}">
      <td><input class="row-select" type="checkbox" aria-label="Выбрать ${escapeHtml(actualName(account))}" ${state.selected.has(account.id) ? "checked" : ""}></td>
      <td><div class="profile-cell"><div><button class="profile-copy" type="button" title="Копировать email и код" aria-label="Копировать email и код профиля ${escapeHtml(actualName(account))}"><strong>${escapeHtml(actualName(account))}</strong></button></div><button class="edit-account icon-small" title="Редактировать" aria-label="Редактировать">✎</button></div></td>
      <td class="email-cell"><button class="inline-copy copy-email" type="button" title="Копировать email" aria-label="Копировать email ${escapeHtml(account.email)}">${escapeHtml(account.email)}</button><button class="emails-btn icon-small" type="button" title="Входящие письма" aria-label="Входящие письма">✉</button></td>
      <td class="code-value${state.codesHidden ? " is-hidden" : ""}">${account.code ? `<button class="inline-copy copy-code" type="button" title="Копировать код" aria-label="Копировать код профиля ${escapeHtml(actualName(account))}">${escapeHtml(state.codesHidden ? "••••••" : account.code)}</button>` : "—"}</td>
      <td class="totp-cell" data-totp-id="${account.id}">${account.has_authenticator
        ? `<div class="totp-value"><strong>${escapeHtml(totp?.code || "------")}</strong><small>${totp ? `${totp.remaining}с` : ""}</small></div><div class="totp-actions"><button class="copy-totp" ${totp ? "" : "disabled"}>Копировать</button><button class="setup-authenticator">Изменить</button></div>`
        : '<button class="setup-authenticator">Добавить ключ</button>'}</td>
      <td class="os-cell">${account.fingerprint_os === "mac" ? "macOS" : "Win"}</td>
      <td><span class="status status-${escapeHtml(account.status)}">${escapeHtml(statusLabel(account.status))}</span></td>
      <td class="proxy-endpoint" title="${hasProxy ? "Прокси назначен" : "Прокси не назначен"}">
        <div class="proxy-value">${hasProxy ? "Прокси назначен" : "Не назначен"}</div>${hasProxy ? `<small class="vision-sync-state${account.status === "pending_sync" ? " pending" : ""}">${escapeHtml(account.status === "pending_sync" ? "Vision · ожидает синхронизации изменений" : visionSyncedAt(account.last_synced_at))}</small>` : ""}
        ${fraudScore(account)}
        <div class="proxy-actions" aria-label="Действия с прокси">
          ${hasProxy ? proxyActionButton({ className: "copy-proxy", icon: "&#10697;", label: "Копировать прокси" }) : ""}
          ${proxyActionButton({ className: "rotate-proxy", icon: rotating ? "&#8230;" : "&#8635;", label: rotating ? "Прокси меняется" : "Новый прокси в той же стране", disabled: !canRotate, working: rotating })}
          ${proxyActionButton({ className: "change-country", icon: "&#9678;", label: "Сменить страну прокси", disabled: !canRotate })}
          ${proxyActionButton({ className: "check-fraud", icon: checkingFraud ? "&#8230;" : "&#9672;", label: checkingFraud ? "Fraud score проверяется" : "Проверить fraud score", disabled: !account.vision_proxy_id || busy || checkingFraud, working: checkingFraud })}
          ${hasProxy ? proxyActionButton({ className: "ip-history-btn", icon: "&#9776;", label: "История IP и fraud score" }) : ""}
        </div>
      </td>
      <td class="actions-cell"><div class="row-icon-actions">
        <button class="sync-one sync-icon" title="${canSync ? "Синхронизировать изменения с Vision" : "Нет несинхронизированных изменений"}" aria-label="Синхронизировать ${escapeHtml(actualName(account))}" ${canSync ? "" : "disabled"}>${syncing ? "…" : "↻"}</button>
        <button class="create-one create-icon" title="Создать профиль в Vision" aria-label="Создать ${escapeHtml(actualName(account))} в Vision" ${canCreate ? "" : "disabled"}>${creating ? "…" : "+"}</button>
        <button class="delete-vision-one delete-vision-icon" title="Удалить профиль из Vision" aria-label="Удалить ${escapeHtml(actualName(account))} из Vision" ${account.vision_profile_id && !busy ? "" : "disabled"}>${deletingVision ? "…" : "×"}</button>
        <button class="permanent-delete-one permanent-delete-icon" title="Удалить не созданный профиль навсегда" aria-label="Навсегда удалить ${escapeHtml(actualName(account))} из панели" ${!account.vision_profile_id && !busy ? "" : "disabled"}>⌫</button>
      </div></td>
    </tr>`;
  }).join("");
  $("#empty").hidden = visible.length > 0;
  $("#summary").textContent = `${state.accounts.length} аккаунтов`;
  $("#selected-count").textContent = `Выбрано: ${state.selected.size}`;
  $("#toggle-codes").textContent = state.codesHidden ? "Показать коды" : "Скрыть коды";
  $("#toggle-codes").setAttribute("aria-pressed", String(state.codesHidden));
  const selectedAccounts = state.accounts.filter((account) => state.selected.has(account.id));
  const available = (account) => !["queued", "running", "rotating", "deleting"].includes(account.status);
  const pendingAccounts = state.accounts.filter((account) => account.vision_profile_id && account.status === "pending_sync" && available(account));
  const selectedPending = selectedAccounts.filter((account) => account.vision_profile_id && account.status === "pending_sync" && available(account));
  const syncTargets = state.selected.size ? selectedPending : pendingAccounts;
  $("#sync-profiles").textContent = `Синхронизировать изменения (${syncTargets.length})`;
  $("#sync-profiles").disabled = syncTargets.length === 0;
  $("#bulk-sync").disabled = selectedPending.length === 0;
  $("#create-profiles").disabled = !selectedAccounts.some((account) => !account.vision_profile_id && ["ready", "not_created"].includes(account.status));
  const fraudTargets = (state.selected.size ? selectedAccounts : state.accounts).filter((account) => account.vision_proxy_id && available(account) && !state.checkingFraud.has(account.id));
  $("#bulk-fraud-check").disabled = fraudTargets.length === 0;
  const badProxies = (state.selected.size ? selectedAccounts : state.accounts).filter((account) => account.vision_profile_id && account.fraud_score >= 25 && available(account) && !state.rotating.has(account.id));
  $("#bulk-rotate-bad").disabled = badProxies.length === 0;
  $("#bulk-delete-vision").disabled = !selectedAccounts.some((account) => account.vision_profile_id && available(account));
  $("#bulk-permanent-delete").disabled = !selectedAccounts.some((account) => !account.vision_profile_id && available(account));
  const visibleIds = visible.map((account) => account.id);
  const selectedVisible = visibleIds.filter((id) => state.selected.has(id)).length;
  $("#select-all").checked = visibleIds.length > 0 && selectedVisible === visibleIds.length;
  $("#select-all").indeterminate = selectedVisible > 0 && selectedVisible < visibleIds.length;
  renderMetrics();
}

async function loadAccounts() {
  const data = await api("/api/accounts"); state.accounts = data.accounts;
  const validIds = new Set(state.accounts.map((account) => account.id));
  state.selected = new Set([...state.selected].filter((id) => validIds.has(id)));
  render();
}

async function loadTrash(renderList = false) {
  const data = await api("/api/trash");
  $("#trash-count").textContent = data.accounts.length;
  if (!renderList) return;
  $("#trash-list").innerHTML = data.accounts.length ? data.accounts.map((account) => `
    <div class="trash-item" data-id="${account.trash_id}">
      <div><strong>${escapeHtml(actualName(account))}</strong><small>${escapeHtml(account.email)} · ${escapeHtml(statusLabel(account.status || "not_created"))}</small></div>
      <button class="restore-account">Восстановить</button>
    </div>`).join("") : '<div class="trash-empty">Корзина пуста</div>';
}

async function loadCountries() {
  const data = await api("/api/countries");
  state.countries = new Map(data.countries.map((country) => [country.code, country.name]));
  $("#countries").replaceChildren(...data.countries.map((country) => {
    const option = document.createElement("option"); option.value = country.code; option.label = country.name; return option;
  })); render();
}

accountsBody.addEventListener("change", (event) => {
  if (!event.target.classList.contains("row-select")) return;
  const id = Number(event.target.closest("tr").dataset.id);
  event.target.checked ? state.selected.add(id) : state.selected.delete(id); render();
});

accountsBody.addEventListener("click", async (event) => {
  const row = event.target.closest("tr"); if (!row) return;
  const id = Number(row.dataset.id);
  if (event.target.closest(".profile-copy")) {
    const account = state.accounts.find((item) => item.id === id);
    if (account) return copyText(actualName(account), "Название скопировано");
  }
  if (event.target.closest(".edit-account")) return openEdit(id);
  if (event.target.closest(".sync-one")) return syncOne(id);
  if (event.target.closest(".create-one")) return createOne(id);
  if (event.target.closest(".delete-vision-one")) return openDeleteVision(id);
  if (event.target.closest(".permanent-delete-one")) return openPermanentDelete(id);
  if (event.target.closest(".check-fraud")) return checkFraud(id);
  if (event.target.closest(".setup-authenticator")) return openAuthenticator(id);
  if (event.target.closest(".copy-totp")) return copyTotp(id);
  if (event.target.closest(".copy-email")) {
    const account = state.accounts.find((item) => item.id === id);
    if (account) return copyEmailAndCode(account);
  }
  if (event.target.closest(".copy-code")) {
    const account = state.accounts.find((item) => item.id === id);
    if (account?.code) return copyText(account.code, "Код скопирован");
  }
  if (event.target.closest(".copy-proxy")) return copyProxy(id);
  if (event.target.closest(".ip-history-btn")) return openIpHistory(id);
  if (event.target.closest(".emails-btn")) return openEmails(id);
  if (event.target.closest(".change-country")) {
    const account = state.accounts.find((item) => item.id === id); state.countryAccountId = id;
    $("#proxy-country").value = account?.country || ""; $("#country-dialog").showModal(); return;
  }
  if (event.target.closest(".rotate-proxy")) openProxyConfirmation(id, "");
});

function openEdit(id) {
  const account = state.accounts.find((item) => item.id === id); if (!account) return;
  state.editAccountId = id; $("#edit-name").value = account.profile_name; $("#edit-email").value = account.email;
  $("#edit-code").value = account.code; $("#edit-country").value = account.country; $("#edit-os").value = account.fingerprint_os;
  $("#edit-os").disabled = Boolean(account.vision_profile_id); $("#edit-dialog").showModal();
}

async function rotateProxy(id, country) {
  state.rotating.add(id); render();
  try {
    await api(`/api/accounts/${id}/rotate-proxy`, {method:"POST", body:JSON.stringify(country ? {country} : {})});
    toast(country ? "Страна и прокси изменены" : "Прокси заменен");
  } catch (error) { toast(error.message); }
  finally { state.rotating.delete(id); await loadAccounts(); }
}

async function copyProxy(id) {
  const account = state.accounts.find((item) => item.id === id);
  if (!account?.vision_proxy_id) return toast("Прокси не назначен");
  try {
    const result = await api(`/api/accounts/${id}/proxy-credentials`, {method:"POST", body:"{}"});
    if (!result.proxy) throw new Error("Vision не вернул данные прокси");
    await copyText(result.proxy, "Прокси с паролем скопирован");
  } catch (error) {
    toast(error.message);
  }
}

async function writeClipboard(value) {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    const field = document.createElement("textarea");
    field.value = value; field.setAttribute("readonly", "");
    field.className = "clipboard-fallback"; document.body.append(field); field.select();
    const copied = document.execCommand("copy"); field.remove();
    return copied;
  }
}

async function copyText(value, successMessage) {
  toast(await writeClipboard(value) ? successMessage : "Не удалось скопировать");
}

async function copyProfileCredentials(account) {
  if (!account.code) return copyText(account.email, "Email скопирован, код не задан");
  const codeCopied = await writeClipboard(account.code);
  await new Promise((resolve) => setTimeout(resolve, 350));
  const emailCopied = await writeClipboard(account.email);
  toast(codeCopied && emailCopied ? "Email и код добавлены в историю буфера" : "Не удалось скопировать email и код");
}

async function copyEmailAndCode(account) {
  if (!account.code) return copyText(account.email, "Email скопирован, код не задан");
  const codeCopied = await writeClipboard(account.code);
  await new Promise((resolve) => setTimeout(resolve, 350));
  const emailCopied = await writeClipboard(account.email);
  toast(codeCopied && emailCopied ? "Код и email добавлены в историю буфера" : "Не удалось скопировать");
}

function openAuthenticator(id) {
  const account = state.accounts.find((item) => item.id === id); if (!account) return;
  state.authenticatorAccountId = id;
  $("#authenticator-title").textContent = `${account.has_authenticator ? "Изменить" : "Добавить"} аутентификатор`;
  $("#authenticator-secret").value = ""; $("#authenticator-dialog").showModal();
}

function copyTotp(id) {
  const totp = state.totpCodes.get(id);
  if (totp?.code) copyText(totp.code, "Код скопирован");
}

function updateTotpCells() {
  document.querySelectorAll("[data-totp-id]").forEach((cell) => {
    const totp = state.totpCodes.get(Number(cell.dataset.totpId));
    const code = cell.querySelector(".totp-value strong");
    const remaining = cell.querySelector(".totp-value small");
    const copy = cell.querySelector(".copy-totp");
    if (code) code.textContent = totp?.code || "------";
    if (remaining) remaining.textContent = totp ? `${totp.remaining}с` : "";
    if (copy) copy.disabled = !totp;
  });
}

async function loadAuthenticatorCodes() {
  if (!state.accounts.some((account) => account.has_authenticator)) {
    state.totpCodes.clear(); updateTotpCells(); return;
  }
  try {
    const data = await api("/api/authenticator/codes");
    state.totpCodes = new Map(data.codes.map((item) => [item.id, item])); updateTotpCells();
  } catch (error) { clearInterval(state.totpPoll); state.totpPoll = null; toast(error.message); }
}

async function syncOne(id) {
  state.syncing.add(id); render();
  try {
    const result = await api("/api/sync", {method:"POST", body:JSON.stringify({push_changes:true, account_ids:[id]})});
    await loadAccounts();
    toast(result.failed ? "Не удалось синхронизировать профиль" : result.missing ? "Профиль не найден в Vision" : "Профиль синхронизирован");
  } catch (error) { toast(error.message); }
  finally { state.syncing.delete(id); render(); }
}

async function createOne(id) {
  state.creating.add(id); render();
  try {
    const data = await api("/api/jobs", {method:"POST", body:JSON.stringify({account_ids:[id], country:"", fingerprint_os:""})});
    toast(`Создание профиля запущено · задание #${data.job_id}`);
    await loadAccounts();
    pollSingleJob(data.job_id, id);
  } catch (error) {
    state.creating.delete(id); render(); toast(error.message);
  }
}

async function checkFraud(id) {
  state.checkingFraud.add(id); render();
  try {
    await api(`/api/accounts/${id}/fraud-check`, {method:"POST", body:"{}"});
    await loadAccounts(); toast("Fraud score обновлен");
  } catch (error) { toast(error.message); }
  finally { state.checkingFraud.delete(id); render(); }
}

function ipHistoryScoreZone(score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 25) return "medium";
  return "low";
}

async function openIpHistory(id) {
  const account = state.accounts.find((a) => a.id === id);
  if (!account) return;
  $("#ip-history-subtitle").textContent = `${actualName(account)} · ${account.email}`;
  $("#ip-history-list").innerHTML = '<div class="ip-history-loading">Загрузка...</div>';
  $("#ip-history-dialog").showModal();
  try {
    const data = await api(`/api/accounts/${id}/ip-history`);
    const rows = data.history || [];
    if (!rows.length) {
      $("#ip-history-list").innerHTML = '<div class="ip-history-empty">История пуста. Проверьте fraud score хотя бы один раз.</div>';
      return;
    }
    $("#ip-history-list").innerHTML = rows.map((r) => {
      const zone = ipHistoryScoreZone(r.fraud_score);
      const date = new Date(r.checked_at);
      const dateStr = Number.isNaN(date.getTime()) ? r.checked_at : date.toLocaleString("ru-RU");
      return `<div class="ip-row">
        <span class="ip-mono">${escapeHtml(r.ip)}</span>
        <span class="ip-score ip-score-${zone}">${r.fraud_score}</span>
        <span class="ip-date">${escapeHtml(dateStr)}</span>
      </div>`;
    }).join("");
  } catch (error) {
    $("#ip-history-list").innerHTML = `<div class="ip-history-empty">${escapeHtml(error.message)}</div>`;
  }
}

async function openEmails(id) {
  const account = state.accounts.find((a) => a.id === id);
  if (!account) return;
  $("#emails-subtitle").textContent = `${actualName(account)} · ${account.email}`;
  $("#emails-list").innerHTML = '<div class="ip-history-loading">Загрузка...</div>';
  $("#emails-dialog").showModal();
  try {
    const data = await api(`/api/accounts/${id}/emails`);
    const emails = data.emails || [];
    if (!emails.length) {
      $("#emails-list").innerHTML = '<div class="ip-history-empty">Писем пока нет</div>';
      return;
    }
    $("#emails-list").innerHTML = emails.map((e) => {
      const date = new Date(e.received_at);
      const dateStr = Number.isNaN(date.getTime()) ? e.received_at : date.toLocaleString("ru-RU");
      const unread = !e.is_read ? ' style="border-left:3px solid var(--accent)"' : '';
      const codeHtml = e.extracted_code ? `<div class="email-code"><button class="inline-copy" onclick="event.stopPropagation();copyText('${escapeHtml(e.extracted_code)}','Код скопирован')" title="Копировать код">${escapeHtml(e.extracted_code)}</button></div>` : '';
      return `<div class="email-item"${unread} data-email-id="${e.id}" onclick="markEmailRead(${e.id}, this)">
        <div class="email-header">
          <span class="email-from">${escapeHtml(e.sender)}</span>
          ${codeHtml}
          <span class="email-date">${escapeHtml(dateStr)}</span>
        </div>
        <div class="email-subject">${escapeHtml(e.subject)}</div>
        <div class="email-body">${escapeHtml(e.body_text).substring(0, 300)}</div>
      </div>`;
    }).join("");
  } catch (error) {
    $("#emails-list").innerHTML = `<div class="ip-history-empty">${escapeHtml(error.message)}</div>`;
  }
}

async function markEmailRead(emailId, el) {
  try {
    await api(`/api/emails/${emailId}/read`, { method: "POST" });
    if (el) el.style.borderLeft = "";
  } catch { /* ignore */ }
}

function openDeleteVision(id) {
  const account = state.accounts.find((item) => item.id === id); if (!account?.vision_profile_id) return;
  state.deleteVisionAccountId = id;
  $("#delete-vision-text").textContent = `${actualName(account)} · ${account.email}. Запись в панели сохранится, но профиль будет удален из Vision.`;
  $("#delete-vision-dialog").showModal();
}

function openPermanentDelete(id) {
  const account = state.accounts.find((item) => item.id === id); if (!account || account.vision_profile_id) return;
  state.permanentDeleteAccountId = id;
  $("#permanent-delete-text").textContent = `${actualName(account)} · ${account.email}. Email, код и остальные данные будут удалены без возможности восстановления.`;
  $("#permanent-delete-dialog").showModal();
}

async function pollSingleJob(jobId, accountId) {
  try {
    const {job} = await api(`/api/jobs/${jobId}`); await loadAccounts();
    if (["completed", "completed_with_errors", "failed", "interrupted"].includes(job.status)) {
      state.creating.delete(accountId); render();
      const account = state.accounts.find((item) => item.id === accountId);
      toast(job.failed ? (account?.error || job.errors?.[0] || "Профиль создать не удалось") : "Профиль создан в Vision");
      return;
    }
  } catch (error) {
    state.creating.delete(accountId); render(); toast(error.message); return;
  }
  setTimeout(() => pollSingleJob(jobId, accountId), 1800);
}

function openProxyConfirmation(id, country) {
  const account = state.accounts.find((item) => item.id === id); if (!account) return;
  state.proxyAccountId = id; state.proxyTargetCountry = country;
  const targetCountry = countryName(country || account.country);
  $("#proxy-confirm-text").textContent = `Профиль ${actualName(account)} получит новый sticky SOCKS5 прокси.`;
  $("#proxy-confirm-details").innerHTML = `<span>Сейчас</span><strong>${account.proxy_endpoint ? "Прокси назначен" : "Не назначен"}</strong><span>Страна</span><strong>${escapeHtml(targetCountry)}</strong>`;
  $("#proxy-confirm-dialog").showModal();
}

async function runSync(pushChanges, accountIds = null) {
  const button = pushChanges ? $("#sync-profiles") : $("#refresh-profiles");
  button.disabled = true; button.textContent = pushChanges ? "Синхронизация..." : "Проверка...";
  try {
    const payload = {push_changes: pushChanges};
    if (accountIds) payload.account_ids = accountIds;
    else if (state.selected.size) payload.account_ids = [...state.selected];
    const result = await api("/api/sync", {method:"POST", body:JSON.stringify(payload)}); await loadAccounts();
    toast(pushChanges ? `Синхронизировано: ${result.pushed}, не найдено: ${result.missing}, ошибок: ${result.failed}` : `Создано: ${result.synced}, не найдено: ${result.missing}, ошибок: ${result.failed}`);
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; render(); }
}

$("#refresh-profiles").addEventListener("click", () => runSync(false));
$("#sync-profiles").addEventListener("click", () => {
  const ids = state.accounts
    .filter((account) => account.status === "pending_sync" && account.vision_profile_id && (!state.selected.size || state.selected.has(account.id)))
    .map((account) => account.id);
  if (ids.length) runSync(true, ids);
});
$("#toggle-codes").addEventListener("click", () => {
  state.codesHidden = !state.codesHidden;
  localStorage.setItem("profile-admin-codes-hidden", state.codesHidden ? "1" : "0");
  render();
});
$("#bulk-sync").addEventListener("click", () => {
  const ids = state.accounts.filter((account) => state.selected.has(account.id) && account.vision_profile_id && account.status === "pending_sync").map((account) => account.id);
  if (ids.length) runSync(true, ids);
});
$("#search").addEventListener("input", render); $("#status-filter").addEventListener("change", render);
$("#select-all").addEventListener("change", (event) => {
  for (const account of filteredAccounts()) event.target.checked ? state.selected.add(account.id) : state.selected.delete(account.id); render();
});

$("#edit-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const id = state.editAccountId; if (!id) return;
  const payload = {profile_name:$("#edit-name").value,email:$("#edit-email").value,code:$("#edit-code").value,country:$("#edit-country").value};
  if (!$("#edit-os").disabled) payload.fingerprint_os = $("#edit-os").value;
  try { await api(`/api/accounts/${id}`, {method:"PATCH", body:JSON.stringify(payload)}); $("#edit-dialog").close(); await loadAccounts(); toast("Изменения сохранены"); }
  catch (error) { toast(error.message); }
});
$("#close-edit").addEventListener("click", () => $("#edit-dialog").close());
$("#cancel-edit").addEventListener("click", () => $("#edit-dialog").close());
$("#delete-from-edit").addEventListener("click", () => {
  const account = state.accounts.find((item) => item.id === state.editAccountId); if (!account) return;
  const hasVisionProfile = Boolean(account.vision_profile_id);
  state.deleteAccountId = account.id;
  $("#delete-title").textContent = hasVisionProfile ? "Удалить профиль из Vision и панели?" : "Переместить профиль в корзину?";
  $("#delete-text").textContent = `${actualName(account)} · ${account.email}. Активная запись будет удалена, а ее данные сохранятся в корзине${hasVisionProfile ? "; удаление профиля из Vision можно отключить ниже" : ""}.`;
  $("#delete-vision-row").hidden = !hasVisionProfile; $("#delete-vision").checked = hasVisionProfile;
  $("#edit-dialog").close(); $("#delete-dialog").showModal();
});
$("#cancel-delete").addEventListener("click", () => $("#delete-dialog").close());
$("#delete-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const account = state.accounts.find((item) => item.id === state.deleteAccountId); if (!account) return;
  try { await api(`/api/accounts/${account.id}`, {method:"DELETE", body:JSON.stringify({delete_vision:Boolean(account.vision_profile_id) && $("#delete-vision").checked})}); $("#delete-dialog").close(); state.selected.delete(account.id); await Promise.all([loadAccounts(), loadTrash()]); toast("Профиль перемещен в корзину"); }
  catch (error) { toast(error.message); }
});

$("#open-trash").addEventListener("click", async () => {
  try { await loadTrash(true); $("#trash-dialog").showModal(); }
  catch (error) { toast(error.message); }
});
$("#close-trash").addEventListener("click", () => $("#trash-dialog").close());
$("#close-ip-history").addEventListener("click", () => $("#ip-history-dialog").close());
$("#close-emails").addEventListener("click", () => $("#emails-dialog").close());
$("#trash-list").addEventListener("click", async (event) => {
  const button = event.target.closest(".restore-account"); if (!button) return;
  const item = button.closest(".trash-item"); const id = Number(item?.dataset.id); if (!id) return;
  button.disabled = true; button.textContent = "Восстановление...";
  try {
    await api(`/api/trash/${id}/restore`, {method:"POST", body:"{}"});
    await Promise.all([loadAccounts(), loadTrash(true)]); toast("Профиль восстановлен");
  } catch (error) { button.disabled = false; button.textContent = "Восстановить"; toast(error.message); }
});

$("#cancel-delete-vision").addEventListener("click", () => {
  $("#delete-vision-dialog").close(); state.deleteVisionAccountId = null;
});
$("#delete-vision-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = state.deleteVisionAccountId;
  if (!id) return;
  $("#delete-vision-dialog").close(); state.deleteVisionAccountId = null;
  state.deletingVision.add(id); render();
  try {
    await api(`/api/accounts/${id}/delete-vision`, {method:"POST", body:"{}"});
    await loadAccounts(); toast("Профиль удален из Vision; запись сохранена в панели");
  } catch (error) { toast(error.message); }
  finally { state.deletingVision.delete(id); await loadAccounts(); }
});

$("#cancel-permanent-delete").addEventListener("click", () => {
  $("#permanent-delete-dialog").close(); state.permanentDeleteAccountId = null;
});
$("#permanent-delete-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = state.permanentDeleteAccountId;
  if (!id) return;
  try {
    await api(`/api/accounts/${id}/permanent`, {method:"DELETE", body:JSON.stringify({confirmed:true})});
    $("#permanent-delete-dialog").close(); state.permanentDeleteAccountId = null;
    state.selected.delete(id); await loadAccounts(); toast("Запись удалена навсегда");
  } catch (error) { toast(error.message); }
});

$("#bulk-delete-vision").addEventListener("click", () => {
  state.bulkActionIds = state.accounts
    .filter((account) => state.selected.has(account.id) && account.vision_profile_id && !["queued", "running", "rotating", "deleting"].includes(account.status))
    .map((account) => account.id);
  if (!state.bulkActionIds.length) return;
  $("#bulk-delete-vision-text").textContent = `${state.bulkActionIds.length} профилей будут удалены из Vision. Записи останутся в панели.`;
  $("#bulk-delete-vision-dialog").showModal();
});
$("#cancel-bulk-delete-vision").addEventListener("click", () => $("#bulk-delete-vision-dialog").close());
$("#bulk-delete-vision-form").addEventListener("submit", async (event) => {
  event.preventDefault(); $("#bulk-delete-vision-dialog").close();
  let failed = 0;
  for (const id of state.bulkActionIds) {
    try { await api(`/api/accounts/${id}/delete-vision`, {method:"POST", body:"{}"}); }
    catch { failed += 1; }
  }
  const completed = state.bulkActionIds.length - failed; state.bulkActionIds = [];
  await loadAccounts(); toast(`Удалено из Vision: ${completed}, ошибок: ${failed}`);
});

$("#bulk-permanent-delete").addEventListener("click", () => {
  state.bulkActionIds = state.accounts
    .filter((account) => state.selected.has(account.id) && !account.vision_profile_id && !["queued", "running", "rotating", "deleting"].includes(account.status))
    .map((account) => account.id);
  if (!state.bulkActionIds.length) return;
  $("#bulk-permanent-delete-text").textContent = `${state.bulkActionIds.length} не созданных записей будут удалены без корзины и возможности восстановления.`;
  $("#bulk-permanent-delete-dialog").showModal();
});
$("#cancel-bulk-permanent-delete").addEventListener("click", () => $("#bulk-permanent-delete-dialog").close());
$("#bulk-permanent-delete-form").addEventListener("submit", async (event) => {
  event.preventDefault(); $("#bulk-permanent-delete-dialog").close();
  let failed = 0;
  for (const id of state.bulkActionIds) {
    try {
      await api(`/api/accounts/${id}/permanent`, {method:"DELETE", body:JSON.stringify({confirmed:true})});
      state.selected.delete(id);
    } catch { failed += 1; }
  }
  const completed = state.bulkActionIds.length - failed; state.bulkActionIds = [];
  await loadAccounts(); toast(`Удалено навсегда: ${completed}, ошибок: ${failed}`);
});

$("#bulk-fraud-check").addEventListener("click", async () => {
  const available = (account) => !["queued", "running", "rotating", "deleting"].includes(account.status);
  const targets = (state.selected.size
    ? state.accounts.filter((a) => state.selected.has(a.id))
    : state.accounts
  ).filter((a) => a.vision_proxy_id && available(a) && !state.checkingFraud.has(a.id));
  if (!targets.length) return;
  const btn = $("#bulk-fraud-check");
  btn.disabled = true;
  let done = 0, failed = 0;
  toast(`Проверка fraud score: 0/${targets.length}...`);
  for (const account of targets) {
    state.checkingFraud.add(account.id); render();
    try {
      await api(`/api/accounts/${account.id}/fraud-check`, {method:"POST", body:"{}"});
      done++;
    } catch { failed++; }
    finally { state.checkingFraud.delete(account.id); }
    if ((done + failed) % 3 === 0) toast(`Проверка fraud score: ${done + failed}/${targets.length}...`);
  }
  await loadAccounts();
  toast(`Fraud score проверен: ${done} ок, ${failed} ошибок`);
});

$("#bulk-rotate-bad").addEventListener("click", async () => {
  const available = (a) => !["queued", "running", "rotating", "deleting"].includes(a.status);
  const targets = (state.selected.size
    ? state.accounts.filter((a) => state.selected.has(a.id))
    : state.accounts
  ).filter((a) => a.vision_profile_id && a.fraud_score >= 25 && available(a) && !state.rotating.has(a.id));
  if (!targets.length) return;
  const btn = $("#bulk-rotate-bad");
  btn.disabled = true;
  let done = 0, failed = 0;
  toast(`Замена прокси (score ≥ 25): 0/${targets.length}...`);
  for (const account of targets) {
    state.rotating.add(account.id); render();
    try {
      await api(`/api/accounts/${account.id}/rotate-proxy`, {method:"POST", body:JSON.stringify({})});
      done++;
    } catch (error) {
      failed++;
      toast(error.message);
    }
    finally { state.rotating.delete(account.id); }
    toast(`Замена прокси: ${done + failed}/${targets.length}...`);
  }
  await loadAccounts();
  toast(`Прокси заменены: ${done} ок, ${failed} ошибок`);
});

$("#cancel-country").addEventListener("click", () => $("#country-dialog").close());
$("#country-form").addEventListener("submit", (event) => { event.preventDefault(); const id = state.countryAccountId; const country = $("#proxy-country").value.trim(); $("#country-dialog").close(); if (id) openProxyConfirmation(id, country); state.countryAccountId = null; });

$("#cancel-proxy-change").addEventListener("click", () => $("#proxy-confirm-dialog").close());
$("#proxy-confirm-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const id = state.proxyAccountId; const country = state.proxyTargetCountry;
  $("#proxy-confirm-dialog").close(); state.proxyAccountId = null; state.proxyTargetCountry = "";
  if (id) await rotateProxy(id, country);
});

function closeAuthenticator() {
  $("#authenticator-dialog").close(); $("#authenticator-secret").value = ""; state.authenticatorAccountId = null;
}
$("#close-authenticator").addEventListener("click", closeAuthenticator);
$("#cancel-authenticator").addEventListener("click", closeAuthenticator);
$("#authenticator-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const id = state.authenticatorAccountId;
  if (!id) return;
  const submit = event.submitter; if (submit) submit.disabled = true;
  try {
    await api(`/api/accounts/${id}/authenticator`, {method:"POST", body:JSON.stringify({secret:$("#authenticator-secret").value})});
    closeAuthenticator(); await loadAccounts(); await loadAuthenticatorCodes(); toast("Ключ аутентификатора сохранен");
  } catch (error) { toast(error.message); }
  finally { if (submit) submit.disabled = false; }
});

$("#open-import").addEventListener("click", () => $("#import-dialog").showModal());
$("#close-import").addEventListener("click", () => $("#import-dialog").close());
$("#cancel-import").addEventListener("click", () => $("#import-dialog").close());
$("#import-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const resultNode = $("#import-result"); resultNode.textContent = "";
  try {
    const data = await api("/api/import", {method:"POST",body:JSON.stringify({text:$("#import-text").value,default_country:$("#import-country").value,default_os:$("#import-os").value,prefix:$("#import-prefix").value.trim()})});
    resultNode.textContent = `Добавлено: ${data.added} · Дубликаты: ${data.duplicates.length} · Ошибки: ${data.invalid.length}`; await loadAccounts();
    if (!data.invalid.length) { $("#import-text").value = ""; setTimeout(() => $("#import-dialog").close(), 650); }
  } catch (error) { resultNode.textContent = error.message; }
});

$("#create-profiles").addEventListener("click", () => {
  state.bulkCreateIds = state.accounts
    .filter((account) => state.selected.has(account.id) && !account.vision_profile_id && ["ready", "not_created"].includes(account.status))
    .map((account) => account.id);
  if (!state.bulkCreateIds.length) return;
  $("#confirm-text").textContent = `Будут созданы ${state.bulkCreateIds.length} профилей и ${state.bulkCreateIds.length} новых прокси.`;
  $("#confirm-dialog").showModal();
});
$("#cancel-create").addEventListener("click", () => $("#confirm-dialog").close());
$("#confirm-form").addEventListener("submit", async (event) => {
  event.preventDefault(); $("#confirm-dialog").close();
  try {
    const data = await api("/api/jobs", {method:"POST",body:JSON.stringify({account_ids:state.bulkCreateIds,country:$("#bulk-country").value,fingerprint_os:$("#bulk-os").value})});
    state.jobId = data.job_id; state.bulkCreateIds = []; state.selected.clear(); toast(`Задание #${state.jobId} запущено`); await loadAccounts(); pollJob();
  } catch (error) { toast(error.message); }
});

async function pollJob() {
  clearTimeout(state.poll); if (!state.jobId) return;
  try {
    const {job} = await api(`/api/jobs/${state.jobId}`); await loadAccounts();
    if (["completed","completed_with_errors","failed","interrupted"].includes(job.status)) {
      toast(job.errors?.[0] || `Готово: ${job.completed}, ошибок: ${job.failed}`); state.jobId = null; return;
    }
  } catch (error) { toast(error.message); }
  state.poll = setTimeout(pollJob, 1800);
}

Promise.all([loadAccounts(), loadCountries(), loadTrash()]).then(() => {
  loadAuthenticatorCodes(); state.totpPoll = setInterval(loadAuthenticatorCodes, 1000);
}).catch((error) => toast(error.message));

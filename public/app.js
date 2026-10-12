const $ = (id) => document.getElementById(id);

let currentUser = null;
let token = "";
let currentTab = "login";
let allEvents = [];
let toastTimer;

function showToast(message) {
  const toast = $("toast");
  toast.textContent = message;
  toast.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), 3200);
}

// Send API requests with the access token; refresh it once if it has expired.
async function api(url, options = {}, mayRefresh = true) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(url, { ...options, headers, credentials: "same-origin" });
  const data = await response.json().catch(() => ({}));

  if (response.status === 401 && mayRefresh &&
      !["/api/auth/login", "/api/auth/register", "/api/auth/refresh"].includes(url)) {
    const refreshed = await fetch("/api/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({})
    });
    const refreshData = await refreshed.json().catch(() => ({}));
    if (refreshed.ok && refreshData.accessToken) {
      token = refreshData.accessToken;
      return api(url, options, false);
    }
    token = "";
    currentUser = null;
    setScreen(false);
    throw new Error("Your session expired. Please sign in again.");
  }

  if (!response.ok) throw new Error(data.message || "Something went wrong.");
  return data;
}

function setScreen(isLoggedIn) {
  $("authScreen").classList.toggle("hidden", isLoggedIn);
  $("dashboard").classList.toggle("hidden", !isLoggedIn);
  $("logoutBtn").classList.toggle("hidden", !isLoggedIn);
  $("topUsername").textContent = currentUser?.username || "Guest";
  $("topRole").textContent = currentUser?.role === "admin" ? "Security admin" : "Standard user";
  $("avatar").textContent = (currentUser?.username || "G").charAt(0).toUpperCase();
  $("welcomeName").textContent = currentUser?.username || "there";
  $("adminNotice").classList.toggle("hidden", currentUser?.role === "admin");
  $("userSecurityPanel").classList.toggle("hidden", currentUser?.role === "admin");
  $("statsGrid").classList.toggle("hidden", currentUser?.role !== "admin");
  document.querySelector(".content-grid").classList.toggle("hidden", currentUser?.role !== "admin");
  $("navEvents").classList.toggle("hidden", currentUser?.role !== "admin");
  $("navUsers").classList.toggle("hidden", currentUser?.role !== "admin");
}

function setAuthTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".auth-tab").forEach(button => button.classList.toggle("active", button.dataset.tab === tab));
  $("usernameField").classList.toggle("hidden", tab !== "register");
  $("authTitle").textContent = tab === "login" ? "Welcome back" : "Create your account";
  $("authSubtitle").textContent = tab === "login" ? "Sign in to your security workspace." : "Get started with a secure account.";
  $("authSubmit").innerHTML = tab === "login" ? 'Sign in securely <span>→</span>' : 'Create account <span>→</span>';
  $("password").autocomplete = tab === "login" ? "current-password" : "new-password";
  $("authMessage").textContent = "";
}

document.querySelectorAll(".auth-tab").forEach(button => button.addEventListener("click", () => setAuthTab(button.dataset.tab)));

$("authForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    email: $("email").value.trim(),
    password: $("password").value
  };
  if (currentTab === "register") payload.username = $("username").value.trim();

  const submit = $("authSubmit");
  submit.disabled = true;
  submit.textContent = currentTab === "login" ? "Signing in…" : "Creating account…";
  $("authMessage").textContent = "";

  try {
    const result = await api(`/api/auth/${currentTab}`, {
      method: "POST",
      body: JSON.stringify(payload)
    });
    token = result.accessToken;
    currentUser = result.user;
    setScreen(true);
    $("password").value = "";
    if (currentUser.role === "admin") await loadDashboard();
    else {
      await loadUserSecurity();
      showToast("Signed in. Your security activity is available below.");
    }
  } catch (error) {
    $("authMessage").textContent = error.message;
  } finally {
    submit.disabled = false;
    setAuthTab(currentTab);
  }
});

// Restore login after a page reload using the HttpOnly refresh cookie.
async function restoreSession() {
  try {
    const refreshed = await fetch("/api/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({})
    });
    const refreshData = await refreshed.json().catch(() => ({}));
    if (!refreshed.ok || !refreshData.accessToken) {
      token = "";
      currentUser = null;
      setScreen(false);
      return;
    }

    token = refreshData.accessToken;
    const result = await api("/api/auth/me");
    currentUser = result.user;
    setScreen(true);
    if (currentUser.role === "admin") await loadDashboard();
    else await loadUserSecurity();
  } catch {
    token = "";
    currentUser = null;
    setScreen(false);
  }
}


async function loadUserSecurity() {
  try {
    const data = await api("/api/auth/security-summary");
    $("userFailedCount").textContent = data.summary.failedLogins;
    $("userLimitedCount").textContent = data.summary.rateLimited;
    $("userSuspiciousCount").textContent = data.summary.suspicious;
    $("userEventsBody").innerHTML = data.events.length ? data.events.map(event => {
      const label = event.type === "login_failed" ? "Failed login" :
        event.type === "rate_limited" ? "Rate limited" :
        event.type === "login_success" ? "Successful login" :
        event.type === "register" ? "Registration" : "Security event";
      const flagged = event.suspicious ? "flagged" : "safe";
      return `<tr>
        <td><span class="user-event-type ${flagged}">${label}</span></td>
        <td>${safeText(event.message)}${event.suspicious ? '<span class="detail-cell">Flagged for review</span>' : ""}</td>
        <td class="time-cell" title="${safeText(new Date(event.createdAt).toLocaleString())}">${timeAgo(event.createdAt)}</td>
      </tr>`;
    }).join("") : '<tr><td colspan="3" class="empty">No security events have been recorded for your email yet.</td></tr>';
  } catch (error) {
    $("userEventsBody").innerHTML = `<tr><td colspan="3" class="empty">${safeText(error.message)}</td></tr>`;
  }
}

async function loadDashboard() {
  try {
    const data = await api("/api/dashboard/summary");
    $("statUsers").textContent = data.stats.users;
    $("statEvents").textContent = data.stats.events;
    $("statFailed").textContent = data.stats.failedLogins;
    $("statSuspicious").textContent = data.stats.suspiciousEvents;
    $("insightFailed").textContent = data.stats.failedLogins;
    $("insightSuspicious").textContent = data.stats.suspiciousEvents;
    $("insightLimited").textContent = data.stats.rateLimited;

    allEvents = data.events;
    renderEvents();
  } catch (error) {
    showToast(error.message);
  }
}

function labelFor(type) {
  return ({
    login_success: ["Success", "tag-success"],
    login_failed: ["Failed login", "tag-failed"],
    rate_limited: ["Rate limited", "tag-limited"],
    register: ["Registration", "tag-register"]
  })[type] || ["Security event", "tag-unknown"];
}

function safeText(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[char]);
}

function timeAgo(dateValue) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(dateValue).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return new Date(dateValue).toLocaleDateString();
}

function renderEvents() {
  const query = $("eventSearch").value.toLowerCase().trim();
  const filter = $("eventFilter").value;
  const filtered = allEvents.filter(event => {
    const matchesFilter = filter === "all" || (filter === "suspicious" ? event.suspicious : event.type === filter);
    const searchable = `${event.email} ${event.ip} ${event.message} ${event.type}`.toLowerCase();
    return matchesFilter && searchable.includes(query);
  });

  $("eventsBody").innerHTML = filtered.length ? filtered.map(event => {
    const [label, tagClass] = labelFor(event.type);
    return `<tr>
      <td><span class="event-tag ${tagClass}">${label}</span>${event.suspicious ? '<span class="detail-cell">Flagged for review</span>' : ""}</td>
      <td><span class="email-cell">${safeText(event.email)}</span><span class="detail-cell">${safeText(event.message)}</span></td>
      <td class="ip-cell">${safeText(event.ip)}</td>
      <td class="time-cell" title="${safeText(new Date(event.createdAt).toLocaleString())}">${timeAgo(event.createdAt)}</td>
    </tr>`;
  }).join("") : '<tr><td colspan="4" class="empty">No events match your search.</td></tr>';
  $("eventCount").textContent = `Showing ${filtered.length} of ${allEvents.length} recent events`;
}

$("eventSearch").addEventListener("input", renderEvents);
$("eventFilter").addEventListener("change", renderEvents);

async function loadUsers() {
  try {
    const data = await api("/api/dashboard/users");
    $("usersBody").innerHTML = data.users.map(user => `<tr>
      <td class="email-cell">${safeText(user.username)}</td>
      <td>${safeText(user.email)}</td>
      <td><span class="role-badge ${user.role === "admin" ? "admin" : ""}">${safeText(user.role)}</span></td>
      <td class="time-cell">${new Date(user.createdAt).toLocaleDateString()}</td>
    </tr>`).join("") || '<tr><td colspan="4" class="empty">No accounts found.</td></tr>';
  } catch (error) {
    showToast(error.message);
  }
}

function showPage(page) {
  $("usersPanel").classList.toggle("hidden", page !== "users");
  document.querySelector(".content-grid").classList.toggle("hidden", page === "users" || currentUser?.role !== "admin");
  document.querySelectorAll(".nav-item").forEach(item => item.classList.remove("active"));
  if (page === "users") {
    $("navUsers").classList.add("active");
    $("pageTitle").textContent = "User accounts";
    $("pageLabel").textContent = "USER ACCOUNTS";
    loadUsers();
  } else if (page === "events") {
    $("navEvents").classList.add("active");
    $("pageTitle").textContent = "Security events";
    $("pageLabel").textContent = "SECURITY EVENTS";
    $("usersPanel").classList.add("hidden");
    document.querySelector(".content-grid").classList.toggle("hidden", currentUser?.role !== "admin");
  } else {
    $("navOverview").classList.add("active");
    $("pageTitle").textContent = "Security overview";
    $("pageLabel").textContent = "OVERVIEW";
    $("usersPanel").classList.add("hidden");
    document.querySelector(".content-grid").classList.toggle("hidden", currentUser?.role !== "admin");
  }
}

$("navOverview").addEventListener("click", () => showPage("overview"));
$("navEvents").addEventListener("click", () => showPage("events"));
$("navUsers").addEventListener("click", () => showPage("users"));
$("refreshBtn").addEventListener("click", async () => {
  const button = $("refreshBtn");
  button.textContent = "…";
  try {
    if (currentUser?.role === "admin") {
      await loadDashboard();
      if (!$("usersPanel").classList.contains("hidden")) await loadUsers();
    } else {
      await loadUserSecurity();
    }
    showToast("Dashboard refreshed.");
  } finally {
    button.textContent = "↻";
  }
});
$("reloadUsers").addEventListener("click", loadUsers);

$("logoutAllBtn").addEventListener("click", async () => {
  const confirmed = window.confirm("Sign out this account from every device? You will need to log in again on this device too.");
  if (!confirmed) return;

  $("logoutAllBtn").disabled = true;
  $("logoutAllBtn").textContent = "Signing out devices…";
  try {
    await api("/api/auth/logout-all", { method: "POST", body: JSON.stringify({}) });
    token = "";
    currentUser = null;
    allEvents = [];
    setScreen(false);
    setAuthTab("login");
    showToast("All devices have been signed out. Please log in again.");
  } catch (error) {
    showToast(error.message);
  } finally {
    $("logoutAllBtn").disabled = false;
    $("logoutAllBtn").textContent = "Sign out all devices";
  }
});

$("logoutBtn").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", body: JSON.stringify({}) });
  } catch {
    // The server session may already have expired; still clear this page's state.
  }
  token = "";
  currentUser = null;
  allEvents = [];
  setScreen(false);
  setAuthTab("login");
  showToast("You have been logged out.");
});

restoreSession();
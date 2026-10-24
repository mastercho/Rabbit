import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import elk from "cytoscape-elk";
import klay from "cytoscape-klay";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  Bot,
  CalendarDays,
  Check,
  CheckCheck,
  CheckCircle2,
  ChevronLeft,
  ChevronDown,
  Copy,
  ChevronRight,
  Circle,
  Clock,
  Download,
  Eye,
  EyeOff,
  FileText,
  Folder,
  History,
  Home,
  KeyRound,
  Loader2,
  Lock,
  LayoutGrid,
  List,
  LogOut,
  Monitor,
  Maximize2,
  MoreVertical,
  Moon,
  Network,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Save,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Square,
  Sun,
  Tag,
  Trash2,
  User,
  X,
} from "lucide-react";
import { apiRequest, downloadFromApi } from "./api";
import { buildFactGraph, fitFactGraph } from "./graphModel";
import NotificationBell from "./components/notifications/NotificationBell";
import {
  Badge,
  ConfirmModal,
  EmptyState,
  MetricCard,
  MiniStat,
  Modal,
  PageHeader,
  ProjectSummaryCard,
  Toast,
  VulnerabilitySummaryCard,
} from "./components/ui";
import {
  SEVERITY_META,
  STATUS_META,
  TASK_TYPES,
  clampText,
  cn,
  formatTime,
  go,
  parseHash,
  parseHintLines,
  relativeHeartbeat,
} from "./utils";

try {
  cytoscape.use(dagre);
  cytoscape.use(elk);
  cytoscape.use(klay);
} catch {
  // Vite HMR may register the extension more than once.
}

const APP_NAME = "Rabbit";
const HUMAN_WORKER = "Human";
const SECRET_MASK = "********";
const VULN_FOCUS_STORAGE_KEY = "rabbit:vuln-focus";
const PROJECT_PRESET_STORAGE_KEY = "rabbit:project-preset";
const WORKER_PRESET_STORAGE_KEY = "rabbit:worker-preset";
const VULN_FILTERS_STORAGE_KEY = "rabbit:vuln-filters";

function queueVulnerabilityFocus(id, hash = "#/vulnerabilities") {
  if (typeof window !== "undefined" && id) {
    window.sessionStorage.setItem(VULN_FOCUS_STORAGE_KEY, String(id));
  }
  go(hash);
}

function queueRoutePreset(storageKey, payload, hash) {
  if (typeof window !== "undefined") {
    window.sessionStorage.setItem(storageKey, JSON.stringify(payload || {}));
  }
  go(hash);
}

function consumeRoutePreset(storageKey) {
  if (typeof window === "undefined") return null;
  const raw = window.sessionStorage.getItem(storageKey);
  if (!raw) return null;
  window.sessionStorage.removeItem(storageKey);
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function useRoute() {
  const [route, setRoute] = useState(parseHash);

  useEffect(() => {
    const onHash = () => setRoute(parseHash());
    window.addEventListener("hashchange", onHash);
    if (!window.location.hash) {
      window.location.hash = "#/dashboard";
    }
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  return route;
}

function useAsyncAction(setToast) {
  return useCallback(
    async (label, action) => {
      try {
        const result = await action();
        if (label) setToast({ type: "success", message: label });
        return result;
      } catch (error) {
        if (error?.status === 401) {
          setToast({ type: "danger", message: "Your session has expired. Sign in again." });
        } else {
          setToast({ type: "danger", message: error.message || "The action failed" });
        }
        throw error;
      }
    },
    [setToast],
  );
}

export default function App() {
  const route = useRoute();
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [toast, setToast] = useState(null);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [confirmState, setConfirmState] = useState(null);
  const [theme, setTheme] = useState(() => {
    // Dark is the default (Terminal CLI aesthetic). Only flip to light when
    // the user has explicitly opted into it; absent storage → dark.
    if (typeof window === "undefined") return "dark";
    return window.localStorage.getItem("rabbit-theme") === "light" ? "light" : "dark";
  });
  const runAction = useAsyncAction(setToast);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    window.localStorage.setItem("rabbit-theme", theme);
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  }, []);

  // Promise-based confirm: pages call confirmAction(...) and await a boolean.
  const confirmAction = useCallback(
    (options) =>
      new Promise((resolve) => {
        setConfirmState({ options: options || {}, resolve });
      }),
    [],
  );

  const resolveConfirm = useCallback(
    (result) => {
      setConfirmState((current) => {
        if (current) current.resolve(result);
        return null;
      });
    },
    [],
  );

  const loadUser = useCallback(async () => {
    try {
      const me = await apiRequest("/api/auth/me");
      setUser(me);
    } catch {
      setUser(null);
    } finally {
      setAuthChecked(true);
    }
  }, []);

  useEffect(() => {
    loadUser();
  }, [loadUser]);

  useEffect(() => {
    if (!toast) return undefined;
    const timer = window.setTimeout(() => setToast(null), 4200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const logout = async () => {
    await runAction(null, () => apiRequest("/api/auth/logout", { method: "POST" }));
    setUser(null);
  };

  if (!authChecked) {
    return (
      <div className="boot-screen">
        <Loader2 className="spin" size={28} />
        <span>Loading Rabbit</span>
      </div>
    );
  }

  if (!user) {
    return (
      <>
        <AuthPage onAuthed={loadUser} setToast={setToast} />
        {toast && <Toast toast={toast} onClose={() => setToast(null)} />}
      </>
    );
  }

  return (
    <div className="app-shell">
      <TopNav
        route={route}
        user={user}
        theme={theme}
        onToggleTheme={toggleTheme}
        onLogout={logout}
        onPassword={() => setPasswordOpen(true)}
        onSettings={() => setSettingsOpen(true)}
        setToast={setToast}
      />
      <main className="app-main">
        {route.page === "project" ? (
          <ProjectWorkspace
            projectId={route.projectId}
            runAction={runAction}
            setToast={setToast}
            confirmAction={confirmAction}
          />
        ) : route.page === "vulnerabilities" ? (
          <VulnerabilitiesPage route={route} runAction={runAction} setToast={setToast} confirmAction={confirmAction} />
        ) : route.page === "workers" ? (
          <WorkersPage runAction={runAction} setToast={setToast} confirmAction={confirmAction} />
        ) : route.page === "templates" ? (
          <TemplatesPage runAction={runAction} setToast={setToast} confirmAction={confirmAction} />
        ) : route.page === "audit" ? (
          <AuditPage setToast={setToast} />
        ) : route.page === "projects" ? (
          <ProjectsPage runAction={runAction} setToast={setToast} confirmAction={confirmAction} />
        ) : (
          <DashboardPage runAction={runAction} setToast={setToast} />
        )}
      </main>
      {passwordOpen && <PasswordModal onClose={() => setPasswordOpen(false)} runAction={runAction} />}
      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} runAction={runAction} />}
      {confirmState && (
        <ConfirmModal
          {...confirmState.options}
          onConfirm={() => resolveConfirm(true)}
          onCancel={() => resolveConfirm(false)}
        />
      )}
      {toast && <Toast toast={toast} onClose={() => setToast(null)} />}
    </div>
  );
}

function TopNav({ route, user, theme, onToggleTheme, onLogout, onPassword, onSettings, setToast }) {
  const mainNav = [
    ["projects", "Projects", Folder],
    ["vulnerabilities", "Vulnerability reports", AlertTriangle],
    ["workers", "Workers", Monitor],
    ["templates", "Templates", FileText],
  ];
  const activeNav = mainNav.find(([key]) => route.page === key || (key === "projects" && route.page === "project"));
  const sectionLabel =
    route.page === "dashboard"
      ? "Dashboard"
      : route.page === "audit"
        ? "Audit log"
        : activeNav?.[1] || APP_NAME;
  const reportSubnav = [
    { title: null, items: [["overview", "Report overview"]] },
    {
      title: "By severity",
      items: [
        ["critical", "Critical"],
        ["high", "High"],
        ["medium", "Medium"],
        ["low", "Low"],
      ],
    },
    {
      title: "By status",
      items: [
        ["confirmed", "Confirmed"],
        ["ignored", "Ignored"],
      ],
    },
    { title: null, items: [["export-records", "Export history"]] },
  ];
  const vulnRouteActive = route.page === "vulnerabilities";
  const [reportExpanded, setReportExpanded] = useState(vulnRouteActive);
  const [reportManual, setReportManual] = useState(false);
  const activeView = route.page === "vulnerabilities" ? route.view || "overview" : null;
  const searchPlaceholder =
    route.page === "projects" || route.page === "project"
      ? "Search project name, id, owner, tags..."
      : "Search title, id, project, tags...";

  useEffect(() => {
    if (vulnRouteActive) {
      if (!reportManual) setReportExpanded(true);
      return;
    }
    setReportExpanded(false);
    setReportManual(false);
  }, [reportManual, vulnRouteActive]);

  const toggleVulnerabilityNav = () => {
    if (!vulnRouteActive) {
      setReportManual(false);
      setReportExpanded(true);
      go("#/vulnerabilities");
      return;
    }
    setReportManual(true);
    setReportExpanded((prev) => !prev);
  };

  return (
    <>
      <header className="top-utility">
        <button className="brand" type="button" onClick={() => go("#/dashboard")}>
          <span className="brand-mark">
            <img src="/static/rabbit-icon.png" alt="Rabbit" />
          </span>
          <span>{APP_NAME}</span>
        </button>
        <div className="top-section-label">{sectionLabel}</div>
        <GlobalSearch setToast={setToast} placeholder={searchPlaceholder} shortcutLabel="⌘K" />
        <div className="nav-actions">
          <NotificationBell setToast={setToast} />
          <button
            className="icon-button"
            type="button"
            onClick={onToggleTheme}
            aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            title={theme === "dark" ? "Light mode" : "Dark mode"}
          >
            {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <button className="user-chip" type="button" onClick={onPassword} title="Change password">
            <span className="user-avatar">{(user.username || "U").slice(0, 1).toUpperCase()}</span>
            <span className="user-name">{user.username}</span>
          </button>
          <button className="icon-button" type="button" onClick={onLogout} aria-label="Sign out" title="Sign out">
            <LogOut size={16} />
          </button>
        </div>
      </header>
      <aside className="top-nav">
        <nav className="nav-tabs" aria-label="Primary">
          <button
            className={cn("nav-tab", route.page === "dashboard" && "active")}
            type="button"
            onClick={() => go("#/dashboard")}
          >
            <Home size={17} />
            Home
          </button>
          {mainNav.map(([key, label, Icon]) => {
            const active = route.page === key || (key === "projects" && route.page === "project");
            return (
              <div key={key} className={cn("nav-group", active && "active", key === "vulnerabilities" && reportExpanded && "expanded")}>
                <button
                  className={cn("nav-tab", active && key !== "vulnerabilities" && "active", key === "vulnerabilities" && active && "module-open")}
                  type="button"
                  onClick={() => (key === "vulnerabilities" ? toggleVulnerabilityNav() : go(key === "projects" ? "#/projects" : `#/${key}`))}
                >
                  <Icon size={17} />
                  {label}
                  {key === "vulnerabilities" && <ChevronDown className="nav-caret" size={14} />}
                </button>
                {key === "vulnerabilities" && reportExpanded && (
                  <div className="sub-nav">
                    {reportSubnav.map((group, index) => (
                      <div key={group.title || `group-${index}`} className="sub-nav-group">
                        {group.title && <span className="sub-nav-group-label">{group.title}</span>}
                        <div className="sub-nav-list">
                          {group.items.map(([view, label]) => (
                            <button
                              key={view}
                              className={cn(activeView === view && "active")}
                              type="button"
                              onClick={() => go(view === "overview" ? "#/vulnerabilities" : `#/vulnerabilities/${view}`)}
                            >
                              <span className="sub-nav-indicator" />
                              {label}
                            </button>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
          <button
            className={cn("nav-tab", route.page === "audit" && "active")}
            type="button"
            onClick={() => go("#/audit")}
          >
            <History size={17} />
            Audit log
          </button>
          <button className="nav-tab" type="button" onClick={onSettings}>
            <Settings size={17} />
            Settings
          </button>
        </nav>
        <div className="sidebar-foot">
          <FileText size={15} />
          <span>Default workspace</span>
        </div>
      </aside>
    </>
  );
}

function GlobalSearch({ setToast, placeholder = "Search title, id, project, tags...", shortcutLabel = "" }) {
  const [term, setTerm] = useState("");
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState({ vulnerabilities: [], projects: [] });
  const wrapRef = useRef(null);
  const cacheRef = useRef(null);

  // Lazily fetch the full vulnerability + project lists once, then filter
  // client-side as the user types. Kept lightweight: one fetch per session,
  // refreshed only when the dropdown is opened after being closed a while.
  const ensureData = useCallback(async () => {
    if (cacheRef.current && Date.now() - cacheRef.current.at < 60000) return cacheRef.current.payload;
    const [vulns, projects] = await Promise.all([
      apiRequest("/api/vulnerabilities").catch(() => []),
      apiRequest("/projects").catch(() => []),
    ]);
    const payload = {
      vulnerabilities: Array.isArray(vulns) ? vulns : [],
      projects: Array.isArray(projects) ? projects : [],
    };
    cacheRef.current = { at: Date.now(), payload };
    return payload;
  }, []);

  useEffect(() => {
    const value = term.trim().toLowerCase();
    if (!value) {
      setData({ vulnerabilities: [], projects: [] });
      setOpen(false);
      return undefined;
    }
    let cancelled = false;
    setLoading(true);
    const timer = window.setTimeout(async () => {
      try {
        const payload = await ensureData();
        if (cancelled) return;
        const vulnerabilities = payload.vulnerabilities
          .filter((item) =>
            [item.title, item.fact_id, item.project_name, item.project_id, item.description]
              .filter(Boolean)
              .some((field) => String(field).toLowerCase().includes(value)),
          )
          .slice(0, 6);
        const projects = payload.projects
          .filter((item) =>
            [item.title, item.id, item.goal, item.origin]
              .filter(Boolean)
              .some((field) => String(field).toLowerCase().includes(value)),
          )
          .slice(0, 5);
        setData({ vulnerabilities, projects });
        setOpen(true);
      } catch (error) {
        if (!cancelled && setToast) setToast({ type: "danger", message: error.message || "Search failed" });
      } finally {
        if (!cancelled) setLoading(false);
      }
    }, 220);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [term, ensureData, setToast]);

  useEffect(() => {
    const onClick = (event) => {
      if (wrapRef.current && !wrapRef.current.contains(event.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  const reset = () => {
    setTerm("");
    setOpen(false);
  };

  const goVuln = (vuln) => {
    reset();
    go(`#/vulnerabilities?q=${encodeURIComponent(vuln.title || vuln.fact_id || "")}`);
  };

  const goProject = (project) => {
    reset();
    go(`#/projects/${project.id}`);
  };

  const hasResults = data.vulnerabilities.length > 0 || data.projects.length > 0;

  return (
    <div className="global-search-wrap" ref={wrapRef}>
      <label className="global-search">
        <Search size={15} />
        <input
          value={term}
          placeholder={placeholder}
          aria-label="Global search"
          onChange={(event) => setTerm(event.target.value)}
          onFocus={() => term.trim() && setOpen(true)}
          onKeyDown={(event) => {
            if (event.key === "Escape") reset();
          }}
        />
        {!term && shortcutLabel && <span className="global-search-shortcut">{shortcutLabel}</span>}
        {term && (
          <button type="button" className="global-search-clear" onClick={reset} aria-label="Clear search">
            <X size={14} />
          </button>
        )}
      </label>
      {open && term.trim() && (
        <div className="search-dropdown">
          {loading && !hasResults ? (
            <div className="search-empty">
              <Loader2 className="spin" size={16} />
              <span>Searching...</span>
            </div>
          ) : !hasResults ? (
            <div className="search-empty">
              <Search size={16} />
              <span>No matches</span>
            </div>
          ) : (
            <>
              {data.vulnerabilities.length > 0 && (
                <section className="search-section">
                  <header>Vulnerabilities</header>
                  {data.vulnerabilities.map((vuln) => {
                    const meta = SEVERITY_META[vuln.severity] || SEVERITY_META.low;
                    return (
                      <button key={`v-${vuln.id}`} type="button" className="search-item" onClick={() => goVuln(vuln)}>
                        <span className={cn("search-dot", vuln.severity)} />
                        <span className="search-item-main">
                          <strong>{clampText(vuln.title, 42)}</strong>
                          <small>
                            {meta.label} · {vuln.fact_id} · {vuln.project_name}
                          </small>
                        </span>
                      </button>
                    );
                  })}
                </section>
              )}
              {data.projects.length > 0 && (
                <section className="search-section">
                  <header>Projects</header>
                  {data.projects.map((project) => (
                    <button key={`p-${project.id}`} type="button" className="search-item" onClick={() => goProject(project)}>
                      <span className="search-icon">
                        <Folder size={15} />
                      </span>
                      <span className="search-item-main">
                        <strong>{clampText(project.title, 42)}</strong>
                        <small>{project.id}</small>
                      </span>
                    </button>
                  ))}
                </section>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function AuditPage({ setToast }) {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true);
    try {
      const list = await apiRequest("/api/audit?limit=100");
      setEntries(Array.isArray(list) ? list : []);
    } catch (error) {
      if (!silent) setToast({ type: "danger", message: error.message || "Could not load the audit log" });
    } finally {
      if (!silent) setLoading(false);
    }
  }, [setToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const timer = window.setInterval(() => load({ silent: true }), 10000);
    return () => window.clearInterval(timer);
  }, [load]);

  const actionTone = (action) => {
    const value = String(action || "");
    if (/delete|remove|clear|disable/i.test(value)) return "danger";
    if (/create|add|export|complete|enable/i.test(value)) return "success";
    if (/update|status|reopen|edit|patch/i.test(value)) return "info";
    return "muted";
  };

  return (
    <>
      <PageHeader
        icon={History}
        title="Audit log"
        subtitle="Time, target, and detail for key actions"
        actions={
          <button className="ghost-button" type="button" onClick={() => load()}>
            <RefreshCw size={18} />
            Refresh
          </button>
        }
      />
      <section className="content-wrap vulnerability-report-page">
        <article className="vuln-table-card audit-card">
          <header className="vuln-table-title">
            <div>
              <h2>Activity</h2>
              <p>The latest 100 key actions, refreshed every 10 seconds</p>
            </div>
            <span className="status-pill">
              <span className="dot success" />
              <span>{entries.length}</span>
            </span>
          </header>
          <div className="audit-head">
            <span>Time</span>
            <span>Action</span>
            <span>Summary</span>
            <span>Target</span>
            <span>Actor</span>
          </div>
          <div className="audit-body">
            {loading ? (
              <EmptyState icon={Loader2} title="Loading the audit log" />
            ) : entries.length === 0 ? (
              <EmptyState icon={History} title="No audit entries yet" subtitle="Key actions will show up here." />
            ) : (
              entries.map((entry) => (
                <div className="audit-row" key={entry.id}>
                  <time>{formatTime(entry.created_at)}</time>
                  <span>
                    <Badge tone={actionTone(entry.action)}>{entry.action}</Badge>
                  </span>
                  <div className="audit-summary-cell">
                    <strong title={entry.summary}>{entry.summary}</strong>
                    {entry.detail && <span title={entry.detail}>{clampText(entry.detail, 80)}</span>}
                  </div>
                  <code title={`${entry.target_type || ""} ${entry.target_id || ""}`.trim()}>
                    {entry.target_type ? `${entry.target_type}${entry.target_id ? `:${entry.target_id}` : ""}` : "-"}
                  </code>
                  <span className="audit-actor">{entry.actor || "-"}</span>
                </div>
              ))
            )}
          </div>
        </article>
      </section>
    </>
  );
}

function AuthPage({ onAuthed, setToast }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ username: "", password: "", confirm_password: "", captcha_answer: "" });
  const [captcha, setCaptcha] = useState(null);
  const [loading, setLoading] = useState(false);
  const [captchaLoading, setCaptchaLoading] = useState(false);
  const [authMessage, setAuthMessage] = useState(null);
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [cooldownUntil, setCooldownUntil] = useState(0);
  const [clock, setClock] = useState(Date.now());

  const loadCaptcha = useCallback(async () => {
    setCaptchaLoading(true);
    try {
      const data = await apiRequest("/api/auth/captcha");
      setCaptcha(data);
      setForm((prev) => ({ ...prev, captcha_answer: "" }));
    } catch (error) {
      setCaptcha(null);
      throw error;
    } finally {
      setCaptchaLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCaptcha().catch((error) => setToast({ type: "danger", message: error.message }));
  }, [loadCaptcha, setToast]);

  useEffect(() => {
    if (!cooldownUntil) return undefined;
    const timer = window.setInterval(() => setClock(Date.now()), 300);
    return () => window.clearInterval(timer);
  }, [cooldownUntil]);

  const isRegister = mode === "register";
  const cooldownSeconds = Math.max(0, Math.ceil((cooldownUntil - clock) / 1000));
  const passwordsMismatch = isRegister && form.confirm_password.length > 0 && form.password !== form.confirm_password;
  const requiredFilled =
    form.username.trim() &&
    form.password &&
    form.captcha_answer.trim() &&
    (!isRegister || form.confirm_password);
  const canSubmit = Boolean(
    requiredFilled && captcha?.captcha_id && !passwordsMismatch && !loading && !captchaLoading && cooldownSeconds === 0,
  );
  const submitLabel = loading
    ? isRegister
      ? "Creating account..."
      : "Signing in..."
    : cooldownSeconds > 0
      ? `${cooldownSeconds} s until you can retry`
      : isRegister
        ? "Create account"
        : "Sign in";

  const updateField = (key, value) => {
    setForm((prev) => ({ ...prev, [key]: value }));
    if (key === "username") {
      setFailedAttempts(0);
      setCooldownUntil(0);
    }
    setAuthMessage(null);
  };

  const switchMode = (nextMode) => {
    setMode(nextMode);
    setAuthMessage(null);
    setLoading(false);
    setFailedAttempts(0);
    setCooldownUntil(0);
    setForm((prev) => ({ ...prev, password: "", confirm_password: "", captcha_answer: "" }));
    loadCaptcha().catch(() => {});
  };

  const describeAuthError = (error) => {
    if (error?.status === 400 && String(error.message || "").toLowerCase().includes("captcha")) {
      return { type: "warning", title: "Invalid captcha", body: error.message };
    }
    if (error?.status === 401) {
      return {
        type: "danger",
        title: "Incorrect username or password",
        body: "Check the username, password, and captcha. For safety, this does not reveal whether the account exists.",
      };
    }
    if (error?.status === 409 && isRegister) {
      return { type: "warning", title: "Username unavailable", body: "That username is taken. Try another." };
    }
    if (error?.status === 422) {
      return {
        type: "warning",
        title: "Input does not meet the requirements",
        body: isRegister ? "Usernames must be 3–32 characters, and passwords at least 8." : "Enter a username, password, and captcha.",
      };
    }
    if (error?.status === 429) {
      return {
        type: "danger",
        title: "Too many sign-in attempts",
        body: "This account failed too many times and is temporarily locked. Try again in 15 minutes.",
      };
    }
    return { type: "danger", title: "Authentication request failed", body: "The service did not return a result. Check the network and try again." };
  };

  const submit = async (event) => {
    event.preventDefault();
    if (loading) return;
    if (!captcha?.captcha_id) {
      setAuthMessage({ type: "warning", title: "Captcha is not ready", body: "Refresh the captcha before submitting." });
      return;
    }
    if (passwordsMismatch) {
      setAuthMessage({ type: "warning", title: "Passwords do not match", body: "Re-enter the password you want to set." });
      return;
    }
    setAuthMessage({ type: "info", title: isRegister ? "Creating the account" : "Checking credentials", body: "Please wait. Do not submit again." });
    setLoading(true);
    try {
      await apiRequest(`/api/auth/${isRegister ? "register" : "login"}`, {
        method: "POST",
        body: {
          username: form.username.trim(),
          password: form.password,
          captcha_id: captcha?.captcha_id,
          captcha_answer: form.captcha_answer,
        },
      });
      setFailedAttempts(0);
      setCooldownUntil(0);
      setAuthMessage({ type: "success", title: "Signed in", body: "Opening the workspace." });
      await onAuthed();
    } catch (error) {
      const message = describeAuthError(error);
      setAuthMessage(message);
      if (!isRegister && error?.status === 401) {
        setFailedAttempts((current) => {
          const next = current + 1;
          if (next >= 3) {
            setCooldownUntil(Date.now() + Math.min(10, next * 2) * 1000);
            setClock(Date.now());
          }
          return next;
        });
      }
      await loadCaptcha().catch(() => {});
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-shell">
      <section className="auth-card auth-split-card">
        <aside className="auth-showcase" aria-hidden="true">
          <div className="auth-brand">
            <span className="auth-brand-logo">
              <img src="/static/rabbit-icon.png" alt="" />
            </span>
            <strong>{APP_NAME}</strong>
          </div>
          <div className="auth-hero-visual">
            <span className="cube cube-a" />
            <span className="cube cube-b" />
            <span className="cube cube-c" />
            <span className="orbit-line orbit-a" />
            <span className="orbit-line orbit-b" />
            <img src="/static/rabbit-icon.png" alt="" />
            <span className="shield-badge">
              <CheckCircle2 size={34} />
            </span>
          </div>
          <div className="auth-copy">
            <h2>
              Continuous security exploration
              <br />
              Leave attacks <span>nowhere to hide</span>
            </h2>
            <p>Rabbit helps security teams automate asset discovery, vulnerability verification, and attack-surface management.</p>
          </div>
          <div className="auth-capabilities">
            <span>
              <ShieldAlert size={16} />
              Asset discovery
            </span>
            <span>
              <CheckCircle2 size={16} />
              Verification
            </span>
            <span>
              <Network size={16} />
              Attack surface
            </span>
          </div>
        </aside>

        <main className="auth-form-panel">
          {mode === "register" && (
            <button className="auth-back" type="button" onClick={() => switchMode("login")} disabled={loading}>
              <ArrowLeft size={16} />
              Back to sign in
            </button>
          )}
          <div className="auth-title align-left">
            <h1>{isRegister ? "Create account" : "Welcome back"}</h1>
            <p>{isRegister ? "Join the Rabbit security workspace" : "Sign in to continue"}</p>
          </div>
          {mode === "login" && (
            <div className="segmented auth-login-tabs">
              <button className="active" type="button">
                Account
              </button>
              <button
                type="button"
                onClick={() =>
                  setAuthMessage({
                    type: "warning",
                    title: "Phone sign-in is not available",
                    body: "Use an account instead.",
                  })
                }
              >
                Phone
              </button>
            </div>
          )}
          <div className="auth-security-note">
            <ShieldCheck size={16} />
            <span>Captcha, lockout, and server sessions are enabled</span>
          </div>
          {authMessage && (
            <div className={cn("auth-inline-alert", authMessage.type)} role="alert" aria-live="polite">
              {authMessage.type === "success" ? <CheckCircle2 size={18} /> : <AlertCircle size={18} />}
              <div>
                <strong>{authMessage.title}</strong>
                <p>{authMessage.body}</p>
                {!isRegister && failedAttempts > 0 && authMessage.type === "danger" && (
                  <small>This browser has recorded {failedAttempts} failures. The server rate-limits each account on a 15-minute window.</small>
                )}
              </div>
            </div>
          )}
          <form className="stack-form auth-stack-form" onSubmit={submit}>
            <label>
              <span>Username</span>
              <input
                autoComplete="username"
                required
                disabled={loading}
                value={form.username}
                onChange={(event) => updateField("username", event.target.value)}
                placeholder="Username"
              />
            </label>
            <label>
              <span>Password</span>
              <input
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                type="password"
                required
                disabled={loading}
                value={form.password}
                onChange={(event) => updateField("password", event.target.value)}
                placeholder={mode === "login" ? "Password" : "Choose a password"}
              />
            </label>
            {mode === "register" && (
              <label>
                <span>Confirm password</span>
                <input
                  autoComplete="new-password"
                  type="password"
                  required
                  disabled={loading}
                  aria-invalid={passwordsMismatch}
                  className={passwordsMismatch ? "input-invalid" : ""}
                  value={form.confirm_password}
                  onChange={(event) => updateField("confirm_password", event.target.value)}
                  placeholder="Re-enter the password"
                />
                {passwordsMismatch && <small className="field-hint danger">The passwords do not match</small>}
              </label>
            )}
            <label>
              <span>Captcha</span>
              <div className="captcha-row">
                <input
                  required
                  disabled={loading || captchaLoading}
                  inputMode="numeric"
                  value={form.captcha_answer}
                  onChange={(event) => updateField("captcha_answer", event.target.value)}
                  placeholder="Enter the result"
                />
                <button className="captcha-chip" type="button" onClick={loadCaptcha} disabled={loading || captchaLoading}>
                  {captchaLoading ? "Loading" : captcha?.question || "Refresh"}
                  <RefreshCw className={captchaLoading ? "spin" : ""} size={15} />
                </button>
              </div>
            </label>
            <button className="primary-button auth-submit" type="submit" disabled={!canSubmit}>
              {loading ? <Loader2 className="spin" size={18} /> : <Lock size={18} />}
              {submitLabel}
            </button>
          </form>
          <p className="auth-switch">
            {mode === "login" ? "No account yet?" : "Already have an account?"}
            <button type="button" onClick={() => switchMode(mode === "login" ? "register" : "login")} disabled={loading}>
              {mode === "login" ? "Create one" : "Back to sign in"}
            </button>
          </p>
        </main>
      </section>
    </div>
  );
}

function DashboardPage({ runAction, setToast }) {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [projects, setProjects] = useState([]);
  const [workers, setWorkers] = useState([]);
  const [workerObservability, setWorkerObservability] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [newOpen, setNewOpen] = useState(false);

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true);
    try {
      const [vulnList, projectList, workerList, workerTelemetry] = await Promise.all([
        apiRequest("/api/vulnerabilities"),
        apiRequest("/projects"),
        apiRequest("/api/workers").catch(() => []),
        apiRequest("/api/workers/observability").catch(() => null),
      ]);
      setVulnerabilities(Array.isArray(vulnList) ? vulnList : []);
      setProjects(Array.isArray(projectList) ? projectList : []);
      setWorkers(Array.isArray(workerList) ? workerList : []);
      setWorkerObservability(workerTelemetry);
      setLastUpdated(new Date());
    } catch (error) {
      if (!silent) setToast({ type: "danger", message: error.message || "Could not load the dashboard" });
    } finally {
      if (!silent) setLoading(false);
    }
  }, [setToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const timer = window.setInterval(() => load({ silent: true }), 8000);
    return () => window.clearInterval(timer);
  }, [load]);

  const statusDistribution = useMemo(() => buildStatusDistribution(vulnerabilities), [vulnerabilities]);
  const trendData = useMemo(() => buildVulnerabilityTrend(vulnerabilities), [vulnerabilities]);
  const severityTop = useMemo(() => buildSeverityTop(vulnerabilities), [vulnerabilities]);
  const recentActivity = useMemo(
    () =>
      [...vulnerabilities]
        .sort((a, b) => String(b.discovered_at || "").localeCompare(String(a.discovered_at || "")))
        .slice(0, 5),
    [vulnerabilities],
  );

  const projectCounts = useMemo(() => {
    const total = projects.length;
    const active = projects.filter((project) => project.status === "active").length;
    const completed = projects.filter((project) => project.status === "completed").length;
    const stopped = projects.filter((project) => project.status === "stopped").length;
    return { total, active, completed, stopped };
  }, [projects]);

  const recentProjects = useMemo(
    () =>
      [...projects]
        .sort((a, b) => String(b.updated_at || b.created_at || "").localeCompare(String(a.updated_at || a.created_at || "")))
        .slice(0, 5),
    [projects],
  );

  const workerCounts = useMemo(() => {
    if (workerObservability?.summary) {
      return {
        total: workerObservability.summary.total || 0,
        online: workerObservability.summary.online || 0,
        running: workerObservability.summary.busy || 0,
        idle: workerObservability.summary.idle || 0,
        offline: workerObservability.summary.offline || 0,
      };
    }
    return workers.reduce(
      (acc, worker) => {
        acc.total += 1;
        if (worker.status === "busy") acc.running += 1;
        if (worker.status === "idle") acc.idle += 1;
        if (worker.status === "idle" || worker.status === "busy") acc.online += 1;
        else acc.offline += 1;
        return acc;
      },
      { total: 0, online: 0, running: 0, idle: 0, offline: 0 },
    );
  }, [workerObservability, workers]);

  const workerHighlights = useMemo(() => {
    const rank = { busy: 0, idle: 1, offline: 2, disabled: 3 };
    return [...workers]
      .sort((left, right) => {
        const rankDelta = (rank[left.status] ?? 99) - (rank[right.status] ?? 99);
        if (rankDelta !== 0) return rankDelta;
        return String(left.name || "").localeCompare(String(right.name || ""));
      })
      .slice(0, 5);
  }, [workers]);

  const projectStatusMeta =
    {
      active: { label: "Running", tone: "success" },
      completed: { label: "Completed", tone: "info" },
      stopped: { label: "Stopped", tone: "warning" },
    };

  const quickActions = [
    { key: "new", label: "New project", desc: "Set an origin, a goal, and hints", icon: Plus, onClick: () => setNewOpen(true) },
    { key: "vulns", label: "Vulnerability reports", desc: "Review and manage findings", icon: AlertTriangle, onClick: () => go("#/vulnerabilities") },
    { key: "workers", label: "Workers", desc: "Status and model configuration", icon: Monitor, onClick: () => go("#/workers") },
    { key: "templates", label: "Templates", desc: "Reuse project templates", icon: FileText, onClick: () => go("#/templates") },
    { key: "audit", label: "Audit log", desc: "Review key actions", icon: History, onClick: () => go("#/audit") },
  ];

  return (
    <>
      <PageHeader
        icon={Home}
        title="Dashboard"
        subtitle="Projects, risk, workers, and recent activity"
        actions={
          <>
            <div className="status-pill">
              <span className="dot success" />
              <span>{lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString("en-US")}` : "Not updated yet"}</span>
            </div>
            <button className="ghost-button" type="button" onClick={() => load()}>
              <RefreshCw size={18} />
              Refresh
            </button>
          </>
        }
      />
      <section className="content-wrap dashboard-shell">
        {loading ? (
          <EmptyState icon={Loader2} title="Loading the dashboard" />
        ) : (
          <>
            <div className="metric-grid dashboard-metric-grid">
              <MetricCard
                label="All projects"
                value={projectCounts.total}
                tone="info"
                icon={Folder}
                description="Total projects"
                onClick={() => go("#/projects")}
              />
              <MetricCard
                label="Running projects"
                value={projectCounts.active}
                tone="success"
                icon={Play}
                description="Currently running"
                onClick={() => queueRoutePreset(PROJECT_PRESET_STORAGE_KEY, { status: "active" }, "#/projects")}
              />
              <MetricCard
                label="Vulnerabilities"
                value={statusDistribution.total || 0}
                tone="high"
                icon={ShieldAlert}
                description="Findings currently tracked"
                onClick={() => go("#/vulnerabilities")}
              />
              <MetricCard
                label="Online workers"
                value={workerCounts.online}
                tone="violet"
                icon={Monitor}
                description="Ready to take tasks"
                onClick={() => queueRoutePreset(WORKER_PRESET_STORAGE_KEY, { status: "online" }, "#/workers")}
              />
            </div>
            <div className="dashboard-analytics-grid">
              <VulnerabilityTrend data={trendData} />
              <div className="dashboard-side-stack">
                <VulnerabilityStatusDistribution data={statusDistribution} />
                <SeverityTopList items={severityTop} onSelect={(item) => queueVulnerabilityFocus(item.id)} />
              </div>
            </div>
            <div className="dashboard-ops-grid">
              <section className="vuln-analysis-card dashboard-entity-card">
                <header>
                  <h3>Projects</h3>
                  <span>{projectCounts.total} projects</span>
                </header>
                <div className="dashboard-inline-stats">
                  <MiniStat label="Running" value={projectCounts.active} />
                  <MiniStat label="Completed" value={projectCounts.completed} />
                  <MiniStat label="Stopped" value={projectCounts.stopped} />
                </div>
                {recentProjects.length === 0 ? (
                  <p className="analysis-empty">No project data</p>
                ) : (
                  <div className="dashboard-entity-list">
                    {recentProjects.map((project) => {
                      const meta = projectStatusMeta[project.status] || projectStatusMeta.active;
                      return (
                        <button
                          key={project.id}
                          className="dashboard-entity-item"
                          type="button"
                          onClick={() => go(`#/projects/${project.id}`)}
                        >
                          <div className="dashboard-entity-copy">
                            <strong title={project.title}>{project.title}</strong>
                            <small>
                              {project.id} · Updated {formatTime(project.updated_at || project.created_at)}
                            </small>
                          </div>
                          <Badge tone={meta.tone}>{meta.label}</Badge>
                        </button>
                      );
                    })}
                  </div>
                )}
              </section>
              <section className="vuln-analysis-card dashboard-entity-card">
                <header>
                  <h3>Worker status</h3>
                  <span>{workerCounts.total} workers</span>
                </header>
                <div className="dashboard-inline-stats">
                  <MiniStat label="Online" value={workerCounts.online} />
                  <MiniStat label="Running" value={workerCounts.running} />
                  <MiniStat label="Idle" value={workerCounts.idle} />
                  <MiniStat label="Offline" value={workerCounts.offline} />
                </div>
                {workerHighlights.length === 0 ? (
                  <p className="analysis-empty">No worker data</p>
                ) : (
                  <div className="dashboard-entity-list">
                    {workerHighlights.map((worker) => {
                      const meta = STATUS_META[worker.status] || STATUS_META.offline;
                      return (
                        <button
                          key={worker.name}
                          className="dashboard-entity-item"
                          type="button"
                          onClick={() => go("#/workers")}
                        >
                          <div className="dashboard-entity-copy">
                            <strong title={worker.name}>{worker.name}</strong>
                            <small title={worker.current_task || ""}>
                              {worker.current_task
                                ? clampText(worker.current_task, 56)
                                : `Last heartbeat ${relativeHeartbeat(worker.last_heartbeat_seconds_ago)}`}
                            </small>
                          </div>
                          <Badge tone={meta.tone}>{meta.label}</Badge>
                        </button>
                      );
                    })}
                  </div>
                )}
              </section>
            </div>
            <div className="dashboard-bottom-grid">
              <section className="vuln-analysis-card dashboard-activity-card">
                <header>
                  <h3>Recent activity</h3>
                  <span>Latest findings</span>
                </header>
                {recentActivity.length === 0 ? (
                  <p className="analysis-empty">No vulnerability activity</p>
                ) : (
                  <div className="dashboard-activity-list">
                    {recentActivity.map((item) => {
                      const meta = SEVERITY_META[item.severity] || SEVERITY_META.low;
                      return (
                        <button
                          key={`activity-${item.id}`}
                          className="dashboard-activity-item"
                          type="button"
                          onClick={() => queueVulnerabilityFocus(item.id)}
                        >
                          <div className="dashboard-activity-head">
                            <Badge tone={meta.tone}>{meta.label}</Badge>
                            <code>{item.fact_id}</code>
                          </div>
                          <strong title={item.title}>{item.title}</strong>
                          <p>
                            {item.project_name} · {formatTime(item.discovered_at)}
                          </p>
                        </button>
                      );
                    })}
                  </div>
                )}
              </section>
              <section className="vuln-analysis-card dashboard-quick-card">
                <header>
                  <h3>Shortcuts</h3>
                  <span>Common destinations</span>
                </header>
                <div className="quick-action-grid">
                  {quickActions.map((action) => (
                    <button
                      key={action.key}
                      className={cn("quick-action", action.key)}
                      type="button"
                      onClick={action.onClick}
                    >
                      <span className="quick-action-chip">
                        <action.icon size={20} />
                      </span>
                      <span className="quick-action-text">
                        <strong>{action.label}</strong>
                        <small>{action.desc}</small>
                      </span>
                      <ChevronRight size={18} />
                    </button>
                  ))}
                </div>
              </section>
            </div>
          </>
        )}
      </section>
      {newOpen && (
        <NewProjectModal
          onClose={() => setNewOpen(false)}
          onCreated={(projectId) => {
            setNewOpen(false);
            go(`#/projects/${projectId}`);
          }}
          runAction={runAction}
        />
      )}
    </>
  );
}

function ProjectsPage({ runAction, setToast, confirmAction }) {
  const [projects, setProjects] = useState([]);
  const [campaignByProjectId, setCampaignByProjectId] = useState({});
  const [campaignLoadingByProjectId, setCampaignLoadingByProjectId] = useState({});
  const [loading, setLoading] = useState(true);
  const [newOpen, setNewOpen] = useState(false);
  const [reopenTarget, setReopenTarget] = useState(null);
  const [statusFilter, setStatusFilter] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [pageSize, setPageSize] = useState(10);
  const [page, setPage] = useState(1);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setCampaignByProjectId({});
      setCampaignLoadingByProjectId({});
      setProjects(await apiRequest("/projects"));
    } catch (error) {
      setToast({ type: "danger", message: error.message || "Could not load projects" });
    } finally {
      setLoading(false);
    }
  }, [setToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const preset = consumeRoutePreset(PROJECT_PRESET_STORAGE_KEY);
    if (preset?.status) setStatusFilter(String(preset.status));
  }, []);

  const counts = useMemo(() => {
    const total = projects.length;
    const active = projects.filter((project) => project.status === "active").length;
    const completed = projects.filter((project) => project.status === "completed").length;
    const stopped = projects.filter((project) => project.status === "stopped").length;
    return { total, active, completed, stopped };
  }, [projects]);
  const filteredProjects = useMemo(() => {
    const keyword = searchTerm.trim().toLowerCase();
    return projects.filter((project) => {
      if (statusFilter !== "all" && project.status !== statusFilter) return false;
      if (keyword) {
        const blob = [project.title, project.id, project.decide?.worker, project.decide?.trigger]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!blob.includes(keyword)) return false;
      }
      return true;
    });
  }, [projects, searchTerm, statusFilter]);
  const totalPages = Math.max(1, Math.ceil(filteredProjects.length / pageSize));
  const visibleProjects = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredProjects.slice(start, start + pageSize);
  }, [filteredProjects, page, pageSize]);

  // Campaign prefetch. Depends only on the stable id+status string of the
  // visible projects — NOT on the campaign state maps. This prevents the
  // effect from re-running when it itself mutates campaignByProjectId /
  // campaignLoadingByProjectId (which previously caused a cancel/reload race
  // that could strand a card in the "Summarizing" loading state).
  const visibleProjectKey = visibleProjects.map((p) => `${p.id}:${p.status}`).join(",");
  useEffect(() => {
    if (!visibleProjectKey) return undefined;
    const ids = visibleProjects.map((p) => p.id);

    let cancelled = false;
    setCampaignLoadingByProjectId((current) => {
      const next = { ...current };
      ids.forEach((id) => {
        next[id] = true;
      });
      return next;
    });

    Promise.all(
      visibleProjects.map(async (project) => {
        try {
          // Race against a timeout so a hung endpoint can never lock the card.
          const campaign = await Promise.race([
            apiRequest(`/api/projects/${project.id}/campaign`),
            new Promise((resolve) => setTimeout(() => resolve(null), 8000)),
          ]);
          return [project.id, campaign];
        } catch {
          return [project.id, null];
        }
      }),
    ).then((entries) => {
      if (cancelled) return;
      setCampaignByProjectId((current) => ({
        ...current,
        ...Object.fromEntries(entries),
      }));
      setCampaignLoadingByProjectId((current) => {
        const next = { ...current };
        ids.forEach((id) => {
          delete next[id];
        });
        return next;
      });
    });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visibleProjectKey]);

  useEffect(() => {
    setPage((current) => Math.min(current, totalPages));
  }, [totalPages]);

  useEffect(() => {
    setPage(1);
  }, [pageSize, searchTerm, statusFilter]);

  const projectTabs = [
    { key: "all", label: "All", count: counts.total, tone: "info" },
    { key: "active", label: "Running", count: counts.active, tone: "success" },
    { key: "completed", label: "Completed", count: counts.completed, tone: "info" },
    { key: "stopped", label: "Stopped", count: counts.stopped, tone: "warning" },
  ];

  const deleteProject = async (project) => {
    const ok = await confirmAction({
      title: "Delete project",
      message: `Delete project "${project.title}"? This cannot be undone.`,
      tone: "danger",
      confirmLabel: "Delete",
    });
    if (!ok) return;
    await runAction("Project deleted", () => apiRequest(`/projects/${project.id}`, { method: "DELETE" }));
    await load();
  };

  const updateStatus = async (project, status) => {
    await runAction("Project status updated", () =>
      apiRequest(`/projects/${project.id}/status`, { method: "PUT", body: { status } }),
    );
    await load();
  };

  const reopenProject = (project) => {
    setReopenTarget(project);
  };

  const submitReopen = async (description) => {
    const project = reopenTarget;
    if (!project) return;
    await runAction("Project reopened", () =>
      apiRequest(`/projects/${project.id}/reopen`, {
        method: "POST",
        body: { description, creator: HUMAN_WORKER },
      }),
    );
    setReopenTarget(null);
    await load();
  };

  return (
    <>
      <PageHeader
        icon={Folder}
        title="Projects"
        subtitle="Fact-graph workspace for a goal"
        actions={
          <>
            <div className="status-pill project-running-pill">
              <span className="dot success" />
              <span>{counts.active}  running</span>
            </div>
            <button className="primary-button compact" type="button" onClick={() => setNewOpen(true)}>
              <Plus size={18} />
              New project
            </button>
            <button className="primary-outline compact" type="button" onClick={load}>
              <RefreshCw size={18} />
              Refresh
            </button>
          </>
        }
      />
      <section className="content-wrap project-dashboard-page">
        <div className="project-summary-grid">
          <ProjectSummaryCard
            label="All projects"
            value={counts.total}
            description="Total projects"
            tone="blue"
            icon={Folder}
          />
          <ProjectSummaryCard
            label="Running"
            value={counts.active}
            description="Projects currently running"
            tone="green"
            icon={Play}
          />
          <ProjectSummaryCard
            label="Completed"
            value={counts.completed}
            description="Projects that have finished"
            tone="slate"
            icon={CheckCircle2}
          />
          <ProjectSummaryCard
            label="Stopped"
            value={counts.stopped}
            description="Projects that are stopped"
            tone="violet"
            icon={Pause}
          />
        </div>
        <div className="project-toolbar">
          <div className="project-filter-tabs" role="tablist" aria-label="Filter projects by status">
            {projectTabs.map((tab) => (
              <button
                key={tab.key}
                type="button"
                role="tab"
                aria-selected={statusFilter === tab.key}
                className={cn("project-filter-tab", statusFilter === tab.key && "active", tab.tone)}
                onClick={() => setStatusFilter(tab.key)}
              >
                <span>{tab.label}</span>
                <strong>{tab.count}</strong>
              </button>
            ))}
          </div>
          <label className="project-search">
            <Search size={15} />
            <input
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
              placeholder="Search project name, id, owner, tags..."
            />
          </label>
        </div>
        {loading ? (
          <EmptyState icon={Loader2} title="Loading projects" />
        ) : filteredProjects.length === 0 ? (
          <EmptyState
            icon={Folder}
            title={projects.length === 0 ? "No projects yet" : "No projects match this filter"}
            subtitle={projects.length === 0 ? "Create a project and Rabbit will build a fact graph from the origin, goal, and hints." : "Change the filter and try again."}
            action={
              <button className="primary-button compact" type="button" onClick={() => setNewOpen(true)}>
                <Plus size={18} />
                New project
              </button>
            }
          />
        ) : (
          <>
            <div className="project-grid project-grid-redesigned">
            {visibleProjects.map((project) => (
              <ProjectCard
                key={project.id}
                project={project}
                campaign={campaignByProjectId[project.id]}
                campaignLoading={Boolean(campaignLoadingByProjectId[project.id])}
                onDelete={() => deleteProject(project)}
                onStop={() => updateStatus(project, "stopped")}
                onStart={() => updateStatus(project, "active")}
                onReopen={() => reopenProject(project)}
              />
            ))}
            </div>
            <div className="project-list-footer">
              <span>{filteredProjects.length} projects{filteredProjects.length !== projects.length ? ` / ${projects.length} total` : ""}</span>
              <div className="project-list-footer-controls">
                <label className="pagination-size">
                  <select
                    value={pageSize}
                    onChange={(event) => {
                      setPageSize(Number(event.target.value) || 10);
                      setPage(1);
                    }}
                  >
                    <option value="10">10 / page</option>
                    <option value="20">20 / page</option>
                    <option value="50">50 / page</option>
                  </select>
                </label>
                <div className="pagination project-pagination">
                  <button
                    type="button"
                    className="nav"
                    disabled={page <= 1}
                    onClick={() => setPage((current) => Math.max(1, current - 1))}
                  >
                    <ChevronLeft size={16} />
                    Previous
                  </button>
                  <button type="button" className="active">
                    {page} / {totalPages}
                  </button>
                  <button
                    type="button"
                    className="nav"
                    disabled={page >= totalPages}
                    onClick={() => setPage((current) => Math.min(totalPages, current + 1))}
                  >
                    Next
                    <ChevronRight size={16} />
                  </button>
                </div>
              </div>
            </div>
          </>
        )}
      </section>
      {newOpen && (
        <NewProjectModal
          onClose={() => setNewOpen(false)}
          onCreated={(projectId) => {
            setNewOpen(false);
            go(`#/projects/${projectId}`);
          }}
          runAction={runAction}
        />
      )}
      {reopenTarget && (
        <TextActionModal
          title={`Reopen "${reopenTarget.title}"`}
          label="Reason for reopening"
          placeholder="Additional verification or a new pass"
          defaultValue="Additional verification or a new pass"
          submitLabel="Reopen"
          onClose={() => setReopenTarget(null)}
          onSubmit={submitReopen}
        />
      )}
    </>
  );
}

function ProjectCard({ project, campaign, campaignLoading, onDelete, onStop, onStart, onReopen }) {
  const statusMeta =
    {
      active: { label: "Running", tone: "success" },
      completed: { label: "Completed", tone: "info" },
      stopped: { label: "Stopped", tone: "warning" },
    }[project.status] || STATUS_META.active;
  const updatedAt = formatTime(project.updated_at || project.created_at);
  return (
    <article className="project-card">
      <div className="project-card-head">
        <button className="project-open" type="button" onClick={() => go(`#/projects/${project.id}`)}>
          <span className="project-folder">
            <Folder size={24} />
          </span>
          <span className="project-main">
            <span className="project-title-row">
              <strong>{project.title}</strong>
              <Badge tone={statusMeta.tone}>{statusMeta.label}</Badge>
            </span>
            <span className="project-sub">
              {project.id} · Created {formatTime(project.created_at)}
            </span>
          </span>
        </button>
        <details className="project-more-menu">
          <summary aria-label="More actions">
            <MoreVertical size={18} />
          </summary>
          <div className="project-more-panel">
            <button type="button" onClick={() => go(`#/projects/${project.id}`)}>
              <Eye size={15} />
              Open project
            </button>
            {project.status === "active" && (
              <button type="button" onClick={onStop}>
                <Square size={15} />
                Stop project
              </button>
            )}
            {project.status === "stopped" && (
              <button type="button" onClick={onStart}>
                <Play size={15} />
                Resume
              </button>
            )}
            {project.status === "completed" && (
              <button type="button" onClick={onReopen}>
                <RefreshCw size={15} />
                Reopen
              </button>
            )}
            <button type="button" className="danger" onClick={onDelete}>
              <Trash2 size={15} />
              Delete project
            </button>
          </div>
        </details>
      </div>
      <div className="project-stats">
        <MiniStat label="Fact" value={project.fact_count} />
        <MiniStat label="Step" value={project.step_count ?? project.intent_count} />
        <MiniStat label="In progress" value={project.working_step_count ?? project.working_intent_count} />
      </div>
      <div className="project-meta-row">
        <div>
          <span>
            <User size={14} />
            Owner
          </span>
          <strong>Not set</strong>
        </div>
        <div>
          <span>
            <CalendarDays size={14} />
            Updated
          </span>
          <strong>{updatedAt}</strong>
        </div>
        <div>
          <span>
            <Tag size={14} />
            Tags
          </span>
          <strong>Not set</strong>
        </div>
      </div>
      <ProjectCampaignPreview campaign={campaign} loading={campaignLoading} />
      {project.decide && (
        <div className="decide-strip project-decide-strip">
          <Activity size={16} />
          <span>{project.decide.worker}</span>
          <span>{project.decide.trigger}</span>
        </div>
      )}
      <div className="card-actions project-action-row">
        <button className="ghost-button compact project-action-button" type="button" onClick={() => go(`#/projects/${project.id}`)}>
          <Eye size={16} />
          Open
        </button>
        {project.status === "active" && (
          <button className="ghost-button compact warning project-action-button" type="button" onClick={onStop}>
            <Square size={16} />
            Stop
          </button>
        )}
        {project.status === "stopped" && (
          <button className="ghost-button compact project-action-button" type="button" onClick={onStart}>
            <Play size={16} />
            Resume
          </button>
        )}
        {project.status === "completed" && (
          <button className="ghost-button compact project-action-button" type="button" onClick={onReopen}>
            <RefreshCw size={16} />
            Reopen
          </button>
        )}
        <button className="ghost-button compact danger project-action-button" type="button" onClick={onDelete}>
          <Trash2 size={16} />
          Delete
        </button>
      </div>
    </article>
  );
}

function ProjectCampaignPreview({ campaign, loading }) {
  if (loading) {
    return (
      <section className="project-briefing loading" aria-live="polite">
        <div className="project-briefing-head">
          <span className="project-briefing-kicker">Campaign</span>
          <span className="project-briefing-loading">
            <Loader2 size={13} className="spin" />
            Summarizing
          </span>
        </div>
        <p className="project-briefing-lead">Building the campaign summary.</p>
      </section>
    );
  }

  if (!campaign) {
    return (
      <section className="project-briefing empty">
        <div className="project-briefing-head">
          <span className="project-briefing-kicker">Campaign</span>
          <Badge tone="muted">Unavailable</Badge>
        </div>
        <p className="project-briefing-lead">This project does not have a stable campaign summary yet.</p>
      </section>
    );
  }

  const goalMeta = campaignGoalMeta(campaign.goal_status);

  return (
    <section className="project-briefing">
      <div className="project-briefing-head">
        <span className="project-briefing-kicker">Campaign</span>
        <div className="project-briefing-badges">
          <Badge tone={goalMeta.tone}>{goalMeta.label}</Badge>
          {campaign.counts.high_value_vulnerabilities > 0 && (
            <span className="project-briefing-chip">{campaign.counts.high_value_vulnerabilities}  high-value</span>
          )}
        </div>
      </div>
      <p className="project-briefing-lead" title={campaign.lead}>
        {campaign.lead}
      </p>
      <div className="project-briefing-meta">
        <span>Open steps {campaign.counts.open_steps}</span>
        <span>Blockers {campaign.blockers.length}</span>
        <span>Next steps {campaign.next_steps.length}</span>
      </div>
    </section>
  );
}

function NewProjectModal({ onClose, onCreated, runAction, initial = null }) {
  const [form, setForm] = useState({
    title: initial?.title || "",
    origin: initial?.origin || "",
    goal: initial?.goal || "",
    hints: initial?.hints?.map((hint) => hint.content).join("\n") || "",
  });
  const [saving, setSaving] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      const detail = await runAction("Project created", () =>
        apiRequest("/projects", {
          method: "POST",
          body: {
            title: form.title,
            origin: form.origin,
            goal: form.goal,
            hints: parseHintLines(form.hints, HUMAN_WORKER),
          },
        }),
      );
      onCreated(detail.project.id);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="New project" subtitle="Set an origin, a goal, and any hints. Workers advance the fact graph from there." onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        <label>
          <span>Project name</span>
          <input value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} required />
        </label>
        <div className="two-col">
          <label>
            <span>Origin</span>
            <textarea
              value={form.origin}
              onChange={(event) => setForm({ ...form, origin: event.target.value })}
              rows={6}
              required
            />
          </label>
          <label>
            <span>Goal</span>
            <textarea
              value={form.goal}
              onChange={(event) => setForm({ ...form, goal: event.target.value })}
              rows={6}
              required
            />
          </label>
        </div>
        <label>
          <span>Initial hints</span>
          <textarea
            value={form.hints}
            onChange={(event) => setForm({ ...form, hints: event.target.value })}
            rows={4}
            placeholder="One hint per line"
          />
        </label>
        <div className="modal-footer">
          <button className="ghost-button" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary-button compact" type="submit" disabled={saving}>
            {saving ? <Loader2 className="spin" size={18} /> : <Plus size={18} />}
            Create project
          </button>
        </div>
      </form>
    </Modal>
  );
}

function ProjectWorkspace({ projectId, runAction, setToast, confirmAction }) {
  const [detail, setDetail] = useState(null);
  const [campaign, setCampaign] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [tab, setTab] = useState("details");
  const [modal, setModal] = useState(null);
  const [layout, setLayout] = useState("dagre_tb");

  const load = useCallback(async () => {
    try {
      const [project, events, synthesis] = await Promise.all([
        apiRequest(`/projects/${projectId}`),
        apiRequest(`/api/projects/${projectId}/timeline`).catch(() => []),
        apiRequest(`/api/projects/${projectId}/campaign`).catch(() => null),
      ]);
      setDetail(project);
      setTimeline(events);
      setCampaign(synthesis);
    } catch (error) {
      setCampaign(null);
      setToast({ type: "danger", message: error.message || "Could not load projects" });
    } finally {
      setLoading(false);
    }
  }, [projectId, setToast]);

  useEffect(() => {
    setLoading(true);
    setSelected(null);
    load();
  }, [load]);

  useEffect(() => {
    if (detail?.project?.status !== "active") return undefined;
    const timer = window.setInterval(load, 5000);
    return () => window.clearInterval(timer);
  }, [detail?.project?.status, load]);

  const project = detail?.project;
  const facts = detail?.facts || [];
  const steps = detail?.steps || [];
  const selectedFactIds = selected?.type === "fact" ? [selected.id] : facts.length ? ["origin"] : [];
  const selectedStep = selected?.type === "step" ? steps.find((step) => step.id === selected.id) : null;

  const updateTitle = () => {
    setModal("title");
  };

  const submitTitle = async (title) => {
    if (!title || title === project.title) {
      setModal(null);
      return;
    }
    await runAction("Project name updated", () =>
      apiRequest(`/projects/${project.id}/title`, { method: "PUT", body: { title } }),
    );
    setModal(null);
    await load();
  };

  const updateStatus = async (status) => {
    await runAction("Project status updated", () =>
      apiRequest(`/projects/${project.id}/status`, { method: "PUT", body: { status } }),
    );
    await load();
  };

  const deleteProject = async () => {
    const ok = await confirmAction({
      title: "Delete project",
      message: `Delete project "${project.title}"? This cannot be undone.`,
      tone: "danger",
      confirmLabel: "Delete",
    });
    if (!ok) return;
    await runAction("Project deleted", () => apiRequest(`/projects/${project.id}`, { method: "DELETE" }));
    go("#/projects");
  };

  const exportProject = async (format) => {
    await runAction(null, () => downloadFromApi(`/projects/${project.id}/export?format=${format}`, `${project.id}.${format}`));
  };

  if (loading) {
    return <EmptyState icon={Loader2} title="Loading the graph" />;
  }

  if (!detail) {
    return (
      <EmptyState
        icon={AlertTriangle}
        title="Project unavailable"
        action={
          <button className="primary-outline" type="button" onClick={() => go("#/projects")}>
            Back to projects
          </button>
        }
      />
    );
  }

  const status = STATUS_META[project.status] || STATUS_META.active;

  return (
    <>
      <section className="workspace-header">
        <button className="icon-button" type="button" onClick={() => go("#/projects")}>
          <ArrowLeft size={20} />
        </button>
        <div className="workspace-title">
          <span>{project.id}</span>
          <button type="button" onClick={updateTitle}>
            {project.title}
          </button>
          <Badge tone={status.tone}>{status.label}</Badge>
        </div>
        <div className="workspace-actions">
          <div className="status-pill">
            <span>{facts.length}  facts</span>
            <span>{steps.length}  steps</span>
          </div>
          <button className="ghost-button compact" type="button" onClick={() => exportProject("yaml")}>
            <Download size={16} />
            YAML
          </button>
          <button className="ghost-button compact" type="button" onClick={() => exportProject("timeline")}>
            <Clock size={16} />
            Timeline
          </button>
          {project.status === "active" ? (
            <button className="ghost-button compact warning" type="button" onClick={() => updateStatus("stopped")}>
              <Square size={16} />
              Stop
            </button>
          ) : project.status === "stopped" ? (
            <button className="ghost-button compact" type="button" onClick={() => updateStatus("active")}>
              <Play size={16} />
              Resume
            </button>
          ) : (
            <button className="ghost-button compact" type="button" onClick={() => setModal("reopen")}>
              <RefreshCw size={16} />
              Reopen
            </button>
          )}
          <button className="ghost-button compact danger" type="button" onClick={deleteProject}>
            <Trash2 size={16} />
            Delete
          </button>
          <button className="ghost-button compact" type="button" onClick={load}>
            <RefreshCw size={16} />
            Refresh
          </button>
        </div>
      </section>
      <section className="workspace-layout">
        <div className="graph-panel">
          <div className="graph-controls">
          <div className="graph-toolbar">
            <button className="ghost-button compact" type="button" aria-label="Fit graph" title="Fit graph" onClick={() => window.dispatchEvent(new Event("rabbit:fit-graph"))}>
              <Maximize2 size={16} />
            </button>
            <select value={layout} onChange={(event) => setLayout(event.target.value)}>
              <option value="dagre_tb">Dagre ↓</option>
              <option value="dagre_lr">Dagre →</option>
              <option value="klay_tb">Klay ↓</option>
              <option value="klay_lr">Klay →</option>
              <option value="elk_tb">ELK ↓</option>
              <option value="elk_lr">ELK →</option>
            </select>
          </div>
          <div className="graph-actions">
            <button className="primary-outline compact" type="button" onClick={() => setModal("intent")}>
              <Plus size={16} />
              Step
            </button>
            <button
              className="primary-outline compact success"
              type="button"
              onClick={() => setModal("conclude")}
              disabled={!selectedStep || selectedStep.to}
            >
              <CheckCircle2 size={16} />
              Complete
            </button>
            <button className="primary-outline compact warning" type="button" onClick={() => setModal("hint")}>
              <Sparkles size={16} />
              Hint
            </button>
            <button className="primary-outline compact" type="button" onClick={() => setModal("complete")}>
              <ShieldAlert size={16} />
              Conclude
            </button>
          </div>
          </div>
          <GraphCanvas detail={detail} selected={selected} onSelect={setSelected} layout={layout} />
        </div>
        <Inspector
          detail={detail}
          campaign={campaign}
          selected={selected}
          setSelected={setSelected}
          tab={tab}
          setTab={setTab}
          timeline={timeline}
          onRefresh={load}
          runAction={runAction}
        />
      </section>
      {modal === "intent" && (
        <IntentModal
          title="New step"
          fromIds={selectedFactIds}
          facts={facts}
          onClose={() => setModal(null)}
          onSubmit={async (payload) => {
            await runAction("Step created", () =>
              apiRequest(`/projects/${project.id}/steps`, { method: "POST", body: payload }),
            );
            setModal(null);
            await load();
          }}
        />
      )}
      {modal === "conclude" && selectedStep && (
        <TextActionModal
          title={`Complete step ${selectedStep.id}`}
          label="Resulting fact"
          onClose={() => setModal(null)}
          onSubmit={async (description) => {
            await runAction("Step completed", () =>
              apiRequest(`/projects/${project.id}/steps/${selectedStep.id}/conclude`, {
                method: "POST",
                body: { worker: selectedStep.worker || HUMAN_WORKER, description },
              }),
            );
            setModal(null);
            await load();
          }}
        />
      )}
      {modal === "hint" && (
        <TextActionModal
          title="Add a hint"
          label="Hint"
          onClose={() => setModal(null)}
          onSubmit={async (content) => {
            await runAction("Hint added", () =>
              apiRequest(`/projects/${project.id}/hints`, { method: "POST", body: { content, creator: HUMAN_WORKER } }),
            );
            setModal(null);
            await load();
          }}
        />
      )}
      {modal === "complete" && (
        <TextActionModal
          title="Conclude project"
          label="Conclusion"
          onClose={() => setModal(null)}
          onSubmit={async (description) => {
            await runAction("Project completed", () =>
              apiRequest(`/projects/${project.id}/complete`, {
                method: "POST",
                body: { from: selectedFactIds, worker: HUMAN_WORKER, description },
              }),
            );
            setModal(null);
            await load();
          }}
        />
      )}
      {modal === "reopen" && (
        <TextActionModal
          title="Reopen project"
          label="Reason for reopening"
          onClose={() => setModal(null)}
          onSubmit={async (description) => {
            await runAction("Project reopened", () =>
              apiRequest(`/projects/${project.id}/reopen`, {
                method: "POST",
                body: { creator: HUMAN_WORKER, description },
              }),
            );
            setModal(null);
            await load();
          }}
        />
      )}
      {modal === "title" && (
        <TextActionModal
          title="Rename project"
          label="Project name"
          multiline={false}
          defaultValue={project.title}
          submitLabel="Save name"
          onClose={() => setModal(null)}
          onSubmit={submitTitle}
        />
      )}
    </>
  );
}

export function GraphCanvas({ detail, selected, onSelect, layout }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  const elements = useMemo(() => buildFactGraph(detail), [detail]);

  // Full re-layout, used when the user switches layout engine and when
  // updateGraph finds structural changes. Ported from Cairn core layoutOpts().
  const runLayout = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const direction = layout.endsWith("_lr") ? "LR" : "TB";
    const engine = layout.startsWith("elk") ? "elk" : layout.startsWith("klay") ? "klay" : "dagre";
    let options;

    if (engine === "elk") {
      options = {
        name: "elk",
        fit: false,
        padding: 50,
        animate: true,
        animationDuration: 350,
        animationEasing: "ease-in-out-cubic",
        elk: {
          algorithm: "layered",
          "elk.direction": direction === "TB" ? "DOWN" : "RIGHT",
          "elk.aspectRatio": "1.5",
          "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
          "elk.spacing.nodeNode": "50",
          "elk.layered.spacing.nodeNodeBetweenLayers": "80",
          "elk.spacing.edgeNode": "25",
          "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
          "elk.layered.nodePlacement.bk.fixedAlignment": "BALANCED",
        },
      };
    } else if (engine === "klay") {
      options = {
        name: "klay",
        fit: false,
        padding: 50,
        animate: true,
        animationDuration: 400,
        animationEasing: "ease-in-out-cubic",
        klay: {
          direction: direction === "TB" ? "DOWN" : "RIGHT",
          edgeRouting: "POLYLINE",
          crossingMinimization: "LAYER_SWEEP",
          nodeLayering: "NETWORK_SIMPLEX",
          nodePlacement: "BRANDES_KOEPF",
          separateConnectedComponents: true,
          spacing: direction === "LR" ? 52 : 40,
          inLayerSpacingFactor: direction === "LR" ? 1.15 : 1.0,
          thoroughness: 8,
        },
      };
    } else {
      options = {
        name: "dagre",
        rankDir: direction,
        nodeSep: 60,
        rankSep: 80,
        padding: 50,
        fit: false,
        animate: true,
        animationDuration: 400,
        animationEasing: "ease-in-out-cubic",
      };
    }
    cy.layout(options).run();
  }, [layout]);

  // Incremental graph update — ported from Cairn core (index.html updateGraph).
  // Diffs the desired elements against the live cy instance instead of destroying
  // and recreating it, so a 5s poll no longer visually flashes the whole graph.
  const snapshotNodePositions = useCallback(() => {
    const positions = new Map();
    const cy = cyRef.current;
    if (!cy) return positions;
    cy.nodes().forEach((node) => {
      positions.set(node.id(), { x: node.position("x"), y: node.position("y") });
    });
    return positions;
  }, []);

  const anchorPositionFromIds = useCallback(
    (nodeIds, previousPositions, offset = 36) => {
      const cy = cyRef.current;
      const anchors = [];
      for (const nodeId of nodeIds) {
        const existing = cy?.getElementById(nodeId);
        if (existing?.length) {
          anchors.push({ x: existing.position("x"), y: existing.position("y") });
          continue;
        }
        const previous = previousPositions.get(nodeId);
        if (previous) anchors.push(previous);
      }
      if (anchors.length === 0) return null;
      const center = anchors.reduce((acc, pos) => ({ x: acc.x + pos.x, y: acc.y + pos.y }), { x: 0, y: 0 });
      const avg = { x: center.x / anchors.length, y: center.y / anchors.length };
      return layout.endsWith("_lr") ? { x: avg.x + offset, y: avg.y } : { x: avg.x, y: avg.y + offset };
    },
    [layout],
  );

  const initialPositionForNode = useCallback(
    (nodeData, previousPositions) => {
      if (nodeData.sourceIds?.length) {
        return anchorPositionFromIds(nodeData.sourceIds, previousPositions, 40);
      }
      const producer = detail.steps.find((item) => item.to === nodeData.id);
      return producer ? anchorPositionFromIds(producer.from || [], previousPositions, 44) : null;
    },
    [anchorPositionFromIds, detail.steps],
  );

  const fadeInFreshElement = useCallback((element) => {
    if (!element || element.length === 0) return;
    element.style("opacity", 0);
    setTimeout(() => {
      if (!element.inside()) return;
      element.animate(
        { style: { opacity: 1 } },
        {
          duration: 500,
          complete: () => {
            if (!element.inside()) return;
            element.removeStyle("opacity");
          },
        },
      );
    }, 30);
  }, []);

  const updateGraph = useCallback(
    (nextElements) => {
      const cy = cyRef.current;
      if (!cy) return;
      const nodes = nextElements.filter((el) => el && el.data && (!el.data.source || !el.data.target));
      const edges = nextElements.filter((el) => el && el.data && el.data.source && el.data.target);
      const wantNodes = new Set(nodes.map((n) => n.data.id));
      const wantEdges = new Set(edges.map((e) => e.data.id));
      const previousPositions = snapshotNodePositions();
      let changed = false;

      cy.nodes().forEach((n) => {
        if (!wantNodes.has(n.id())) {
          n.remove();
          changed = true;
        }
      });
      cy.edges().forEach((e) => {
        if (!wantEdges.has(e.id())) {
          e.remove();
          changed = true;
        }
      });

      for (const n of nodes) {
        const ex = cy.getElementById(n.data.id);
        if (ex.length === 0) {
          const initialPosition = initialPositionForNode(n.data, previousPositions);
          const added = cy.add(initialPosition ? { ...n, position: initialPosition } : n);
          fadeInFreshElement(added);
          changed = true;
        } else if (
          ex.data("nodeType") !== n.data.nodeType ||
          ex.data("label") !== n.data.label ||
          ex.data("description") !== n.data.description ||
          ex.data("status") !== n.data.status ||
          ex.data("width") !== n.data.width ||
          ex.data("height") !== n.data.height
        ) {
          ex.data(n.data);
          changed = true;
        }
      }
      for (const e of edges) {
        const ex = cy.getElementById(e.data.id);
        if (ex.length === 0) {
          const added = cy.add(e);
          fadeInFreshElement(added);
          changed = true;
        } else {
          if (ex.source().id() !== e.data.source || ex.target().id() !== e.data.target) {
            ex.move({ source: e.data.source, target: e.data.target });
            changed = true;
          }
          ex.data(e.data);
        }
      }
      if (changed) {
        runLayout();
      }
    },
    [snapshotNodePositions, initialPositionForNode, fadeInFreshElement, runLayout],
  );

  useEffect(() => {
    if (!containerRef.current) return undefined;
    const cy = cytoscape({
      container: containerRef.current,
      elements,
      wheelSensitivity: 0.16,
      minZoom: 0.05,
      maxZoom: 3.5,
      boxSelectionEnabled: false,
      style: [
        {
          selector: 'node[nodeType="origin"]',
          style: {
            label: "data(label)",
            shape: "round-rectangle",
            "background-color": "#14b8a6",
            color: "#fff",
            "font-family": "sans-serif",
            "font-size": 11,
            "font-weight": "bold",
            "text-wrap": "wrap",
            "text-max-width": 116,
            "text-overflow-wrap": "anywhere",
            "text-valign": "center",
            "text-halign": "center",
            width: "data(width)",
            height: "data(height)",
            "border-width": 0,
          },
        },
        {
          selector: 'node[nodeType="goal"]',
          style: {
            label: "data(label)",
            shape: "round-rectangle",
            "background-color": "#f43f5e",
            color: "#fff",
            "font-family": "sans-serif",
            "font-size": 11,
            "font-weight": "bold",
            "text-wrap": "wrap",
            "text-max-width": 116,
            "text-overflow-wrap": "anywhere",
            "text-valign": "center",
            "text-halign": "center",
            width: "data(width)",
            height: "data(height)",
            "border-width": 0,
          },
        },
        {
          selector: 'node[nodeType="goal"][status="completed"]',
          style: { "background-color": "#10b981", "border-color": "#047857", "border-width": 2 },
        },
        {
          selector: 'node[nodeType="fact"]',
          style: {
            label: "data(label)",
            shape: "round-rectangle",
            "background-color": "#6366f1",
            color: "#fff",
            "font-family": "sans-serif",
            "font-size": 10,
            "font-weight": "bold",
            "text-wrap": "wrap",
            "text-max-width": 116,
            "text-overflow-wrap": "anywhere",
            "text-valign": "center",
            "text-halign": "center",
            width: "data(width)",
            height: "data(height)",
            "border-width": 0,
          },
        },
        {
          selector: 'node[nodeType="in_progress"]',
          style: {
            label: "?",
            shape: "ellipse",
            "background-color": "#f59e0b",
            "background-opacity": 0.8,
            color: "#fff",
            "font-family": "sans-serif",
            "font-size": 11,
            "font-weight": "bold",
            width: 22,
            height: 22,
            "border-width": 2,
            "border-color": "#d97706",
          },
        },
        {
          selector: 'node[nodeType="unclaimed"]',
          style: {
            label: "?",
            shape: "ellipse",
            "background-color": "#cbd5e1",
            "background-opacity": 0.5,
            color: "#94a3b8",
            "font-family": "sans-serif",
            "font-size": 11,
            "font-weight": "bold",
            width: 20,
            height: 20,
            "border-width": 1.5,
            "border-color": "#94a3b8",
            "border-style": "dashed",
          },
        },
        {
          selector: 'node[nodeType="step_pending"]',
          style: {
            "background-color": "#1c212b",
            "background-opacity": 0.96,
            label: "data(label)",
            "border-color": "#f59e0b",
            color: "#fdba74",
            shape: "round-rectangle",
            "font-family": "sans-serif",
            "font-size": 10,
            "font-weight": "bold",
            width: "data(width)",
            height: "data(height)",
            "border-width": 1.5,
            "border-style": "dashed",
            "text-wrap": "wrap",
            "text-max-width": 70,
            "text-valign": "center",
            "text-halign": "center",
          },
        },
        {
          selector: 'node[nodeType="step_running"]',
          style: {
            "background-color": "#fb923c",
            "background-opacity": 0.96,
            label: "data(label)",
            "border-color": "#ea580c",
            color: "#fff7ed",
            shape: "round-rectangle",
            "font-family": "sans-serif",
            "font-size": 10,
            "font-weight": "bold",
            width: "data(width)",
            height: "data(height)",
            "border-width": 2,
            "text-wrap": "wrap",
            "text-max-width": 70,
            "text-valign": "center",
            "text-halign": "center",
          },
        },
        {
          selector: 'node[nodeType="step_done"]',
          style: {
            label: "data(label)", shape: "round-rectangle",
            "background-color": "#059669", color: "#ecfdf5",
            "font-family": "sans-serif", "font-size": 10, "font-weight": "bold",
            width: "data(width)", height: "data(height)", "border-width": 0,
            "text-wrap": "wrap", "text-max-width": 104,
            "text-valign": "center", "text-halign": "center",
          },
        },
        {
          selector: 'node[nodeType="step_abandoned"]',
          style: {
            label: "data(label)", shape: "ellipse",
            "background-color": "#64748b", color: "#e2e8f0",
            "font-family": "sans-serif", "font-size": 10,
            width: 24, height: 24,
            "border-width": 1.5, "border-style": "dashed", "border-color": "#94a3b8",
            "text-wrap": "wrap", "text-max-width": 104,
            "text-valign": "center", "text-halign": "center",
          },
        },
        {
          selector: 'node[nodeType="finding"]',
          style: {
            label: "data(label)", shape: "diamond",
            "background-color": "#8b5cf6", color: "#ffffff",
            "font-family": "sans-serif", "font-size": 10, "font-weight": "bold",
            width: "data(width)", height: "data(height)", "border-width": 0,
            "text-wrap": "wrap", "text-max-width": 104,
            "text-valign": "center", "text-halign": "center",
          },
        },
        {
          selector: 'edge[status="step_source"], edge[status="step_result"], edge[status="step_scope"], edge[status="goal_child"], edge[status="goal_evidence"], edge[status="finding"]',
          style: {
            width: 1.8, "line-color": "#94a3b8", "target-arrow-color": "#94a3b8",
            "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.8,
          },
        },
        {
          selector: 'edge[status="step_scope"], edge[status="goal_evidence"]',
          style: { "line-style": "dashed", "line-color": "#94a3b8", "target-arrow-color": "#94a3b8", label: "data(label)", "font-size": 7, color: "#94a3b8", "text-rotation": "autorotate", "text-wrap": "ellipsis", "text-max-width": 80, "text-margin-y": -8 },
        },
        {
          selector: 'edge[status="finding"]',
          style: { "line-color": "#a78bfa", "target-arrow-color": "#a78bfa" },
        },
        {
          selector: 'edge[status="concluded"]',
          style: {
            width: 2,
            "line-color": "#6ee7b7",
            "target-arrow-color": "#6ee7b7",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 7,
            color: "#94a3b8",
            "text-rotation": "autorotate",
            "text-margin-y": -9,
            "text-max-width": 80,
            "text-wrap": "ellipsis",
            "text-background-color": "#f8fafc",
            "text-background-opacity": 0.85,
            "text-background-padding": 2,
            "text-events": "yes",
            "arrow-scale": 0.9,
          },
        },
        {
          selector: 'edge[status="in_progress"]',
          style: {
            width: 2,
            "line-color": "#fbbf24",
            "line-style": "dashed",
            "line-dash-pattern": [8, 4],
            "line-dash-offset": 0,
            "target-arrow-color": "#fbbf24",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            "arrow-scale": 0.9,
            label: "data(label)",
            "font-size": 7,
            color: "#b45309",
            "text-rotation": "autorotate",
            "text-margin-y": -9,
            "text-max-width": 80,
            "text-wrap": "ellipsis",
            "text-background-color": "#fffbeb",
            "text-background-opacity": 0.85,
            "text-background-padding": 2,
            "text-events": "yes",
          },
        },
        {
          selector: 'edge[status="unclaimed"]',
          style: {
            width: 1.5,
            "line-color": "#cbd5e1",
            "line-style": "dashed",
            "line-dash-pattern": [5, 5],
            "target-arrow-color": "#cbd5e1",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 7,
            color: "#94a3b8",
            "text-rotation": "autorotate",
            "text-margin-y": -9,
            "text-max-width": 80,
            "text-wrap": "ellipsis",
            "text-background-color": "#f8fafc",
            "text-background-opacity": 0.85,
            "text-background-padding": 2,
            "text-events": "yes",
            "arrow-scale": 0.7,
          },
        },
        {
          selector: 'edge[status="step_pending"]',
          style: {
            width: 2,
            "line-color": "#fdba74",
            "line-style": "dashed",
            "line-dash-pattern": [8, 4],
            "line-dash-offset": 0,
            "target-arrow-color": "#fdba74",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 7,
            color: "#c2410c",
            "text-rotation": "autorotate",
            "text-margin-y": -9,
            "text-max-width": 88,
            "text-wrap": "ellipsis",
            "text-background-color": "#fff7ed",
            "text-background-opacity": 0.92,
            "text-background-padding": 2,
            "text-events": "yes",
            "arrow-scale": 0.85,
          },
        },
        {
          selector: 'edge[status="step_running"]',
          style: {
            width: 2.5,
            "line-color": "#fb923c",
            "line-style": "dashed",
            "line-dash-pattern": [10, 4],
            "line-dash-offset": 0,
            "target-arrow-color": "#fb923c",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 7,
            color: "#c2410c",
            "text-rotation": "autorotate",
            "text-margin-y": -9,
            "text-max-width": 88,
            "text-wrap": "ellipsis",
            "text-background-color": "#fff7ed",
            "text-background-opacity": 0.92,
            "text-background-padding": 2,
            "text-events": "yes",
            "arrow-scale": 0.95,
          },
        },
        {
          selector: 'edge[edgeType="step_scope"]',
          style: {
            label: "",
            width: 1.8,
            "curve-style": "bezier",
            "line-style": "dotted",
            "line-dash-pattern": [2, 5],
            "target-arrow-shape": "triangle-backcurve",
            "arrow-scale": 0.75,
            "target-distance-from-node": 2,
          },
        },
        { selector: ".highlight", style: { "z-index": 999 } },
        { selector: "edge.highlight", style: { "z-index": 999 } },
        {
          selector: "node.focus",
          style: {
            "border-width": 3,
            "border-color": "#312e81",
            "border-opacity": 0.95,
            "z-index": 1000,
          },
        },
        {
          selector: "edge.focus",
          style: {
            "z-index": 1000,
            "overlay-color": "#93c5fd",
            "overlay-opacity": 0.22,
            "overlay-padding": 5,
          },
        },
        {
          selector: "node.selected-fact",
          style: {
            "border-width": 0,
            "underlay-color": "#93c5fd",
            "underlay-padding": 8,
            "underlay-opacity": 0.28,
            "z-index": 1001,
          },
        },
        { selector: ".faded", style: { opacity: 0.5 } },
        { selector: "node, edge", style: { "font-family": "sans-serif", "text-overflow-wrap": "anywhere" } },
      ],
    });
    cyRef.current = cy;
    const fitGraph = () => fitFactGraph(cy);
    cy.on("layoutstop", fitGraph);
    window.addEventListener("rabbit:fit-graph", fitGraph);
    cy.on("tap", "node", (event) => {
      const node = event.target;
      const nodeType = String(node.data("nodeType") || "fact");
      const type = node.data("stepId") ? "step" : nodeType === "origin" ? "fact" : nodeType;
      onSelect({ type, id: node.id() });
    });
    cy.on("tap", "edge", (event) => {
      const edge = event.target;
      const status = edge.data("status");
      if (edge.data("stepId")) onSelect({ type: "step", id: edge.data("stepId") });
      else if (status === "step_source") onSelect({ type: "step", id: edge.target().id() });
      else if (status === "step_result" || status === "step_scope") onSelect({ type: "step", id: edge.source().id() });
      else if (status === "finding") onSelect({ type: "finding", id: edge.target().id() });
      else if (status === "goal_child" || status === "goal_evidence") onSelect({ type: "goal", id: edge.target().id() });
    });
    cy.on("tap", (event) => {
      if (event.target === cy) onSelect(null);
    });
    const resizeObserver =
      typeof ResizeObserver === "undefined"
        ? null
        : new ResizeObserver(() => {
            cy.resize();
            if (cy.elements().length > 0) {
              fitGraph();
            }
          });
    resizeObserver?.observe(containerRef.current);
    return () => {
      resizeObserver?.disconnect();
      window.removeEventListener("rabbit:fit-graph", fitGraph);
      cy.destroy();
      cyRef.current = null;
    };
  }, [onSelect]);

  // Data update: diff the desired elements into the live cy instance.
  // Replaces the previous "destroy + recreate on every poll" behavior so the
  // graph no longer visually flashes every 5s.
  useEffect(() => {
    if (!cyRef.current) return;
    updateGraph(elements);
  }, [elements, updateGraph]);

  // Full re-layout only when the user switches layout engine.
  useEffect(() => {
    if (!cyRef.current) return;
    runLayout();
  }, [runLayout]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass("highlight focus faded selected-fact");
    if (!selected?.id) return;
    if (selected.type === "step") {
      const stepEdges = cy.edges().filter(edge => edge.data("stepId") === selected.id);
      const visible = stepEdges.add(stepEdges.connectedNodes());
      visible.addClass("highlight");
      cy.elements().not(visible).addClass("faded");
      return;
    }
    const focusNode = cy.getElementById(selected.id);
    if (!focusNode.length) return;
    const connectedEdges = focusNode.connectedEdges();
    const connectedNodes = connectedEdges.connectedNodes();
    const visible = focusNode.add(connectedEdges).add(connectedNodes);
    focusNode.addClass("focus selected-fact");
    connectedEdges.addClass("highlight");
    connectedNodes.addClass("highlight");
    cy.elements().not(visible).addClass("faded");
  }, [detail, selected]);

  return <div className="graph-canvas" ref={containerRef} />;
}

function InspectorListItem({ title, description, meta, onClick }) {
  const Comp = onClick ? "button" : "article";
  const props = onClick
    ? {
        type: "button",
        onClick,
      }
    : {};
  return (
    <Comp className={cn("timeline-item", onClick && "clickable")} {...props}>
      <div className="timeline-item-head">
        <strong className="timeline-item-title" title={title}>
          {title}
        </strong>
      </div>
      <p title={description}>{description}</p>
      <small title={meta}>{meta}</small>
    </Comp>
  );
}

function Inspector({ detail, campaign, selected, setSelected, tab, setTab, timeline, onRefresh, runAction }) {
  const facts = detail.facts;
  const steps = detail.steps;
  const fact = selected?.type === "fact" ? facts.find((item) => item.id === selected.id) : null;
  const step = selected?.type === "step" ? steps.find((item) => item.id === selected.id) : null;
  const goal = selected?.type === "goal" ? (detail.goals || []).find((item) => item.id === selected.id) : null;
  const finding = selected?.type === "finding" ? (detail.findings || []).find((item) => item.id === selected.id) : null;
  const tabs = [
    ["details", "Details", null],
    ["hints", "Hint", detail.hints.length],
    ["logs", "Logs", steps.length],
    ["timeline", "Timeline", timeline.length],
  ];

  const claimStep = async () => {
    if (!step) return;
    await runAction("Step claimed", () =>
      apiRequest(`/projects/${detail.project.id}/steps/${step.id}/heartbeat`, {
        method: "POST",
        body: { worker: HUMAN_WORKER },
      }),
    );
    onRefresh();
  };

  const releaseStep = async () => {
    if (!step) return;
    await runAction("Step released", () =>
      apiRequest(`/projects/${detail.project.id}/steps/${step.id}/release`, {
        method: "POST",
        body: { worker: step.worker || HUMAN_WORKER },
      }),
    );
    onRefresh();
  };

  return (
    <aside className="inspector">
      <div className="inspector-tabs">
        {tabs.map(([key, label, count]) => (
          <button key={key} className={cn(tab === key && "active")} type="button" onClick={() => setTab(key)}>
            <span className="inspector-tab-label">{label}</span>
            {count !== null && <span className="inspector-tab-badge">{count}</span>}
          </button>
        ))}
      </div>
      <div className="inspector-body">
        {tab === "details" && (
          <>
            {!selected && (
              <>
                <div className="detail-card">
                  <span>Projects</span>
                  <h3>{detail.project.title}</h3>
                  <p>{detail.project.id}</p>
                  <div className="detail-grid">
                    <MiniStat label="Fact" value={facts.length} />
                    <MiniStat label="Goal" value={(detail.goals || []).length} />
                    <MiniStat label="Step" value={steps.length} />
                    <MiniStat label="Finding" value={(detail.findings || []).length} />
                  </div>
                </div>
                <ProjectCampaignPanel campaign={campaign} />
              </>
            )}
            {fact && (
              <div className="detail-card">
                <span>Fact</span>
                <h3>{fact.id}</h3>
                <p>{fact.description}</p>
              </div>
            )}
            {step && (
              <div className="detail-card">
                <span>Step</span>
                <h3>{step.id}</h3>
                <p>{step.description}</p>
                <div className="detail-meta">
                  <span>From: {(step.from || []).join(", ")}</span>
                  <span>Result: {step.to || "Open"}</span>
                  <span>Creator: {step.creator}</span>
                  <span>Worker：{step.worker || "Unclaimed"}</span>
                </div>
                {!step.to && (
                  <div className="button-row">
                    {!step.worker ? (
                      <button className="primary-outline compact" type="button" onClick={claimStep}>
                        <Activity size={16} />
                        Claim
                      </button>
                    ) : (
                      <button className="ghost-button compact" type="button" onClick={releaseStep}>
                        <Pause size={16} />
                        Release
                      </button>
                    )}
                  </div>
                )}
              </div>
            )}
            {goal && (
              <div className="detail-card">
                <span>Goal</span>
                <h3>{goal.id}</h3>
                <p>{goal.description}</p>
                <div className="detail-meta">
                  <span>Status: {goal.status}</span>
                  <span>Parent goal: {goal.parent_goal_id || "Top-level goal"}</span>
                  <span>Evidence: {(goal.from || []).join(", ") || "None"}</span>
                </div>
              </div>
            )}
            {finding && (
              <div className="detail-card">
                <span>Finding</span>
                <h3>{finding.title || finding.id}</h3>
                <p>{finding.description}</p>
                <div className="detail-meta">
                  <span>ID：{finding.id}</span>
                  <span>Type: {finding.kind}</span>
                  <span>Severity: {finding.severity}</span>
                  <span>Linked fact: {finding.fact_id || "None"}</span>
                </div>
              </div>
            )}
          </>
        )}
        {tab === "hints" && (
          <div className="timeline-list">
            {detail.hints.length === 0 ? (
              <EmptyState title="No hints" />
            ) : (
              detail.hints.map((hint) => (
                <InspectorListItem
                  key={hint.id}
                  title={hint.id}
                  description={hint.content}
                  meta={`${hint.creator} · ${formatTime(hint.created_at)}`}
                />
              ))
            )}
          </div>
        )}
        {tab === "logs" && (
          <div className="timeline-list">
            {steps.map((item) => (
              <InspectorListItem
                key={item.id}
                title={item.id}
                description={item.description}
                meta={item.worker || item.creator}
                onClick={() => {
                  setSelected({ type: "step", id: item.id });
                  setTab("details");
                }}
              />
            ))}
          </div>
        )}
        {tab === "timeline" && (
          <div className="timeline-list">
            {timeline.length === 0 ? (
              <EmptyState title="No timeline" />
            ) : (
              timeline.map((event) => (
                <InspectorListItem
                  key={event.id}
                  title={event.event_type}
                  description={event.description}
                  meta={`${formatTime(event.timestamp)}${event.actor ? ` · ${event.actor}` : ""}`}
                  onClick={() => {
                    if (!event.node_id) return;
                    const prefix = event.node_id[0];
                    setSelected({ type: prefix === "s" ? "step" : prefix === "g" ? "goal" : prefix === "v" ? "finding" : "fact", id: event.node_id });
                  }}
                />
              ))
            )}
          </div>
        )}
      </div>
    </aside>
  );
}

function ProjectCampaignPanel({ campaign }) {
  if (!campaign) {
    return (
      <div className="detail-card project-campaign-card project-campaign-empty">
        <div className="project-campaign-head">
          <div>
            <span>Campaign judgment</span>
            <h3>Summary unavailable</h3>
          </div>
        </div>
        <p>This project has no stable campaign summary, or the summary service is unavailable.</p>
      </div>
    );
  }

  const goalMeta = campaignGoalMeta(campaign.goal_status);
  const projectMeta = projectStatusBadgeMeta(campaign.project_status);

  return (
    <div className="detail-card project-campaign-card">
      <div className="project-campaign-head">
        <div>
          <span>Campaign judgment</span>
          <h3>Current line</h3>
        </div>
        <div className="project-campaign-badges">
          <Badge tone={goalMeta.tone}>{goalMeta.label}</Badge>
          <Badge tone={projectMeta.tone}>{projectMeta.label}</Badge>
        </div>
      </div>
      <p className="project-campaign-lead">{campaign.lead}</p>
      <p className="project-campaign-summary">{campaign.summary}</p>
      <div className="detail-grid project-campaign-stats">
        <MiniStat label="High-value findings" value={campaign.counts.high_value_vulnerabilities} />
        <MiniStat label="Open steps" value={campaign.counts.open_steps} />
        <MiniStat label="Blockers" value={campaign.blockers.length} />
        <MiniStat label="Next steps" value={campaign.next_steps.length} />
      </div>
      {!!campaign.top_findings?.length && (
        <CampaignListBlock title="Strong signals">
          {campaign.top_findings.map((finding) => (
            <article key={`${finding.source_type}-${finding.source_id}`} className="project-campaign-item">
              <div className="project-campaign-item-head">
                <strong title={finding.title}>{finding.title}</strong>
                <div className="project-campaign-inline">
                  {finding.severity && <Badge tone={findingBadgeTone(finding.severity)}>{severityLabel(finding.severity)}</Badge>}
                  <Badge tone={findingConfidenceTone(finding.confidence)}>{findingConfidenceLabel(finding.confidence)}</Badge>
                </div>
              </div>
              <p title={finding.summary}>{finding.summary}</p>
              <small>
                {finding.source_id} · {findingSourceLabel(finding.source_type)}
              </small>
            </article>
          ))}
        </CampaignListBlock>
      )}
      {!!campaign.open_steps?.length && (
        <CampaignListBlock title="Steps to advance">
          {campaign.open_steps.map((item, index) => (
            <article key={`open-intent-${index}`} className="project-campaign-item">
              <strong>{item}</strong>
            </article>
          ))}
        </CampaignListBlock>
      )}
      {!!campaign.blockers?.length && (
        <CampaignListBlock title="Current blockers">
          {campaign.blockers.map((item, index) => (
            <article key={`blocker-${index}`} className="project-campaign-item blocker">
              <strong>{item}</strong>
            </article>
          ))}
        </CampaignListBlock>
      )}
      {!!campaign.next_steps?.length && (
        <CampaignListBlock title="Suggested next steps">
          {campaign.next_steps.map((item, index) => (
            <article key={`next-step-${index}`} className="project-campaign-item next-step">
              <strong>{item}</strong>
            </article>
          ))}
        </CampaignListBlock>
      )}
    </div>
  );
}

function CampaignListBlock({ title, children }) {
  return (
    <section className="project-campaign-block">
      <header>
        <h4>{title}</h4>
      </header>
      <div className="project-campaign-list">{children}</div>
    </section>
  );
}

function campaignGoalMeta(status) {
  if (status === "achieved") return { label: "Goal achieved", tone: "success" };
  if (status === "in_progress") return { label: "Campaign in progress", tone: "warning" };
  return { label: "Currently blocked", tone: "danger" };
}

function projectStatusBadgeMeta(status) {
  if (status === "completed") return { label: "Project completed", tone: "info" };
  if (status === "stopped") return { label: "Project stopped", tone: "warning" };
  return { label: "Project running", tone: "success" };
}

function findingBadgeTone(severity) {
  return SEVERITY_META[severity]?.tone || "muted";
}

function severityLabel(severity) {
  return SEVERITY_META[severity]?.label || severity || "-";
}

function findingConfidenceTone(confidence) {
  if (confidence === "confirmed") return "success";
  if (confidence === "supported") return "info";
  return "warning";
}

function findingConfidenceLabel(confidence) {
  if (confidence === "confirmed") return "Confirmed";
  if (confidence === "supported") return "Supported";
  return "Unverified";
}

function findingSourceLabel(sourceType) {
  if (sourceType === "vulnerability") return "Vulnerabilities";
  if (sourceType === "fact") return "Fact";
  return "Hint";
}

function IntentModal({ fromIds, facts, onClose, onSubmit }) {
  const [form, setForm] = useState({
    from: fromIds,
    description: "",
    worker: "",
  });
  const [saving, setSaving] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSubmit({
        from: form.from,
        description: form.description,
        creator: HUMAN_WORKER,
        worker: form.worker || null,
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="New step" onClose={onClose}>
      <form className="stack-form modal-body" onSubmit={submit}>
        <label>
          <span>Source facts</span>
          <select
            multiple
            value={form.from}
            onChange={(event) =>
              setForm({ ...form, from: Array.from(event.target.selectedOptions).map((option) => option.value) })
            }
          >
            {facts.map((fact) => (
              <option key={fact.id} value={fact.id}>
                {fact.id} · {clampText(fact.description, 60)}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Step description</span>
          <textarea
            rows={5}
            value={form.description}
            onChange={(event) => setForm({ ...form, description: event.target.value })}
            required
          />
        </label>
        <label>
          <span>Claim for a worker (optional)</span>
          <input value={form.worker} onChange={(event) => setForm({ ...form, worker: event.target.value })} />
        </label>
        <div className="modal-footer">
          <button className="ghost-button" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary-button compact" type="submit" disabled={saving || !form.from.length}>
            {saving ? <Loader2 className="spin" size={18} /> : <Plus size={18} />}
            Save
          </button>
        </div>
      </form>
    </Modal>
  );
}

function TextActionModal({
  title,
  label,
  onClose,
  onSubmit,
  defaultValue = "",
  multiline = true,
  placeholder,
  submitLabel = "Save",
}) {
  const [text, setText] = useState(defaultValue);
  const [saving, setSaving] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSubmit(text);
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal title={title} onClose={onClose}>
      <form className="stack-form modal-body" onSubmit={submit}>
        <label>
          <span>{label}</span>
          {multiline ? (
            <textarea
              rows={6}
              value={text}
              placeholder={placeholder}
              onChange={(event) => setText(event.target.value)}
              autoFocus
              required
            />
          ) : (
            <input
              value={text}
              placeholder={placeholder}
              onChange={(event) => setText(event.target.value)}
              autoFocus
              required
            />
          )}
        </label>
        <div className="modal-footer">
          <button className="ghost-button" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary-button compact" type="submit" disabled={saving}>
            {saving ? <Loader2 className="spin" size={18} /> : <Save size={18} />}
            {submitLabel}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function VulnerabilitiesPage({ route, runAction, setToast, confirmAction }) {
  const view = route?.view || "overview";
  const severityViews = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  const statusViews = { confirmed: "Confirmed", ignored: "Ignored" };
  const viewTitle =
    view === "export-records"
      ? "Export history"
      : severityViews[view] || statusViews[view] || "Report overview";

  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [projects, setProjects] = useState([]);
  const [reportTemplates, setReportTemplates] = useState([]);
  const [templateUploading, setTemplateUploading] = useState(false);
  const reportTemplateInputRef = useRef(null);
  const [filters, setFilters] = useState(() => {
    const fallback = { severity: "", project_id: "", status: "", search: route?.search || "", date_from: "", date_to: "" };
    if (typeof window === "undefined") return fallback;
    try {
      const raw = window.localStorage.getItem(VULN_FILTERS_STORAGE_KEY);
      const saved = raw ? JSON.parse(raw) : {};
      return { ...fallback, ...saved, search: route?.search || saved?.search || "" };
    } catch {
      return fallback;
    }
  });
  const [detailVulnId, setDetailVulnId] = useState(null);
  const [selectedIds, setSelectedIds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // The left sub-nav drives a severity or status filter via the URL view. The
  // in-page filter selects (project/search) still compose on top of it.
  const viewSeverity = severityViews[view] ? view : "";
  const viewStatus = statusViews[view] ? view : "";

  const query = useMemo(() => {
    const params = new URLSearchParams();
    const severity = viewSeverity || filters.severity;
    const status = viewStatus || filters.status;
    if (severity) params.set("severity", severity);
    if (filters.project_id) params.set("project_id", filters.project_id);
    if (status) params.set("status", status);
    const suffix = params.toString();
    return suffix ? `?${suffix}` : "";
  }, [filters.project_id, filters.severity, filters.status, viewSeverity, viewStatus]);

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true);
    try {
      const [list, projectList, templateList] = await Promise.all([
        apiRequest(`/api/vulnerabilities${query}`),
        apiRequest("/projects"),
        apiRequest("/api/report-templates").catch(() => []),
      ]);
      setVulnerabilities(list);
      setProjects(projectList);
      setReportTemplates(templateList);
    } catch (error) {
      if (!silent) setToast({ type: "danger", message: error.message || "Could not load vulnerability reports" });
    } finally {
      if (!silent) setLoading(false);
    }
  }, [query, setToast]);

  useEffect(() => {
    load();
  }, [load]);

  // When the global search navigates here with a ?q= term, reflect it in the
  // in-page search filter even if this page is already mounted.
  useEffect(() => {
    if (route?.search !== undefined) {
      setFilters((prev) => (prev.search === route.search ? prev : { ...prev, search: route.search || "" }));
    }
  }, [route?.search]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      load({ silent: true });
    }, 8000);
    return () => window.clearInterval(timer);
  }, [load]);

  const refresh = async () => {
    await runAction("Vulnerability reports refreshed", () => apiRequest("/api/vulnerabilities/refresh", { method: "POST" }));
    await load();
  };

  const exportMd = async ({ selected = [], title = "vulnerabilities" }) => {
    if (!selected.length) {
      setToast({ type: "warning", message: "Select vulnerabilities to export" });
      return;
    }
    const params = new URLSearchParams({ format: "md" });
    params.set("vulnerability_ids", selected.join(","));
    await runAction("Markdown report generated", () => downloadFromApi(`/api/vulnerabilities/export?${params}`, `${title}.md`));
  };

  const uploadReportTemplate = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".docx")) {
      setToast({ type: "warning", message: "Choose a DOCX report template" });
      return;
    }
    setTemplateUploading(true);
    try {
      const content = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result).split(",", 2)[1] || "");
        reader.onerror = () => reject(new Error("Could not read the template"));
        reader.readAsDataURL(file);
      });
      await apiRequest("/api/report-templates", {
        method: "POST",
        body: { name: file.name.replace(/\.docx$/i, ""), filename: file.name, content_base64: content },
      });
      setToast({ type: "success", message: "The report agent recognized and enabled this template" });
      await load({ silent: true });
    } catch (error) {
      setToast({ type: "danger", message: error.message || "Could not import the report template" });
    } finally {
      setTemplateUploading(false);
    }
  };

  const exportTemplateReport = async () => {
    const active = reportTemplates.find((item) => item.is_active);
    if (!active) {
      setToast({ type: "warning", message: "Import and enable a DOCX report template first" });
      return;
    }
    if (!filters.project_id) {
      setToast({ type: "warning", message: "Select a project before generating a client report" });
      return;
    }
    const project = projects.find((item) => item.id === filters.project_id);
    await runAction("Client report generated", () =>
      downloadFromApi(
        `/api/report-templates/${encodeURIComponent(active.id)}/export?project_id=${encodeURIComponent(filters.project_id)}`,
        `${project?.title || "assessment"}-penetration-test-report.docx`,
      ),
    );
  };

  const updateVulnerabilityStatus = async (vuln, status) => {
    const label = status === "ignored" ? "Vulnerability marked ignored" : "Vulnerability restored to confirmed";
    await runAction(label, () =>
      apiRequest(`/api/vulnerabilities/${encodeURIComponent(vuln.id)}/status`, {
        method: "PATCH",
        body: { status },
      }),
    );
    await load();
  };

  const updateSelectedStatus = async (status) => {
    if (!selectedIds.length) {
      setToast({ type: "warning", message: "Select vulnerabilities to update" });
      return;
    }
    const label = status === "ignored" ? "Marked ignored" : "Restored to confirmed";
    await runAction(label, () =>
      apiRequest("/api/vulnerabilities/batch/status", {
        method: "POST",
        body: { ids: selectedIds, status },
      }),
    );
    setSelectedIds([]);
    await load();
  };

  const visibleVulnerabilities = useMemo(() => {
    const term = filters.search.trim().toLowerCase();
    const from = filters.date_from;
    const to = filters.date_to;
    return vulnerabilities.filter((item) => {
      if (term) {
        const matched = [item.title, item.description, item.project_name, item.project_id, item.fact_id, item.source_worker]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(term));
        if (!matched) return false;
      }
      const day = String(item.discovered_at || "").slice(0, 10);
      if (from && day && day < from) return false;
      if (to && day && day > to) return false;
      return true;
    });
  }, [filters.search, filters.date_from, filters.date_to, vulnerabilities]);

  const filteredVulnCount = visibleVulnerabilities.length;
  const totalPages = Math.max(1, Math.ceil(filteredVulnCount / pageSize));
  const currentPage = Math.min(page, totalPages);
  const pagedVulnerabilities = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return visibleVulnerabilities.slice(start, start + pageSize);
  }, [visibleVulnerabilities, currentPage, pageSize]);
  const pageStart = filteredVulnCount === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const pageEnd = Math.min(currentPage * pageSize, filteredVulnCount);
  const pageNumbers = useMemo(() => buildPageNumbers(currentPage, totalPages), [currentPage, totalPages]);
  const visibleSummary = useMemo(() => summarizeSeverity(visibleVulnerabilities), [visibleVulnerabilities]);
  const statusDistribution = useMemo(() => buildStatusDistribution(visibleVulnerabilities), [visibleVulnerabilities]);
  const visibleIds = useMemo(() => visibleVulnerabilities.map((item) => item.id), [visibleVulnerabilities]);
  const pageIds = useMemo(() => pagedVulnerabilities.map((item) => item.id), [pagedVulnerabilities]);

  // Active filter chips: each non-empty filter becomes a removable chip.
  // The clear fn drops just that one key, preserving the rest.
  const activeFilterChips = useMemo(() => {
    const chips = [];
    if (filters.project_id) {
      const proj = projects.find((p) => p.id === filters.project_id);
      chips.push({ key: "project_id", label: proj ? proj.title : filters.project_id });
    }
    const sev = viewSeverity || filters.severity;
    if (sev) chips.push({ key: "severity", label: SEVERITY_META[sev]?.label || sev });
    const st = viewStatus || filters.status;
    if (st) chips.push({ key: "status", label: st === "confirmed" ? "Confirmed" : "Ignored" });
    if (filters.date_from) chips.push({ key: "date_from", label: `From ${filters.date_from}` });
    if (filters.date_to) chips.push({ key: "date_to", label: `To ${filters.date_to}` });
    return chips;
  }, [filters, projects, viewSeverity, viewStatus]);

  const clearFilter = (key) => setFilters((prev) => ({ ...prev, [key]: "" }));
  const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => selectedIds.includes(id));
  const allPageSelected = pageIds.length > 0 && pageIds.every((id) => selectedIds.includes(id));
  const detailVuln = useMemo(
    () => vulnerabilities.find((item) => item.id === detailVulnId) || null,
    [detailVulnId, vulnerabilities],
  );

  useEffect(() => {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(VULN_FILTERS_STORAGE_KEY, JSON.stringify(filters));
  }, [filters]);

  useEffect(() => {
    setSelectedIds((prev) => prev.filter((id) => visibleIds.includes(id)));
  }, [visibleIds]);

  useEffect(() => {
    if (detailVulnId && !vulnerabilities.some((item) => item.id === detailVulnId)) {
      setDetailVulnId(null);
    }
  }, [detailVulnId, vulnerabilities]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const pendingId = window.sessionStorage.getItem(VULN_FOCUS_STORAGE_KEY);
    if (!pendingId || !visibleVulnerabilities.length) return;
    const focusIndex = visibleVulnerabilities.findIndex((item) => String(item.id) === pendingId);
    if (focusIndex === -1) return;
    setPage(Math.floor(focusIndex / pageSize) + 1);
    setDetailVulnId(pendingId);
    window.sessionStorage.removeItem(VULN_FOCUS_STORAGE_KEY);
  }, [pageSize, visibleVulnerabilities]);

  // Reset to the first page whenever the result set or page size changes.
  useEffect(() => {
    setPage(1);
  }, [query, filters.search, filters.date_from, filters.date_to, pageSize]);

  // Keep the current page within bounds if the total shrinks.
  useEffect(() => {
    setPage((prev) => Math.min(prev, totalPages));
  }, [totalPages]);

  const toggleSelected = (id) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  };

  const togglePageSelected = () => {
    setSelectedIds((prev) =>
      allPageSelected ? prev.filter((id) => !pageIds.includes(id)) : Array.from(new Set([...prev, ...pageIds])),
    );
  };

  const toggleVisibleSelected = () => {
    setSelectedIds((prev) =>
      allVisibleSelected ? prev.filter((id) => !visibleIds.includes(id)) : Array.from(new Set([...prev, ...visibleIds])),
    );
  };

  const openDetail = (id) => setDetailVulnId(id);

  const closeDetail = () => setDetailVulnId(null);

  if (view === "export-records") {
    return <ExportRecordsView setToast={setToast} confirmAction={confirmAction} />;
  }

  return (
    <>
      <PageHeader
        compact
        title={`Vulnerability reports / ${viewTitle}`}
        subtitle="Review findings and track how they are handled"
        actions={<div className="button-row">
          <input ref={reportTemplateInputRef} type="file" accept=".docx" hidden onChange={uploadReportTemplate} />
          <button className="primary-outline compact" type="button" disabled={templateUploading} onClick={() => reportTemplateInputRef.current?.click()}>
            {templateUploading ? <Loader2 className="spin" size={17} /> : <FileText size={17} />}
            Import report template
          </button>
          <button className="primary-button compact report-export-button" type="button" onClick={exportTemplateReport}>
            <Download size={18} />
            Generate client report
          </button>
        </div>}
      />
      <section className="content-wrap vulnerability-report-page">
        <div className="notice-banner info">
          <FileText size={18} />
          <div>
            <strong>{reportTemplates.find((item) => item.is_active)?.name || "No report template imported"}</strong>
            <span>The report agent organizes confirmed findings. Pausing a project does not block viewing or export.</span>
          </div>
        </div>
        <div className="report-summary-grid">
          <VulnerabilitySummaryCard icon={ShieldAlert} label="Critical" value={visibleSummary.critical || 0} tone="critical" />
          <VulnerabilitySummaryCard icon={AlertTriangle} label="High" value={visibleSummary.high || 0} tone="high" />
          <VulnerabilitySummaryCard icon={AlertCircle} label="Medium" value={visibleSummary.medium || 0} tone="medium" />
          <VulnerabilitySummaryCard icon={ShieldCheck} label="Low" value={visibleSummary.low || 0} tone="low" />
          <VulnerabilitySummaryCard icon={CheckCheck} label="Confirmed" value={statusDistribution.confirmed || 0} tone="success" />
        </div>
        <div className="vuln-filter-bar">
          <div className="vuln-search-row">
            <label className="vuln-search">
              <Search size={15} />
              <input
                value={filters.search}
                onChange={(event) => setFilters({ ...filters, search: event.target.value })}
                placeholder="Search title, id, project, tags..."
              />
              {filters.search && (
                <button
                  type="button"
                  className="vuln-search-clear"
                  aria-label="Clear search"
                  onClick={() => setFilters((prev) => ({ ...prev, search: "" }))}
                >
                  <X size={13} />
                </button>
              )}
            </label>
            <span className="vuln-result-count">
              {filteredVulnCount > 0
                ? `${filteredVulnCount}  results`
                : "No matches"}
            </span>
            <button
              className="ghost-button compact filter-reset"
              type="button"
              disabled={!filteredVulnCount && !filters.search && activeFilterChips.length === 0}
              onClick={() => setFilters({ severity: "", project_id: "", status: "", search: "", date_from: "", date_to: "" })}
            >
              <X size={14} />
              Reset
            </button>
          </div>
          <div className="vuln-filter-row">
            <label className="vuln-filter-field">
              <select value={filters.project_id} onChange={(event) => setFilters({ ...filters, project_id: event.target.value })}>
                <option value="">Projects</option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.title}
                  </option>
                ))}
              </select>
            </label>
            <label className="vuln-filter-field">
              <select
                value={viewSeverity || filters.severity}
                disabled={!!viewSeverity}
                onChange={(event) => setFilters({ ...filters, severity: event.target.value })}
              >
                <option value="">Severity</option>
                {Object.entries(SEVERITY_META).map(([key, meta]) => (
                  <option key={key} value={key}>
                    {meta.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="vuln-filter-field">
              <select
                value={viewStatus || filters.status}
                disabled={!!viewStatus}
                onChange={(event) => setFilters({ ...filters, status: event.target.value })}
              >
                <option value="">Status</option>
                <option value="confirmed">Confirmed</option>
                <option value="ignored">Ignored</option>
              </select>
            </label>
            <label className="vuln-filter-field vuln-date-field">
              <input
                type="date"
                value={filters.date_from}
                max={filters.date_to || undefined}
                onChange={(event) => setFilters({ ...filters, date_from: event.target.value })}
              />
              <span className="vuln-date-sep"><ChevronRight size={12} /></span>
              <input
                type="date"
                value={filters.date_to}
                min={filters.date_from || undefined}
                onChange={(event) => setFilters({ ...filters, date_to: event.target.value })}
              />
            </label>
            {activeFilterChips.map((chip) => (
              <button
                key={chip.key}
                type="button"
                className="vuln-chip"
                onClick={() => clearFilter(chip.key)}
                title="Remove this filter"
              >
                {chip.label}
                <X size={12} />
              </button>
            ))}
          </div>
        </div>
        {loading ? (
          <EmptyState icon={Loader2} title="Analyzing vulnerability reports" />
        ) : visibleVulnerabilities.length === 0 ? (
          <EmptyState icon={CheckCircle2} title="No matching vulnerabilities" subtitle="Nothing in the current filter." />
        ) : (
          <article className="vuln-table-card vuln-table-card-full">
            <header className="vuln-table-title">
              <div>
                <h2>Vulnerabilities</h2>
                <p>Open a finding to see evidence, the process, and proof packets</p>
              </div>
              <div className="button-row">
                <button className="ghost-button compact" type="button" disabled={!pageIds.length} onClick={togglePageSelected}>
                  {allPageSelected ? "Clear page" : "Select page"}
                </button>
                <button className="ghost-button compact" type="button" disabled={!visibleIds.length} onClick={toggleVisibleSelected}>
                  {allVisibleSelected ? "Clear results" : "Select all results"}
                </button>
              </div>
            </header>
            {selectedIds.length > 0 && (
              <div className="vuln-bulk-bar">
                <div className="vuln-bulk-summary">
                  <strong>Selected {selectedIds.length}</strong>
                  <span>{allVisibleSelected ? "All filtered results are selected" : "Turn the page to add more"}</span>
                </div>
                <div className="button-row vuln-bulk-actions">
                  <button className="ghost-button compact" type="button" onClick={() => updateSelectedStatus("confirmed")}>
                    <CheckCircle2 size={15} />
                    Confirm selected
                  </button>
                  <button className="ghost-button compact warning" type="button" onClick={() => updateSelectedStatus("ignored")}>
                    <X size={15} />
                    Ignore selected
                  </button>
                  <button
                    className="primary-outline compact"
                    type="button"
                    onClick={() => exportMd({ selected: selectedIds, title: "rabbit-vulnerabilities-batch" })}
                  >
                    <Download size={15} />
                    Export selected
                  </button>
                  <button className="ghost-button compact" type="button" onClick={() => setSelectedIds([])}>
                    Clear selection
                  </button>
                </div>
              </div>
            )}
            <div className="vuln-table-scroll">
              <div className="vuln-table-head">
                <span />
                <span>Title</span>
                <span>Project</span>
                <span>Severity</span>
                <span>Status</span>
                <span>Discovered</span>
                <span>Action</span>
              </div>
              <div className="vuln-table-body">
                {pagedVulnerabilities.map((vuln) => (
                  <VulnerabilityItem
                    key={vuln.id}
                    vuln={vuln}
                    selected={selectedIds.includes(vuln.id)}
                    active={detailVulnId === vuln.id}
                    onSelect={() => toggleSelected(vuln.id)}
                    onOpen={() => openDetail(vuln.id)}
                    onExport={() => exportMd({ selected: [vuln.id], title: `${vuln.project_id}-${vuln.fact_id}` })}
                    onStatusChange={(status) => updateVulnerabilityStatus(vuln, status)}
                  />
                ))}
              </div>
            </div>
            <footer className="vuln-table-footer">
              <span className="vuln-table-footer-meta">
                {filteredVulnCount}{filteredVulnCount > 0 ? ` · ${pageStart}-${pageEnd}` : ""}
              </span>
              <div className="vuln-table-footer-controls">
                <label className="pagination-size">
                  <select value={pageSize} onChange={(event) => setPageSize(Number(event.target.value))}>
                    {[10, 20, 50, 100].map((size) => (
                      <option key={size} value={size}>
                        {size} / page
                      </option>
                    ))}
                  </select>
                </label>
                <div className="pagination">
                  <button
                    type="button"
                    aria-label="Previous"
                    disabled={currentPage <= 1}
                    onClick={() => setPage((prev) => Math.max(1, prev - 1))}
                  >
                    <ChevronRight size={14} />
                  </button>
                  {pageNumbers.map((item, index) =>
                    item === "..." ? (
                      <span key={`gap-${index}`}>...</span>
                    ) : (
                      <button
                        key={item}
                        className={cn(item === currentPage && "active")}
                        type="button"
                        onClick={() => setPage(item)}
                      >
                        {item}
                      </button>
                    ),
                  )}
                  <button
                    type="button"
                    aria-label="Next"
                    disabled={currentPage >= totalPages}
                    onClick={() => setPage((prev) => Math.min(totalPages, prev + 1))}
                  >
                    <ChevronRight size={14} />
                  </button>
                </div>
              </div>
            </footer>
          </article>
        )}
      </section>
      {detailVuln && (
        <VulnerabilityDrawer
          vuln={detailVuln}
          onClose={closeDetail}
          onExport={() => exportMd({ selected: [detailVuln.id], title: `${detailVuln.project_id}-${detailVuln.fact_id}` })}
          onStatusChange={(status) => updateVulnerabilityStatus(detailVuln, status)}
        />
      )}
    </>
  );
}

function ExportRecordsView({ setToast, confirmAction }) {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true);
    try {
      const list = await apiRequest("/api/vulnerabilities/export-records");
      setRecords(Array.isArray(list) ? list : []);
    } catch (error) {
      if (!silent) setToast({ type: "danger", message: error.message || "Could not load export history" });
    } finally {
      if (!silent) setLoading(false);
    }
  }, [setToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const timer = window.setInterval(() => load({ silent: true }), 8000);
    return () => window.clearInterval(timer);
  }, [load]);

  const formatLabels = { md: "Markdown", markdown: "Markdown", json: "JSON", csv: "CSV", pdf: "PDF", docx: "Word", word: "Word" };

  const redownload = async (record) => {
    setBusyId(record.id);
    try {
      const params = new URLSearchParams();
      params.set("format", record.format || "md");
      if (record.project_id) params.set("project_id", record.project_id);
      if (record.severity) params.set("severity", record.severity);
      if (record.status) params.set("status", record.status);
      await downloadFromApi(`/api/vulnerabilities/export?${params}`, record.filename);
      setToast({ type: "success", message: "Report exported again" });
      await load({ silent: true });
    } catch (error) {
      setToast({ type: "danger", message: error.message || "Could not export again" });
    } finally {
      setBusyId(null);
    }
  };

  const removeRecord = async (record) => {
    const ok = await confirmAction({
      title: "Delete export record",
      message: `Delete the export record "${record.filename}"?`,
      tone: "danger",
      confirmLabel: "Delete",
    });
    if (!ok) return;
    try {
      await apiRequest(`/api/vulnerabilities/export-records/${record.id}`, { method: "DELETE" });
      setToast({ type: "success", message: "Record deleted" });
      await load({ silent: true });
    } catch (error) {
      setToast({ type: "danger", message: error.message || "Could not delete" });
    }
  };

  const clearAll = async () => {
    const ok = await confirmAction({
      title: "Clear export history",
      message: "Clear all export history? This cannot be undone.",
      tone: "danger",
      confirmLabel: "Clear",
    });
    if (!ok) return;
    try {
      await apiRequest("/api/vulnerabilities/export-records", { method: "DELETE" });
      setToast({ type: "success", message: "Export history cleared" });
      await load({ silent: true });
    } catch (error) {
      setToast({ type: "danger", message: error.message || "Could not clear" });
    }
  };

  return (
    <>
      <PageHeader
        compact
        title="Vulnerability reports / Export history"
        subtitle="Past exports, including scope, format, and time"
      />
      <section className="content-wrap vulnerability-report-page">
        <article className="vuln-table-card export-records-card">
          <header className="vuln-table-title">
            <div>
              <h2>Export history</h2>
              <p>Each vulnerability export is recorded here</p>
            </div>
            <div className="button-row">
              <button
                className="ghost-button compact danger"
                type="button"
                disabled={!records.length}
                onClick={clearAll}
              >
                <Trash2 size={15} />
                Clear history
              </button>
              <button className="ghost-button compact" type="button" onClick={() => load()}>
                <RefreshCw size={15} />
                Refresh
              </button>
            </div>
          </header>
          <div className="export-records-head">
            <span>ExportTime</span>
            <span>Scope</span>
            <span>Format</span>
            <span>Count</span>
            <span>Filename</span>
            <span>Action</span>
          </div>
          <div className="export-records-body">
            {loading ? (
              <EmptyState icon={Loader2} title="Loading export history" />
            ) : records.length === 0 ? (
              <EmptyState icon={Download} title="No exports yet" subtitle="Exports from the vulnerability list show up here." />
            ) : (
              records.map((record) => (
                <div className="export-records-row" key={record.id}>
                  <time>{formatTime(record.created_at)}</time>
                  <div className="export-scope-cell">
                    <strong>{record.scope}</strong>
                    {record.project_name && <span>{record.project_name}</span>}
                  </div>
                  <span><Badge tone="info">{formatLabels[record.format] || record.format.toUpperCase()}</Badge></span>
                  <span className="export-count">{record.vulnerability_count}</span>
                  <code title={record.filename}>{record.filename}</code>
                  <div className="button-row export-record-actions">
                    <button
                      className="table-action"
                      type="button"
                      title="Export again"
                      aria-label="Export again"
                      disabled={busyId === record.id}
                      onClick={() => redownload(record)}
                    >
                      {busyId === record.id ? <Loader2 className="spin" size={15} /> : <Download size={15} />}
                    </button>
                    <button
                      className="table-action danger"
                      type="button"
                      title="Delete record"
                      aria-label="Delete record"
                      onClick={() => removeRecord(record)}
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </article>
      </section>
    </>
  );
}

function summarizeSeverity(items) {
  return items.reduce(
    (acc, item) => {
      acc[item.severity] = (acc[item.severity] || 0) + 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );
}

function buildVulnerabilityTrend(items) {
  // Build a fixed 7-day calendar window ending today (local time), so the
  // chart always shows the last 7 days even on days with no findings.
  const dayKeys = [];
  const byKey = new Map();
  const now = new Date();
  for (let offset = 6; offset >= 0; offset -= 1) {
    const day = new Date(now.getFullYear(), now.getMonth(), now.getDate() - offset);
    const key = `${day.getFullYear()}-${String(day.getMonth() + 1).padStart(2, "0")}-${String(day.getDate()).padStart(2, "0")}`;
    dayKeys.push(key);
    byKey.set(key, {
      date: key,
      label: `${String(day.getMonth() + 1).padStart(2, "0")}-${String(day.getDate()).padStart(2, "0")}`,
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    });
  }
  items.forEach((item) => {
    const key = String(item.discovered_at || "").slice(0, 10);
    const entry = byKey.get(key);
    if (!entry) return;
    entry.total += 1;
    if (entry[item.severity] !== undefined) entry[item.severity] += 1;
  });
  return dayKeys.map((key) => byKey.get(key));
}

function buildSeverityTop(items, limit = 5) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...items]
    .sort((a, b) => {
      const byRank = (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9);
      if (byRank !== 0) return byRank;
      return String(b.discovered_at || "").localeCompare(String(a.discovered_at || ""));
    })
    .slice(0, limit);
}

function buildPageNumbers(current, total) {
  // Compact pager: always show first/last, current ±1, with ellipsis gaps.
  if (total <= 7) {
    return Array.from({ length: total }, (_, index) => index + 1);
  }
  const pages = new Set([1, total, current, current - 1, current + 1]);
  const sorted = [...pages].filter((page) => page >= 1 && page <= total).sort((a, b) => a - b);
  const result = [];
  let prev = 0;
  for (const page of sorted) {
    if (page - prev > 1) result.push("...");
    result.push(page);
    prev = page;
  }
  return result;
}

function buildStatusDistribution(items) {
  return items.reduce(
    (acc, item) => {
      if (item.status === "ignored") acc.ignored += 1;
      else acc.confirmed += 1;
      acc.total += 1;
      return acc;
    },
    { total: 0, confirmed: 0, ignored: 0 },
  );
}

function VulnerabilityTrend({ data }) {
  const series = [
    ["critical", "Critical", "#ff375f"],
    ["high", "High", "#ff7a1a"],
    ["medium", "Medium", "#f5b700"],
    ["low", "Low", "#0a84ff"],
  ];
  const hasData = data.some((item) => item.total > 0);
  const max = Math.max(1, ...data.flatMap((item) => series.map(([key]) => item[key] || 0)));
  const width = 280;
  const height = 120;
  const padX = 6;
  const innerW = width - padX * 2;
  const pointX = (index) => (data.length <= 1 ? width / 2 : padX + (index / (data.length - 1)) * innerW);
  const pointY = (value) => height - ((value || 0) / max) * (height - 18) - 9;
  const toPoints = (key) => data.map((item, index) => `${pointX(index)},${pointY(item[key])}`).join(" ");
  return (
    <section className="vuln-analysis-card">
      <header>
        <h3>Vulnerability trend</h3>
        <span>Last 7 days</span>
      </header>
      {!hasData ? (
        <p className="analysis-empty">No new findings in the last 7 days</p>
      ) : (
        <>
          <svg className="trend-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Vulnerability trend">
            {series.map(([key, label, color]) => (
              <polyline
                key={key}
                points={toPoints(key)}
                fill="none"
                stroke={color}
                strokeWidth="2.4"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-label={label}
              />
            ))}
            {data.map((item, index) =>
              series.map(([key, label, color]) => (
                <circle
                  key={`${item.date}-${key}`}
                  cx={pointX(index)}
                  cy={pointY(item[key])}
                  r="2.8"
                  fill={color}
                  aria-label={`${item.date} ${label} ${item[key] || 0}`}
                />
              )),
            )}
          </svg>
          <div className="trend-axis">
            {data.map((item) => (
              <span key={`axis-${item.date}`}>{item.label}</span>
            ))}
          </div>
          <div className="trend-legend">
            {series.map(([key, label, color]) => (
              <span key={key}>
                <i style={{ background: color }} />
                <strong>{data.reduce((sum, item) => sum + (item[key] || 0), 0)}</strong>
                {label}
              </span>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

function SeverityTopList({ items, onSelect }) {
  return (
    <section className="vuln-analysis-card severity-top-card">
      <header>
        <h3>Top 5 critical findings</h3>
        <span>{items.length}</span>
      </header>
      <div className="severity-top-list">
        {items.length === 0 ? (
          <p className="analysis-empty">No vulnerabilities</p>
        ) : (
          items.map((item, index) => {
            const meta = SEVERITY_META[item.severity] || SEVERITY_META.low;
            return (
              <button
                key={`top-${item.id}`}
                className={cn("severity-top-item", onSelect && "linked")}
                type="button"
                onClick={() => onSelect?.(item)}
              >
                <span className="severity-top-rank">{index + 1}</span>
                <span className={cn("status-badge", meta.tone)}>{meta.label}</span>
                <strong title={item.title}>{clampText(item.title, 30)}</strong>
                <code>{item.fact_id}</code>
              </button>
            );
          })
        )}
      </div>
    </section>
  );
}

function VulnerabilityStatusDistribution({ data }) {
  const total = Math.max(0, data.total || 0);
  const confirmed = data.confirmed || 0;
  const ignored = data.ignored || 0;
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const confirmedLength = total ? (confirmed / total) * circumference : 0;
  const ignoredLength = total ? (ignored / total) * circumference : 0;
  return (
    <section className="vuln-analysis-card status-distribution-card">
      <header>
        <h3>Status</h3>
        <span>Live</span>
      </header>
      {total === 0 ? (
        <p className="analysis-empty">No status data</p>
      ) : (
        <div className="status-distribution">
          <svg viewBox="0 0 96 96" role="img" aria-label="Vulnerability status">
            <circle className="donut-track" cx="48" cy="48" r={radius} />
            <circle
              className="donut-segment confirmed"
              cx="48"
              cy="48"
              r={radius}
              strokeDasharray={`${confirmedLength} ${circumference - confirmedLength}`}
            />
            <circle
              className="donut-segment ignored"
              cx="48"
              cy="48"
              r={radius}
              strokeDasharray={`${ignoredLength} ${circumference - ignoredLength}`}
              strokeDashoffset={-confirmedLength}
            />
            <text x="48" y="45" textAnchor="middle">
              {total}
            </text>
            <text x="48" y="59" textAnchor="middle" className="donut-caption">
              Total
            </text>
          </svg>
          <div className="status-distribution-list">
            <span>
              <i className="status-dot confirmed" />
              Confirmed
              <strong>{confirmed}</strong>
            </span>
            <span>
              <i className="status-dot ignored" />
              Ignored
              <strong>{ignored}</strong>
            </span>
          </div>
        </div>
      )}
    </section>
  );
}

function VulnerabilityItem({ vuln, selected, active, onSelect, onOpen, onExport, onStatusChange }) {
  const meta = SEVERITY_META[vuln.severity] || SEVERITY_META.low;
  const ignored = vuln.status === "ignored";
  return (
    <article className={cn("vuln-table-item", ignored && "ignored", active && "active")}>
      <div
        className="vuln-table-row"
        role="button"
        tabIndex={0}
        onClick={onOpen}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onOpen();
          }
        }}
      >
        <label className="vuln-select" onClick={(event) => event.stopPropagation()}>
          <input type="checkbox" checked={selected} onChange={onSelect} />
        </label>
        <div className="vuln-name-cell">
          <div className="vuln-meta">
            <span>{vuln.fact_id}</span>
          </div>
          <button
            className="vuln-title-button"
            type="button"
            title={vuln.title}
            onClick={(event) => {
              event.stopPropagation();
              onOpen();
            }}
          >
            <span className="vuln-title-text">{vuln.title}</span>
          </button>
        </div>
        <div className="vuln-project-cell">
          <strong>{vuln.project_name}</strong>
          <span>{vuln.project_id}</span>
        </div>
        <div>
          <Badge tone={meta.tone}>{meta.label}</Badge>
        </div>
        <div>
          <Badge tone={ignored ? "muted" : "success"}>{ignored ? "Ignored" : "Confirmed"}</Badge>
        </div>
        <time>{formatTime(vuln.discovered_at)}</time>
        <div className="button-row vuln-table-actions" onClick={(event) => event.stopPropagation()}>
          <button className="table-inline-action detail" type="button" onClick={onOpen} title="View details" aria-label="View details">
            <Eye size={14} />
            Details
          </button>
          <button
            className="table-inline-action"
            type="button"
            onClick={onExport}
            title="Export"
            aria-label="Export"
          >
            <Download size={14} />
          </button>
          <button
            className={cn("table-inline-action", ignored ? "success" : "warning")}
            type="button"
            onClick={() => onStatusChange(ignored ? "confirmed" : "ignored")}
            title={ignored ? "Restore" : "Ignore"}
            aria-label={ignored ? "Restore" : "Ignore"}
          >
            {ignored ? <CheckCircle2 size={14} /> : <X size={14} />}
          </button>
        </div>
      </div>
    </article>
  );
}

function VulnerabilityDrawer({ vuln, onClose, onExport, onStatusChange }) {
  const meta = SEVERITY_META[vuln.severity] || SEVERITY_META.low;
  const ignored = vuln.status === "ignored";
  const [reportDraft, setReportDraft] = useState(null);
  const [reportLoading, setReportLoading] = useState(true);
  const [reportRefreshing, setReportRefreshing] = useState(false);
  const [reportError, setReportError] = useState("");
  const [reportHint, setReportHint] = useState("");
  const [screenshotEvidence, setScreenshotEvidence] = useState([]);
  const [screenshotUploading, setScreenshotUploading] = useState(false);
  const screenshotInputRef = useRef(null);

  const loadScreenshotEvidence = useCallback(async () => {
    try {
      setScreenshotEvidence(await apiRequest(`/api/vulnerabilities/${encodeURIComponent(vuln.id)}/evidence`));
    } catch {
      setScreenshotEvidence([]);
    }
  }, [vuln.id]);

  const uploadScreenshotEvidence = async (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setScreenshotUploading(true);
    try {
      const content = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result).split(",", 2)[1] || "");
        reader.onerror = () => reject(new Error("Could not read the screenshot"));
        reader.readAsDataURL(file);
      });
      await apiRequest(`/api/vulnerabilities/${encodeURIComponent(vuln.id)}/evidence/screenshot`, {
        method: "POST",
        body: { filename: file.name, mime_type: file.type, content_base64: content },
      });
      setReportHint("Screenshot saved. It will be inserted into the client report.");
      await loadScreenshotEvidence();
    } catch (error) {
      setReportHint(error.message || "Could not upload the screenshot");
    } finally {
      setScreenshotUploading(false);
    }
  };

  // Anchor nav: scroll a section into view inside the drawer content pane.
  // Uses button onClick (not <a href="#id">) so we don't mutate the URL hash,
  // which would be picked up by the hash router and navigate away.
  const scrollDrawerTo = useCallback((sectionId) => {
    const el = document.getElementById(sectionId);
    if (!el) return;
    el.scrollIntoView({ behavior: "smooth", block: "start" });
    // briefly highlight the target section for affordance
    el.classList.add("drawer-section-flash");
    window.setTimeout(() => el.classList.remove("drawer-section-flash"), 700);
  }, []);

  const regenerateReportDraft = useCallback(async () => {
    setReportRefreshing(true);
    setReportHint("Regenerating the report with the model…");
    try {
      const payload = await apiRequest(
        `/api/vulnerabilities/${encodeURIComponent(vuln.id)}/report?use_model=1`,
      );
      if (payload?.composer_source === "model") {
        setReportDraft(payload);
        setReportError("");
        setReportHint(`Switched to ${payload.composer_model || "Model"} version`);
      } else {
        setReportHint("The model did not respond. The template draft is unchanged.");
      }
    } catch (error) {
      if (!reportDraft) {
        setReportError(error.message || "Could not generate the report draft");
      }
      setReportHint("The model is unavailable. The template draft is unchanged.");
    } finally {
      setReportRefreshing(false);
    }
  }, [reportDraft, vuln.id]);

  useEffect(() => {
    const onKeyDown = (event) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  useEffect(() => {
    let cancelled = false;
    setReportLoading(true);
    setReportRefreshing(false);
    setReportError("");
    setReportHint("");

    const load = async () => {
      try {
        // Only fetch the template version on open — fast (~1s) and gives
        // the user something to read immediately. The LLM-enhanced version
        // (use_model=1) is slow (~80s on glm-5.2) and is triggered on demand
        // by the "Regenerate with model" button, not auto-fired on every drawer open.
        const payload = await apiRequest(`/api/vulnerabilities/${encodeURIComponent(vuln.id)}/report`);
        if (cancelled) return;
        setReportDraft(payload);
        setReportHint(payload?.composer_source === "model" ? `Switched to ${payload.composer_model || "Model"} version` : "Template draft is ready. Regenerate with the model to produce a reproducible script.");
      } catch (error) {
        if (cancelled) return;
        setReportDraft(null);
        setReportError(error.message || "Could not generate the report draft");
      } finally {
        if (!cancelled) {
          setReportLoading(false);
        }
      }
    };

    load();
    return () => {
      cancelled = true;
    };
  }, [vuln.id]);

  useEffect(() => {
    loadScreenshotEvidence();
  }, [loadScreenshotEvidence]);

  return (
    <div className="drawer-backdrop" role="presentation" onClick={onClose}>
      <aside
        className="drawer-panel vulnerability-drawer"
        role="dialog"
        aria-modal="true"
        aria-label={`Vulnerability ${vuln.fact_id}`}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="drawer-header">
          <div className="drawer-heading">
            <div className="drawer-kicker">
              <span className="drawer-fact-id">{vuln.fact_id}</span>
              <Badge tone={meta.tone}>{meta.label}</Badge>
              <Badge tone={ignored ? "muted" : "success"}>{ignored ? "Ignored" : "Confirmed"}</Badge>
            </div>
            <h2>{vuln.title}</h2>
            <p>
              {vuln.project_name} · <span className="mono">{vuln.project_id}</span> · Discovered {formatTime(vuln.discovered_at)}
            </p>
          </div>
          <button className="icon-button drawer-close" type="button" onClick={onClose} aria-label="Close details">
            <X size={18} />
          </button>
        </header>
        <div className="drawer-body drawer-dual">
          <nav className="drawer-anchor-nav" aria-label="Vulnerability sections">
            <button type="button" className="drawer-anchor-link" onClick={() => scrollDrawerTo("vuln-narrative")}>Delivery draft</button>
            <button type="button" className="drawer-anchor-link" onClick={() => scrollDrawerTo("vuln-info")}>Overview</button>
            <button type="button" className="drawer-anchor-link" onClick={() => scrollDrawerTo("vuln-description")}>Proof narrative</button>
            <button type="button" className="drawer-anchor-link" onClick={() => scrollDrawerTo("vuln-evidence")}>Key evidence</button>
            <button type="button" className="drawer-anchor-link" onClick={() => scrollDrawerTo("vuln-packets")}>Proof packets</button>
            <button type="button" className="drawer-anchor-link" onClick={() => scrollDrawerTo("vuln-process")}>How it emerged</button>
          </nav>
          <div className="drawer-content">
            <section id="vuln-narrative" className="drawer-section">
              <VulnerabilityNarrativeCard
                report={reportDraft}
                loading={reportLoading}
                refreshing={reportRefreshing}
                error={reportError}
                hint={reportHint}
                onRefresh={regenerateReportDraft}
              />
            </section>
            <section id="vuln-info" className="drawer-section">
              <h4>Overview</h4>
              <div className="drawer-info-grid">
                <InfoBox label="Project" value={`${vuln.project_name} (${vuln.project_id})`} />
                <InfoBox label="Confirmed fact" value={vuln.fact_id} />
                <InfoBox label="Source step" value={vuln.source_step_id || vuln.source_intent_id || "-"} />
                <InfoBox label="Workers" value={vuln.source_worker || "-"} />
              </div>
            </section>
            <section id="vuln-description" className="drawer-section">
              <h4>Proof narrative</h4>
              <p className="soft-box">{vuln.description || "Not recorded"}</p>
            </section>
            <section id="vuln-evidence" className="drawer-section">
              <div className="section-title-row">
                <h4>Key evidence</h4>
                <input ref={screenshotInputRef} type="file" accept="image/png,image/jpeg" hidden onChange={uploadScreenshotEvidence} />
                <button className="primary-outline compact" type="button" disabled={screenshotUploading} onClick={() => screenshotInputRef.current?.click()}>
                  {screenshotUploading ? <Loader2 className="spin" size={14} /> : <Eye size={14} />}
                  Add a proof screenshot
                </button>
              </div>
              <div className="evidence-list">
                {(vuln.evidence?.length ? vuln.evidence : ["Not recorded"]).map((item, index) => (
                  <p key={`${item}-${index}`}>{item}</p>
                ))}
              </div>
              {!!screenshotEvidence.length && <p className="muted-copy">Saved {screenshotEvidence.length} proof screenshots. They are inserted into the client report.</p>}
            </section>
            <section id="vuln-packets" className="drawer-section">
              <h4>Proof packets</h4>
              <div className="packet-list">
                {(vuln.proof_packets || []).length === 0 ? (
                  <p className="soft-box">No proof packet recorded.</p>
                ) : (
                  vuln.proof_packets.map((packet, index) => (
                    <ProofPacket key={`${packet.title}-${index}`} packet={packet} index={index} />
                  ))
                )}
              </div>
            </section>
            <section id="vuln-process" className="drawer-section">
              <h4>How it emerged</h4>
              <div className="process-list">
                {(vuln.process || []).length === 0 ? (
                  <p className="soft-box">No emergence process recorded.</p>
                ) : (
                  (vuln.process || []).map((step, index) => (
                    <article className="process-step" key={`${step.id}-${index}`}>
                      <span className="process-node" />
                      <div className="process-body">
                        <div className="process-head">
                          <strong>
                            {step.label || step.type || "Process"} {step.id || ""}
                          </strong>
                          {(step.worker || step.time) && (
                            <small>
                              {step.worker || ""} {step.time ? `· ${formatTime(step.time)}` : ""}
                            </small>
                          )}
                        </div>
                        <p>{step.description || "No description"}</p>
                      </div>
                    </article>
                  ))
                )}
              </div>
            </section>
          </div>
        </div>
        <footer className="drawer-footer">
          <button className="ghost-button compact" type="button" onClick={onClose}>
            Close
          </button>
          <div className="drawer-footer-actions">
            <button
              className="ghost-button compact"
              type="button"
              onClick={regenerateReportDraft}
              disabled={reportLoading || reportRefreshing}
            >
              {reportRefreshing ? <Loader2 className="spin" size={16} /> : <Sparkles size={16} />}
              Regenerate with model
            </button>
            <button className="primary-outline compact" type="button" onClick={onExport}>
              <Download size={16} />
              Export
            </button>
            <button
              className={cn("ghost-button compact", ignored ? "success" : "warning")}
              type="button"
              onClick={() => onStatusChange(ignored ? "confirmed" : "ignored")}
            >
              {ignored ? <CheckCircle2 size={16} /> : <X size={16} />}
              {ignored ? "Restore" : "Ignore"}
            </button>
          </div>
        </footer>
      </aside>
    </div>
  );
}

// Proof packet card with copy buttons + collapsible long request/response.
// Pure-client: uses navigator.clipboard, no API. Falls back to a textarea
// select hack when clipboard API is unavailable (older browsers / non-HTTPS).
function ProofPacket({ packet, index }) {
  const request = packet.request || "";
  const response = packet.response || "";
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(null); // "request" | "response" | null

  const copy = async (label, text) => {
    if (!text) return;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      setCopied(label);
      window.setTimeout(() => setCopied(null), 1400);
    } catch {
      setCopied(null);
    }
  };

  const longRequest = request.split("\n").length > 12;
  const longResponse = response.split("\n").length > 12;

  return (
    <article className="packet-card">
      <header className="packet-head">
        <strong>{packet.title || `Proof ${index + 1}`}</strong>
      </header>
      <div className="packet-block">
        <div className="packet-block-head">
          <span>Request</span>
          <button
            type="button"
            className="packet-copy"
            onClick={() => copy("request", request)}
            disabled={!request}
            aria-label="Copy request"
          >
            {copied === "request" ? <Check size={13} /> : <Copy size={13} />}
            {copied === "request" ? "Copied" : "Copy"}
          </button>
        </div>
        <pre className={cn(!expanded && longRequest && "collapsed")}>{request || "Not recorded"}</pre>
        {longRequest && (
          <button type="button" className="packet-toggle" onClick={() => setExpanded((v) => !v)}>
            {expanded ? "Collapse" : `Expand all (${request.split("\n").length}  lines)`}
          </button>
        )}
      </div>
      <div className="packet-block">
        <div className="packet-block-head">
          <span>Response</span>
          <button
            type="button"
            className="packet-copy"
            onClick={() => copy("response", response)}
            disabled={!response}
            aria-label="Copy response"
          >
            {copied === "response" ? <Check size={13} /> : <Copy size={13} />}
            {copied === "response" ? "Copied" : "Copy"}
          </button>
        </div>
        <pre className={cn(!expanded && longResponse && "collapsed")}>{response || "Not recorded"}</pre>
        {longResponse && (
          <button type="button" className="packet-toggle" onClick={() => setExpanded((v) => !v)}>
            {expanded ? "Collapse" : `Expand all (${response.split("\n").length}  lines)`}
          </button>
        )}
      </div>
      {packet.note && <p className="packet-note">{packet.note}</p>}
    </article>
  );
}

function VulnerabilityNarrativeCard({ report, loading, refreshing, error, hint, onRefresh }) {
  const statusChip = loading
    ? "loading"
    : error
      ? "error"
      : report?.composer_source === "model"
        ? "model"
        : refreshing
          ? "enhancing"
          : report
            ? "template"
            : "empty";
  const statusLabel = {
    loading: "Generating",
    error: "Unavailable",
    model: `Model · ${report?.composer_model || "Model"}`,
    enhancing: "Template ready · enhancing",
    template: "Template draft",
    empty: "Waiting",
  }[statusChip];
  return (
    <section className="drawer-section report-draft-section">
      <div className="report-draft-head">
        <div className="report-draft-heading">
          <h4>Delivery draft</h4>
          <span className={cn("report-draft-chip", statusChip)}>{statusLabel}</span>
        </div>
        <button
          className="ghost-button compact"
          type="button"
          onClick={onRefresh}
          disabled={loading || refreshing}
        >
          {refreshing ? <Loader2 className="spin" size={15} /> : <RefreshCw size={15} />}
          Regenerate with model
        </button>
      </div>
      {!!hint && hint !== statusLabel && <small className="report-draft-hint">{hint}</small>}
      {loading ? (
        <div className="report-draft-card report-draft-loading">
          <Loader2 className="spin" size={16} />
          <span>Preparing the report draft…</span>
        </div>
      ) : error ? (
        <div className="report-draft-card report-draft-error">
          <strong>Report draft unavailable</strong>
          <p>{error}</p>
        </div>
      ) : !report ? (
        <div className="report-draft-card report-draft-error">
          <strong>Report draft unavailable</strong>
          <p>This finding does not have a delivery draft yet.</p>
        </div>
      ) : (
        <div className="report-draft-card">
          <div className="report-draft-summary">
            <span className="report-draft-type">{report.vulnerability_type}</span>
            <p>{report.executive_summary}</p>
          </div>
          {!!report.attack_surface?.length && (
            <div className="report-draft-block">
              <h5>Attack surface</h5>
              <div className="report-draft-tags">
                {report.attack_surface.map((item) => (
                  <span key={item}>{item}</span>
                ))}
              </div>
            </div>
          )}
          <div className="report-draft-block">
            <h5>Proof</h5>
            <p>{report.vulnerability_proof}</p>
          </div>
          {!!report.exploit_script ? (
            <div className="report-draft-block">
              <h5>Exploit script</h5>
              <div className="exploit-script-card">
                <div className="exploit-script-head">
                  <span>Reproducible Python 3 script</span>
                  <button
                    type="button"
                    className="packet-copy"
                    onClick={() => {
                      const text = report.exploit_script.replace(/^```python\s*/, "").replace(/```\s*$/, "");
                      if (navigator.clipboard?.writeText) {
                        navigator.clipboard.writeText(text);
                      }
                    }}
                    aria-label="Copy script"
                  >
                    <Copy size={13} />
                    Copy
                  </button>
                </div>
                <pre className="exploit-script-pre">{report.exploit_script.replace(/^```python\s*/, "").replace(/```\s*$/, "")}</pre>
              </div>
            </div>
          ) : (
            <div className="report-draft-block muted">
              <h5>Exploit script</h5>
              <p className="soft-box">This finding can be reproduced from the proof steps above and does not need a separate script. Regenerate with the model if you want one.</p>
            </div>
          )}
          {!!report.proof_points?.length && (
            <div className="report-draft-block">
              <h5>Proof points</h5>
              <div className="report-draft-points">
                {report.proof_points.map((point) => (
                  <article key={`${point.label}-${point.content}`}>
                    <strong>{point.label}</strong>
                    <p>{point.content}</p>
                  </article>
                ))}
              </div>
            </div>
          )}
          <div className="report-draft-two-col">
            <div className="report-draft-block">
              <h5>Impact</h5>
              <p>{report.impact}</p>
            </div>
            <div className="report-draft-block">
              <h5>Root cause</h5>
              <p>{report.root_cause}</p>
            </div>
          </div>
          {!!report.evidence_highlights?.length && (
            <div className="report-draft-block">
              <h5>Key evidence</h5>
              <ul className="report-draft-list">
                {report.evidence_highlights.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          )}
          {!!report.remediation?.length && (
            <div className="report-draft-block">
              <h5>Remediation</h5>
              <ul className="report-draft-list">
                {report.remediation.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          )}
          {!!report.operator_notes?.length && (
            <div className="report-draft-block muted">
              <h5>Notes</h5>
              <ul className="report-draft-list">
                {report.operator_notes.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function InfoBox({ label, value }) {
  return (
    <div className="info-box">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function WorkersPage({ runAction, setToast, confirmAction }) {
  const [workers, setWorkers] = useState([]);
  const [config, setConfig] = useState(null);
  const [observability, setObservability] = useState(null);
  const [history, setHistory] = useState({});
  const [expanded, setExpanded] = useState({});
  const [editor, setEditor] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [batchTesting, setBatchTesting] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [statusFilter, setStatusFilter] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [viewMode, setViewMode] = useState("grid");

  const load = useCallback(async ({ background = false } = {}) => {
    if (background) setRefreshing(true);
    try {
      const [statusList, configPayload, observabilityPayload] = await Promise.all([
        apiRequest("/api/workers").catch((error) => {
          setToast({ type: "warning", message: error.message || "Worker status is unavailable" });
          return [];
        }),
        apiRequest("/api/workers/config").catch((error) => {
          setToast({ type: "warning", message: error.message || "Worker configuration is unavailable" });
          return null;
        }),
        apiRequest("/api/workers/observability").catch(() => null),
      ]);
      setWorkers(statusList);
      setConfig(configPayload);
      setObservability(observabilityPayload);
      setLastUpdated(new Date());
    } finally {
      setLoading(false);
      if (background) setRefreshing(false);
    }
  }, [setToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const preset = consumeRoutePreset(WORKER_PRESET_STORAGE_KEY);
    if (preset?.status) setStatusFilter(String(preset.status));
  }, []);

  useEffect(() => {
    if (!autoRefresh) return undefined;
    const timer = window.setInterval(() => {
      load({ background: true }).catch(() => {});
    }, 15000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, load]);

  const statusByName = useMemo(() => new Map(workers.map((worker) => [worker.name, worker])), [workers]);
  const visibleWorkers = useMemo(() => {
    const configured = config?.workers || [];
    const names = new Set(configured.map((worker) => worker.name));
    const statusOnly = workers.filter((worker) => !names.has(worker.name)).map((worker) => ({ ...worker, env: {} }));
    return [...configured, ...statusOnly];
  }, [config, workers]);
  const configuredNames = useMemo(() => new Set((config?.workers || []).map((worker) => worker.name)), [config]);
  const workerCards = useMemo(() => {
    return visibleWorkers.map((worker) => {
      const live = statusByName.get(worker.name) || worker;
      const statusKey = live.status || (worker.enabled === false ? "disabled" : "offline");
      const statusMeta = STATUS_META[statusKey] || STATUS_META.offline;
      const taskTypes = worker.task_types?.length ? worker.task_types : [...TASK_TYPES];
      return {
        worker,
        live,
        statusKey,
        statusMeta,
        isManaged: configuredNames.has(worker.name),
        modelLabel: workerModelLabel(worker),
        runtimeLabel: workerRuntimeLabel(worker),
        heartbeatLabel: relativeHeartbeat(live.last_heartbeat_seconds_ago),
        taskTypes,
        searchBlob: [
          worker.name,
          worker.type,
          workerModelLabel(worker),
          workerRuntimeLabel(worker),
          statusMeta.label,
          taskTypes.join(" "),
          live.current_task || "",
        ]
          .join(" ")
          .toLowerCase(),
      };
    });
  }, [configuredNames, statusByName, visibleWorkers]);
  const workerCounts = useMemo(() => {
    const counts = { total: workerCards.length, online: 0, idle: 0, running: 0, offline: 0, disabled: 0, tasks: 0 };
    for (const card of workerCards) {
      if (card.statusKey === "busy") counts.running += 1;
      if (card.statusKey === "idle") counts.idle += 1;
      if (card.statusKey === "idle" || card.statusKey === "busy") counts.online += 1;
      if (card.statusKey === "offline") counts.offline += 1;
      if (card.statusKey === "disabled") counts.disabled += 1;
      counts.tasks += card.live.tasks_completed || 0;
    }
    return counts;
  }, [workerCards]);
  const statusTabs = useMemo(
    () => [
      { key: "all", label: "All", count: workerCounts.total, tone: "info" },
      { key: "online", label: "Online", count: workerCounts.online, tone: "success" },
      { key: "idle", label: "Idle", count: workerCounts.idle, tone: "info" },
      { key: "offline", label: "Offline", count: workerCounts.offline, tone: "danger" },
      { key: "disabled", label: "Disabled", count: workerCounts.disabled, tone: "muted" },
    ],
    [workerCounts],
  );
  const filteredWorkers = useMemo(() => {
    const keyword = searchTerm.trim().toLowerCase();
    const rank = { busy: 0, idle: 1, offline: 2, disabled: 3 };
    return workerCards
      .filter((card) => {
        if (statusFilter === "online" && !["idle", "busy"].includes(card.statusKey)) return false;
        if (statusFilter !== "all" && statusFilter !== "online" && card.statusKey !== statusFilter) return false;
        if (keyword && !card.searchBlob.includes(keyword)) return false;
        return true;
      })
      .sort((left, right) => {
        const rankDelta = (rank[left.statusKey] ?? 99) - (rank[right.statusKey] ?? 99);
        if (rankDelta !== 0) return rankDelta;
        return right.live.tasks_completed - left.live.tasks_completed || left.worker.name.localeCompare(right.worker.name);
      });
  }, [searchTerm, statusFilter, workerCards]);

  const saveWorkers = async (nextWorkers, label = "Worker configuration saved") => {
    const updated = await runAction(label, () =>
      apiRequest("/api/workers/config", { method: "PUT", body: { workers: nextWorkers } }),
    );
    setConfig(updated);
    await load({ background: true });
  };

  const setEnabled = async (worker, enabled) => {
    if (!config) return;
    const next = config.workers.map((item) => (item.name === worker.name ? { ...item, enabled } : item));
    await saveWorkers(next, enabled ? "Worker enabled" : "Worker disabled");
  };

  const testWorker = async (worker) => {
    const source = config?.workers?.find((item) => item.name === worker.name) || worker;
    const result = await runAction(null, () =>
      apiRequest("/api/workers/config/test", { method: "POST", body: { worker: normalizeWorkerForSave(source) } }),
    );
    setToast({
      type: result.ok ? "success" : "danger",
      message: result.ok ? `${result.worker_name} connectivity ok` : `${result.worker_name} test failed: ${result.preview || result.stderr_preview}`,
    });
  };

  const loadHistory = async (workerName) => {
    if (history[workerName]) return;
    const rows = await runAction(null, () => apiRequest(`/api/workers/${encodeURIComponent(workerName)}/history`));
    setHistory((prev) => ({ ...prev, [workerName]: rows }));
  };

  const toggleHistory = async (workerName) => {
    const open = !expanded[workerName];
    setExpanded((prev) => ({ ...prev, [workerName]: open }));
    if (open) await loadHistory(workerName);
  };

  const saveEditor = async (worker) => {
    if (!config) return;
    const normalized = normalizeWorkerForSave(worker);
    const exists = config.workers.some((item) => item.name === normalized.name);
    const next = exists
      ? config.workers.map((item) => (item.name === normalized.name ? normalized : item))
      : [...config.workers, normalized];
    await saveWorkers(next, exists ? "Worker updated" : "Worker added");
    setEditor(null);
  };

  const deleteWorker = async (worker) => {
    if (!config) return;
    const ok = await confirmAction({
      title: "Delete worker",
      message: `Delete worker "${worker.name}"?`,
      tone: "danger",
      confirmLabel: "Delete",
    });
    if (!ok) return;
    await saveWorkers(config.workers.filter((item) => item.name !== worker.name), "Worker deleted");
    setEditor(null);
  };
  const openEditorForWorker = (worker) => {
    if (configuredNames.has(worker.name)) {
      setEditor(worker);
      return;
    }
    setEditor(workerDraftFromStatus(worker, config?.workers || []));
  };
  const testVisibleWorkers = async () => {
    if (!filteredWorkers.length || batchTesting) return;
    setBatchTesting(true);
    let ok = 0;
    const failed = [];
    try {
      for (const card of filteredWorkers) {
        try {
          const source = config?.workers?.find((item) => item.name === card.worker.name) || card.worker;
          const result = await apiRequest("/api/workers/config/test", {
            method: "POST",
            body: { worker: normalizeWorkerForSave(source) },
          });
          if (result.ok) ok += 1;
          else failed.push(result.worker_name || card.worker.name);
        } catch {
          failed.push(card.worker.name);
        }
      }
      setToast({
        type: failed.length ? "warning" : "success",
        message: failed.length
          ? `Batch test finished: ${ok} ok, ${failed.length} failed`
          : `Batch test finished: ${ok} workers connected`,
      });
    } finally {
      setBatchTesting(false);
      await load({ background: true });
    }
  };

  return (
    <>
      <section className="content-wrap workers-console-page">
        <section className="workers-console-shell">
          <div className="workers-console-head">
            <div className="workers-console-title">
              <span className="workers-console-mark">
                <Monitor size={28} />
              </span>
              <div>
                <h1>Workers</h1>
                <p>Worker instances, model channels, task status, and health checks</p>
              </div>
            </div>
            <div className="workers-console-actions">
              <label className="workers-search">
                <Search size={16} />
                <input
                  value={searchTerm}
                  onChange={(event) => setSearchTerm(event.target.value)}
                  placeholder="Search workers, models, tasks, tags..."
                />
              </label>
              <button
                className="primary-button compact"
                type="button"
                disabled={!config}
                onClick={() => setEditor(defaultWorkerDraft(config?.workers || []))}
              >
                <Plus size={18} />
                Add worker
              </button>
              <button className="ghost-button compact" type="button" disabled={!filteredWorkers.length || batchTesting} onClick={testVisibleWorkers}>
                <Activity size={16} />
                {batchTesting ? "Testing" : "Test all"}
              </button>
              <button className="ghost-button compact" type="button" onClick={() => load({ background: true })} disabled={refreshing}>
                <RefreshCw className={refreshing ? "spin" : ""} size={16} />
                Refresh
              </button>
            </div>
          </div>
        {loading ? (
          <EmptyState icon={Loader2} title="Loading workers" />
        ) : visibleWorkers.length === 0 ? (
          <EmptyState
            icon={Bot}
            title="No workers"
            subtitle="After you add a worker, the dispatcher assigns tasks by priority and concurrency."
            action={
              <button
                className="primary-button compact"
                type="button"
                disabled={!config}
                onClick={() => setEditor(defaultWorkerDraft(config?.workers || []))}
              >
                <Plus size={18} />
                Add worker
              </button>
            }
          />
        ) : (
          <>
            <div className="workers-overview-grid">
              <WorkerOverviewCard tone="success" label="Online" value={workerCounts.online} subtitle="Ready for tasks" />
              <WorkerOverviewCard tone="muted" label="Offline" value={workerCounts.offline} subtitle="Waiting to recover" />
              <WorkerOverviewCard tone="info" label="Running tasks" value={workerCounts.running} subtitle="Running now" />
              <WorkerOverviewCard tone="violet" label="Tasks completed" value={workerCounts.tasks} subtitle="Recorded as finished" />
            </div>
            {observability && (
              <div className="workers-observability-grid">
                <section className="workers-observability-card">
                  <header>
                    <h3>Dispatch capacity</h3>
                    <span>Live limits</span>
                  </header>
                  <div className="workers-observability-stats">
                    <MiniStat label="Max concurrency" value={observability.summary?.max_workers || 0} />
                    <MiniStat label="Running tasks" value={observability.summary?.running_tasks || 0} />
                    <MiniStat label="Running projects" value={observability.summary?.running_projects || 0} />
                    <MiniStat label="Per-project limit" value={observability.summary?.max_project_workers || 0} />
                  </div>
                </section>
                <section className="workers-observability-card">
                  <header>
                    <h3>Recent results</h3>
                    <span>Task history</span>
                  </header>
                  <div className="workers-outcome-grid">
                    <MiniStat label="Success" value={observability.outcomes?.success || 0} />
                    <MiniStat label="Failed" value={observability.outcomes?.failed || 0} />
                    <MiniStat label="Rejected" value={observability.outcomes?.rejected || 0} />
                    <MiniStat label="Release" value={observability.outcomes?.released || 0} />
                  </div>
                </section>
                <section className="workers-observability-card">
                  <header>
                    <h3>Task types</h3>
                    <span>Last 40</span>
                  </header>
                  {(observability.task_mix || []).length === 0 ? (
                    <p className="analysis-empty">No task mix yet</p>
                  ) : (
                    <div className="workers-task-mix">
                      {observability.task_mix.map((item) => (
                        <div key={item.task_type} className="workers-task-mix-item">
                          <span>{item.task_type}</span>
                          <strong>{item.count}</strong>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
                <section className="workers-observability-card">
                  <header>
                    <h3>Dispatch notes</h3>
                    <span>{observability.rejections?.length ? `${observability.rejections.length} backoffs` : "Running tasks"}</span>
                  </header>
                  {(observability.rejections || []).length > 0 ? (
                    <div className="workers-observability-list">
                      {observability.rejections.map((item, index) => (
                        <article key={`${item.worker_name}-${item.project_id}-${index}`}>
                          <strong>{item.worker_name}</strong>
                          <span>{item.project_name} · {item.task_type}</span>
                          <small>{item.seconds_remaining ? `${Math.round(item.seconds_remaining)} s until you can retry` : "Waiting to recover"}</small>
                        </article>
                      ))}
                    </div>
                  ) : (observability.running_tasks || []).length > 0 ? (
                    <div className="workers-observability-list">
                      {observability.running_tasks.map((item, index) => (
                        <article key={`${item.worker_name}-${item.project_id}-${index}`}>
                          <strong>{item.worker_name}</strong>
                          <span title={item.current_task}>{clampText(item.current_task, 52)}</span>
                          <small>{item.project_name} · {item.task_type}</small>
                        </article>
                      ))}
                    </div>
                  ) : (observability.recent_history || []).length > 0 ? (
                    <div className="workers-observability-list">
                      {observability.recent_history.slice(0, 4).map((item, index) => (
                        <article key={`${item.worker_name}-${item.started_at}-${index}`}>
                          <strong>{item.worker_name}</strong>
                          <span>{item.project_name} · {item.task_type}</span>
                          <small>{item.outcome} · {formatTime(item.started_at)}</small>
                        </article>
                      ))}
                    </div>
                  ) : (
                    <p className="analysis-empty">No running tasks or backoff records</p>
                  )}
                </section>
              </div>
            )}
            <div className="workers-filter-bar">
              <div className="workers-filter-tabs" role="tablist" aria-label="Filter workers by status">
                {statusTabs.map((tab) => (
                  <button
                    key={tab.key}
                    type="button"
                    role="tab"
                    aria-selected={statusFilter === tab.key}
                    className={cn("workers-filter-tab", statusFilter === tab.key && "active", tab.tone)}
                    onClick={() => setStatusFilter(tab.key)}
                  >
                    <span>{tab.label}</span>
                    <strong>{tab.count}</strong>
                  </button>
                ))}
              </div>
              <div className="workers-filter-controls">
                <label className="workers-auto-refresh">
                  <span className={cn("workers-auto-indicator", autoRefresh && "on")} />
                  Auto-refresh
                  <button
                    className={cn("switch compact-switch", autoRefresh && "on")}
                    type="button"
                    onClick={() => setAutoRefresh((current) => !current)}
                    aria-label={autoRefresh ? "Turn auto-refresh off" : "Turn auto-refresh on"}
                  >
                    <span />
                  </button>
                </label>
                <span className="workers-last-updated">
                  {lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString("en-US")}` : "Not updated yet"}
                </span>
                <div className="workers-view-toggle" role="tablist" aria-label="Worker layout">
                  <button
                    type="button"
                    role="tab"
                    aria-selected={viewMode === "grid"}
                    className={cn(viewMode === "grid" && "active")}
                    onClick={() => setViewMode("grid")}
                  >
                    <LayoutGrid size={16} />
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={viewMode === "list"}
                    className={cn(viewMode === "list" && "active")}
                    onClick={() => setViewMode("list")}
                  >
                    <List size={16} />
                  </button>
                </div>
              </div>
            </div>
            {filteredWorkers.length === 0 ? (
              <EmptyState icon={Search} title="No matching workers" subtitle="Change the query or status filter and try again." />
            ) : (
              <div className={cn("workers-node-grid", viewMode === "list" && "list")}>
                {filteredWorkers.map((card) => {
                  const worker = card.worker;
                  const status = card.live;
                  const isExpanded = Boolean(expanded[worker.name]);
                  const actionLabel = !card.isManaged ? "Adopt" : worker.enabled === false ? "Enable" : "Close";
                  return (
                    <article className="worker-node-card" key={worker.name}>
                      <div className="worker-node-card-head">
                        <div className="worker-node-title">
                          <span className={cn("worker-node-dot", card.statusMeta.tone)} />
                          <div>
                            <div className="worker-node-title-row">
                              <h3>{worker.name}</h3>
                              {!card.isManaged && <span className="worker-node-discovered">Unmanaged</span>}
                            </div>
                            <p>{card.worker.type} · {card.modelLabel}</p>
                          </div>
                        </div>
                        <Badge tone={card.statusMeta.tone}>{card.statusMeta.label}</Badge>
                      </div>
                      {status.current_task && <div className="worker-node-task">{clampText(status.current_task, 132)}</div>}
                      <div className="worker-node-meta">
                        <div>
                          <span>Provider</span>
                          <strong>{worker.type}</strong>
                        </div>
                        <div>
                          <span>Model</span>
                          <strong>{card.modelLabel}</strong>
                        </div>
                        <div>
                          <span>Runtime</span>
                          <strong>{card.runtimeLabel}</strong>
                        </div>
                        <div>
                          <span>Last heartbeat</span>
                          <strong>{card.heartbeatLabel}</strong>
                        </div>
                      </div>
                      <div className="worker-node-stats">
                        <div>
                          <span>Tasks</span>
                          <strong>{status.tasks_completed ?? 0}</strong>
                        </div>
                        <div>
                          <span>Avg duration</span>
                          <strong>{status.avg_duration_seconds ? `${status.avg_duration_seconds}s` : "-"}</strong>
                        </div>
                        <div>
                          <span>Max concurrency</span>
                          <strong>{worker.max_running ?? 1}</strong>
                        </div>
                        <div>
                          <span>Priority</span>
                          <strong>{worker.priority ?? 0}</strong>
                        </div>
                      </div>
                      <div className="worker-node-tags">
                        {card.taskTypes.map((taskType) => (
                          <span key={taskType}>{taskType}</span>
                        ))}
                      </div>
                      <div className="worker-node-actions">
                        <button
                          className={cn("worker-node-toggle", worker.enabled === false || !card.isManaged ? "start" : "stop")}
                          type="button"
                          disabled={!config}
                          onClick={() => (card.isManaged ? setEnabled(worker, worker.enabled === false) : openEditorForWorker(worker))}
                        >
                          {worker.enabled === false || !card.isManaged ? <Play size={16} /> : <Pause size={16} />}
                          {actionLabel}
                        </button>
                        <button className="ghost-button compact" type="button" disabled={!config} onClick={() => testWorker(worker)}>
                          <Activity size={16} />
                          Test
                        </button>
                        <button className="ghost-button compact" type="button" disabled={!config} onClick={() => openEditorForWorker(worker)}>
                          <Settings size={16} />
                          Edit
                        </button>
                        <button className="ghost-button compact" type="button" onClick={() => toggleHistory(worker.name)}>
                          <History size={16} />
                          {isExpanded ? "Hide history" : "History"}
                        </button>
                        <button className="worker-node-menu" type="button" onClick={() => openEditorForWorker(worker)} aria-label="More actions">
                          <MoreVertical size={16} />
                        </button>
                      </div>
                      {isExpanded && (
                        <div className="history-list worker-node-history">
                          {(history[worker.name] || []).length === 0 ? (
                            <p>This worker has no task history yet.</p>
                          ) : (
                            history[worker.name].map((row, index) => (
                              <article key={`${row.started_at}-${index}`}>
                                <strong>{row.task_type}</strong>
                                <span>{row.description}</span>
                                <small>
                                  {row.project_name} · {formatTime(row.started_at)} · {row.outcome}
                                </small>
                              </article>
                            ))
                          )}
                        </div>
                      )}
                    </article>
                  );
                })}
              </div>
            )}
          </>
        )}
        </section>
      </section>
      {editor && (
        <WorkerEditor
          worker={editor}
          onClose={() => setEditor(null)}
          onSave={saveEditor}
          onDelete={config?.workers?.some((item) => item.name === editor.name) ? () => deleteWorker(editor) : null}
        />
      )}
    </>
  );
}

function WorkerOverviewCard({ tone, label, value, subtitle }) {
  return (
    <article className={cn("worker-overview-card", tone)}>
      <span className="worker-overview-ring" />
      <div>
        <strong>{label}</strong>
        <b>{value}</b>
        <small>{subtitle}</small>
      </div>
    </article>
  );
}

function workerModelLabel(worker) {
  const env = worker.env || {};
  return env.ANTHROPIC_MODEL || env.CODEX_MODEL || env.PI_MODEL || "No model configured";
}

function workerRuntimeLabel(worker) {
  if (worker.type === "pi") return "local";
  if (worker.type === "mock") return "mock";
  return "cloud";
}

function workerDraftFromStatus(worker, existingWorkers) {
  return {
    ...defaultWorkerDraft(existingWorkers),
    ...worker,
    enabled: worker.enabled !== false,
    task_types: worker.task_types?.length ? worker.task_types : [...TASK_TYPES],
    max_running: worker.max_running ?? 1,
    priority: worker.priority ?? 0,
    env: { ...(worker.env || {}) },
    secret_env_keys: worker.secret_env_keys || [],
  };
}

function defaultWorkerDraft(existingWorkers) {
  let index = 1;
  const names = new Set(existingWorkers.map((worker) => worker.name));
  while (names.has(`worker_local_${index}`)) index += 1;
  return {
    name: `worker_local_${index}`,
    type: "pi",
    enabled: true,
    task_types: [...TASK_TYPES],
    max_running: 1,
    priority: 0,
    env: {
      PI_MODEL: "",
      PI_BASE_URL: "",
      PI_API_KEY: "",
      PI_PROVIDER_API: "openai-completions",
    },
    secret_env_keys: ["PI_API_KEY"],
  };
}

function normalizeWorkerForSave(worker) {
  return {
    name: worker.name.trim(),
    type: worker.type,
    enabled: worker.enabled !== false,
    task_types: worker.task_types?.length ? worker.task_types : [...TASK_TYPES],
    max_running: Number(worker.max_running) || 1,
    priority: Number(worker.priority) || 0,
    env: Object.fromEntries(Object.entries(worker.env || {}).map(([key, value]) => [key, String(value ?? "")])),
    secret_env_keys: worker.secret_env_keys || [],
  };
}

const WORKER_PRESETS = [
  {
    id: "pi-openai-chat",
    label: "Pi · OpenAI Chat",
    type: "pi",
    env: {
      PI_MODEL: "deepseekv4",
      PI_BASE_URL: "http://10.2.8.77:3000/v1",
      PI_API_KEY: "",
      PI_PROVIDER_API: "openai-completions",
    },
  },
  {
    id: "claude-code",
    label: "Claude Code · Anthropic",
    type: "claudecode",
    env: {
      ANTHROPIC_MODEL: "claude-3-5-sonnet-latest",
      ANTHROPIC_BASE_URL: "https://api.anthropic.com",
      ANTHROPIC_AUTH_TOKEN: "",
    },
  },
  {
    id: "codex",
    label: "Codex · Responses API",
    type: "codex",
    env: {
      CODEX_MODEL: "gpt-5",
      CODEX_BASE_URL: "https://api.openai.com/v1",
      OPENAI_API_KEY: "",
    },
  },
  {
    id: "mock",
    label: "Mock",
    type: "mock",
    env: {},
  },
];

function WorkerEditor({ worker, onClose, onSave, onDelete }) {
  const [draft, setDraft] = useState(() => JSON.parse(JSON.stringify(worker)));
  const [saving, setSaving] = useState(false);
  const envKeys = useMemo(() => workerEnvKeys(draft.type), [draft.type]);

  const applyPreset = (presetId) => {
    const preset = WORKER_PRESETS.find((item) => item.id === presetId);
    if (!preset) return;
    setDraft((prev) => ({
      ...prev,
      type: preset.type,
      env: { ...preset.env },
      secret_env_keys: Object.keys(preset.env).filter((key) => /KEY|TOKEN|SECRET/i.test(key)),
    }));
  };

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSave(draft);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="Worker configuration" subtitle="The dispatcher validates and hot-reloads this. The previous configuration stays if validation fails." onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        <div className="two-col tight">
          <label>
            <span>Preset</span>
            <select defaultValue="" onChange={(event) => applyPreset(event.target.value)}>
              <option value="" disabled>
                Choose a model preset
              </option>
              {WORKER_PRESETS.map((preset) => (
                <option key={preset.id} value={preset.id}>
                  {preset.label}
                </option>
              ))}
            </select>
          </label>
          <label className="switch-line">
            <span>Enabled</span>
            <button
              className={cn("switch", draft.enabled !== false && "on")}
              type="button"
              onClick={() => setDraft({ ...draft, enabled: draft.enabled === false })}
            >
              <span />
            </button>
          </label>
        </div>
        <div className="two-col tight">
          <label>
            <span>Name</span>
            <input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} required />
          </label>
          <label>
            <span>Type</span>
            <select
              value={draft.type}
              onChange={(event) => {
                const type = event.target.value;
                setDraft({ ...draft, type, env: defaultEnvForType(type), secret_env_keys: workerEnvKeys(type).filter((key) => /KEY|TOKEN|SECRET/i.test(key)) });
              }}
            >
              <option value="pi">pi</option>
              <option value="claudecode">claudecode</option>
              <option value="codex">codex</option>
              <option value="mock">mock</option>
            </select>
          </label>
        </div>
        <div className="three-col">
          <label>
            <span>Max concurrency</span>
            <input
              type="number"
              min="1"
              value={draft.max_running}
              onChange={(event) => setDraft({ ...draft, max_running: event.target.value })}
            />
          </label>
          <label>
            <span>Priority</span>
            <input
              type="number"
              min="0"
              value={draft.priority}
              onChange={(event) => setDraft({ ...draft, priority: event.target.value })}
            />
          </label>
          <label>
            <span>Task types</span>
            <div className="checkbox-row">
              {TASK_TYPES.map((type) => (
                <label key={type}>
                  <input
                    type="checkbox"
                    checked={draft.task_types?.includes(type)}
                    onChange={(event) => {
                      const next = event.target.checked
                        ? [...(draft.task_types || []), type]
                        : (draft.task_types || []).filter((item) => item !== type);
                      setDraft({ ...draft, task_types: next });
                    }}
                  />
                  {type}
                </label>
              ))}
            </div>
          </label>
        </div>
        <div className="env-grid">
          {envKeys.map((key) => {
            const secret = /KEY|TOKEN|SECRET/i.test(key);
            return (
              <label key={key}>
                <span>{key}</span>
                <input
                  type={secret ? "password" : "text"}
                  value={draft.env?.[key] ?? ""}
                  placeholder={secret ? SECRET_MASK : ""}
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      env: { ...(draft.env || {}), [key]: event.target.value },
                      secret_env_keys: secret
                        ? Array.from(new Set([...(draft.secret_env_keys || []), key]))
                        : draft.secret_env_keys || [],
                    })
                  }
                  required={draft.type !== "mock"}
                />
              </label>
            );
          })}
        </div>
        <div className="modal-footer split">
          <div>
            {onDelete && (
              <button className="ghost-button danger" type="button" onClick={onDelete}>
                <Trash2 size={16} />
                Delete worker
              </button>
            )}
          </div>
          <div className="button-row">
            <button className="ghost-button" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="primary-button compact" type="submit" disabled={saving}>
              {saving ? <Loader2 className="spin" size={18} /> : <Save size={18} />}
              Save configuration
            </button>
          </div>
        </div>
      </form>
    </Modal>
  );
}

function workerEnvKeys(type) {
  if (type === "claudecode") return ["ANTHROPIC_MODEL", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"];
  if (type === "codex") return ["CODEX_MODEL", "CODEX_BASE_URL", "OPENAI_API_KEY"];
  if (type === "pi") return ["PI_MODEL", "PI_BASE_URL", "PI_API_KEY", "PI_PROVIDER_API", "PI_MODEL_CONTEXT_WINDOW"];
  return [];
}

function defaultEnvForType(type) {
  const preset = WORKER_PRESETS.find((item) => item.type === type);
  return { ...(preset?.env || {}) };
}

function TemplatesPage({ runAction, setToast, confirmAction }) {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newTemplate, setNewTemplate] = useState(false);
  const [projectTemplate, setProjectTemplate] = useState(null);
  const [category, setCategory] = useState("all");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setTemplates(await apiRequest("/api/templates"));
    } catch (error) {
      setToast({ type: "danger", message: error.message || "Could not load templates" });
    } finally {
      setLoading(false);
    }
  }, [setToast]);

  useEffect(() => {
    load();
  }, [load]);

  const deleteTemplate = async (template) => {
    const ok = await confirmAction({
      title: "Delete template",
      message: `Delete template "${template.title}"?`,
      tone: "danger",
      confirmLabel: "Delete",
    });
    if (!ok) return;
    await runAction("Template deleted", () => apiRequest(`/api/templates/${template.id}`, { method: "DELETE" }));
    await load();
  };

  const categoryCounts = useMemo(() => {
    const counts = {};
    for (const template of templates) {
      const key = templateCategory(template);
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  }, [templates]);

  const visibleTemplates = useMemo(
    () => (category === "all" ? templates : templates.filter((template) => templateCategory(template) === category)),
    [templates, category],
  );

  return (
    <>
      <PageHeader
        icon={FileText}
        title="Templates"
        subtitle="Save a goal, origin, and hints as a reusable project template"
        actions={
          <>
            <button className="primary-outline" type="button" onClick={() => setNewTemplate(true)}>
              <Plus size={18} />
              New template
            </button>
            <button className="ghost-button" type="button" onClick={load}>
              <RefreshCw size={18} />
              Refresh
            </button>
          </>
        }
      />
      <section className="content-wrap">
        <div className="template-tabs" role="tablist" aria-label="Template categories">
          {TEMPLATE_CATEGORIES.map((tab) => {
            const count = tab.key === "all" ? templates.length : categoryCounts[tab.key] || 0;
            return (
              <button
                key={tab.key}
                type="button"
                role="tab"
                aria-selected={category === tab.key}
                className={cn("template-tab", category === tab.key && "active")}
                onClick={() => setCategory(tab.key)}
              >
                {tab.label}
                <span className="template-tab-count">{count}</span>
              </button>
            );
          })}
        </div>
        {loading ? (
          <EmptyState icon={Loader2} title="Loading templates" />
        ) : visibleTemplates.length === 0 ? (
          <EmptyState
            icon={FileText}
            title="No templates in this category"
            subtitle="Switch category, or create a custom template."
            action={
              <button className="primary-button compact" type="button" onClick={() => setNewTemplate(true)}>
                <Plus size={16} />
                New template
              </button>
            }
          />
        ) : (
          <div className="template-grid">
            {visibleTemplates.map((template) => {
              const catKey = templateCategory(template);
              const catMeta = TEMPLATE_CATEGORY_META[catKey] || TEMPLATE_CATEGORY_META.custom;
              const hintCount = template.hints?.length || 0;
              return (
                <article className="template-card" key={template.id}>
                  <header>
                    <span className="template-icon">
                      <FileText size={20} />
                    </span>
                    <div className="template-heading">
                      <h3>{template.title}</h3>
                      <div className="template-badges">
                        <Badge tone={catMeta.tone}>{catMeta.label}</Badge>
                        <Badge tone={template.is_builtin ? "info" : "success"}>
                          {template.is_builtin ? "Built-in" : "Custom"}
                        </Badge>
                      </div>
                    </div>
                  </header>
                  <p className="template-description">{template.goal}</p>
                  <div className="template-section">
                    <span>Origin</span>
                    <p>{template.origin}</p>
                  </div>
                  <div className="template-foot">
                    <span className="template-meta">
                      <Sparkles size={14} />
                      {hintCount ? `${hintCount} hints` : "No initial hints"}
                    </span>
                    <div className="card-actions">
                      <button className="primary-outline compact" type="button" onClick={() => setProjectTemplate(template)}>
                        <Plus size={16} />
                        Use template
                      </button>
                      {!template.is_builtin && (
                        <button className="ghost-button compact danger" type="button" onClick={() => deleteTemplate(template)}>
                          <Trash2 size={16} />
                          Delete
                        </button>
                      )}
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>
      {newTemplate && (
        <TemplateEditor
          onClose={() => setNewTemplate(false)}
          onSave={async (payload) => {
            await runAction("Template created", () => apiRequest("/api/templates", { method: "POST", body: payload }));
            setNewTemplate(false);
            await load();
          }}
        />
      )}
      {projectTemplate && (
        <NewProjectModal
          initial={projectTemplate}
          runAction={runAction}
          onClose={() => setProjectTemplate(null)}
          onCreated={(projectId) => {
            setProjectTemplate(null);
            go(`#/projects/${projectId}`);
          }}
        />
      )}
    </>
  );
}

const TEMPLATE_CATEGORIES = [
  { key: "all", label: "All templates" },
  { key: "web", label: "Web" },
  { key: "internal", label: "Internal" },
  { key: "recon", label: "Recon" },
  { key: "ctf", label: "CTF" },
  { key: "custom", label: "Custom" },
];

const TEMPLATE_CATEGORY_META = {
  web: { label: "Web", tone: "info" },
  internal: { label: "Internal", tone: "high" },
  recon: { label: "Recon", tone: "medium" },
  ctf: { label: "CTF", tone: "critical" },
  custom: { label: "Custom", tone: "success" },
};

// Presentational-only category grouping derived from the template's own text.
// Templates have no category field from the API, so this never fabricates data;
// it only buckets a template for the filter tabs and badge.
function templateCategory(template) {
  if (!template.is_builtin) return "custom";
  const text = `${template.title || ""} ${template.origin || ""} ${template.goal || ""}`;
  if (/CTF/i.test(text)) return "ctf";
  if (/web/i.test(text)) return "web";
  if (/internal|intranet/i.test(text)) return "internal";
  if (/external|recon|reconnaissance/i.test(text)) return "recon";
  return "web";
}

function TemplateEditor({ onClose, onSave }) {
  const [form, setForm] = useState({ title: "", origin: "", goal: "", hints: "" });
  const [saving, setSaving] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSave({
        title: form.title,
        origin: form.origin,
        goal: form.goal,
        hints: parseHintLines(form.hints, HUMAN_WORKER),
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="New template" onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        <label>
          <span>Template name</span>
          <input value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} required />
        </label>
        <div className="two-col">
          <label>
            <span>Origin</span>
            <textarea rows={6} value={form.origin} onChange={(event) => setForm({ ...form, origin: event.target.value })} required />
          </label>
          <label>
            <span>Goal</span>
            <textarea rows={6} value={form.goal} onChange={(event) => setForm({ ...form, goal: event.target.value })} required />
          </label>
        </div>
        <label>
          <span>Hint</span>
          <textarea rows={4} value={form.hints} onChange={(event) => setForm({ ...form, hints: event.target.value })} />
        </label>
        <div className="modal-footer">
          <button className="ghost-button" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary-button compact" type="submit" disabled={saving}>
            {saving ? <Loader2 className="spin" size={18} /> : <Save size={18} />}
            Save template
          </button>
        </div>
      </form>
    </Modal>
  );
}

function PasswordModal({ onClose, runAction }) {
  const [form, setForm] = useState({ current_password: "", new_password: "", confirm_password: "" });
  const [show, setShow] = useState({ current: false, next: false });
  const [saving, setSaving] = useState(false);

  const rules = [
    { key: "len", label: "At least 8 characters", ok: form.new_password.length >= 8 },
    { key: "case", label: "Upper and lower case", ok: /[a-z]/.test(form.new_password) && /[A-Z]/.test(form.new_password) },
    { key: "num", label: "A number", ok: /\d/.test(form.new_password) },
    { key: "sym", label: "A symbol", ok: /[^A-Za-z0-9]/.test(form.new_password) },
  ];
  const allOk = rules.every((rule) => rule.ok);
  const matched = form.confirm_password.length > 0 && form.new_password === form.confirm_password;
  const canSubmit = !!form.current_password && allOk && matched && !saving;

  const submit = async (event) => {
    event.preventDefault();
    if (!canSubmit) return;
    setSaving(true);
    try {
      await runAction("Password changed", () =>
        apiRequest("/api/auth/password", {
          method: "PUT",
          body: {
            current_password: form.current_password,
            new_password: form.new_password,
          },
        }),
      );
      onClose();
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="Change password" subtitle="Set a stronger password for this account" onClose={onClose}>
      <form className="stack-form modal-body password-form" onSubmit={submit}>
        <label>
          <span>Current password</span>
          <div className="input-affix">
            <KeyRound size={16} className="affix-icon" />
            <input
              type={show.current ? "text" : "password"}
              value={form.current_password}
              onChange={(event) => setForm({ ...form, current_password: event.target.value })}
              placeholder="Current password"
              autoComplete="current-password"
              required
            />
            <button type="button" className="affix-toggle" onClick={() => setShow({ ...show, current: !show.current })} aria-label="Show or hide password">
              {show.current ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </label>
        <label>
          <span>New password</span>
          <div className="input-affix">
            <Lock size={16} className="affix-icon" />
            <input
              type={show.next ? "text" : "password"}
              value={form.new_password}
              onChange={(event) => setForm({ ...form, new_password: event.target.value })}
              placeholder="New password"
              autoComplete="new-password"
              required
            />
            <button type="button" className="affix-toggle" onClick={() => setShow({ ...show, next: !show.next })} aria-label="Show or hide password">
              {show.next ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
        </label>
        <label>
          <span>Confirm new password</span>
          <div className="input-affix">
            <Lock size={16} className="affix-icon" />
            <input
              type={show.next ? "text" : "password"}
              value={form.confirm_password}
              onChange={(event) => setForm({ ...form, confirm_password: event.target.value })}
              placeholder="Re-enter the new password"
              autoComplete="new-password"
              required
            />
          </div>
          {form.confirm_password.length > 0 && !matched && <small className="field-hint danger">The passwords do not match</small>}
        </label>
        <ul className="password-rules">
          {rules.map((rule) => (
            <li key={rule.key} className={cn(rule.ok && "ok")}>
              {rule.ok ? <CheckCircle2 size={14} /> : <Circle size={14} />}
              {rule.label}
            </li>
          ))}
        </ul>
        <div className="modal-footer">
          <button className="ghost-button" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="primary-button compact" type="submit" disabled={!canSubmit}>
            {saving ? <Loader2 className="spin" size={18} /> : <Save size={18} />}
            Save
          </button>
        </div>
      </form>
    </Modal>
  );
}

function SettingsModal({ onClose, runAction }) {
  const [settings, setSettings] = useState(null);
  const [health, setHealth] = useState(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [cleaning, setCleaning] = useState(false);

  const settingsFallback = useMemo(
    () => ({
      step_timeout: 15,
      decide_timeout: 15,
      worker_unhealthy_retry_after_seconds: 5,
      worker_rejected_retry_after_seconds: 5,
      max_failed_login_attempts: 5,
      rate_limit_window_minutes: 15,
      session_duration_hours: 24,
      log_retention_days: 30,
      export_retention_days: 30,
      notification_retention_days: 14,
      project_idle_alert_hours: 12,
    }),
    [],
  );

  useEffect(() => {
    apiRequest("/settings").then(setSettings).catch(() => setSettings(settingsFallback));
  }, [settingsFallback]);

  const loadHealth = useCallback(async () => {
    setHealthLoading(true);
    try {
      setHealth(await apiRequest("/settings/health"));
    } catch {
      setHealth(null);
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHealth();
  }, [loadHealth]);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await runAction("Settings saved", () => apiRequest("/settings", { method: "PUT", body: settings }));
      await loadHealth();
    } finally {
      setSaving(false);
    }
  };

  const runCleanup = async () => {
    setCleaning(true);
    try {
      await runAction("Cleanup finished", () => apiRequest("/settings/cleanup", { method: "POST" }));
      await loadHealth();
    } finally {
      setCleaning(false);
    }
  };

  const setNumber = (key, value) => {
    setSettings((current) => ({ ...current, [key]: Number(value) }));
  };

  const healthTone = (status) => (status === "error" ? "danger" : status === "warning" ? "high" : "success");
  const healthLabel = (status) => (status === "error" ? "Error" : status === "warning" ? "Warning" : "Healthy");

  return (
    <Modal
      title="Settings"
      subtitle="Dispatch, security policy, retention, and health checks."
      onClose={onClose}
      wide
    >
      {!settings ? (
        <EmptyState icon={Loader2} title="Loading settings" />
      ) : (
        <form className="stack-form modal-body settings-shell" onSubmit={submit}>
          <section className="settings-section">
            <div className="settings-section-head">
              <div>
                <h3>Runtime</h3>
                <p>Changes dispatch timing and cooldown only. Projects and workers stay as they are.</p>
              </div>
              <Badge tone="info">Dispatch</Badge>
            </div>
            <div className="two-col">
              <label>
                <span>Step timeout (seconds)</span>
                <input type="number" min="5" value={settings.step_timeout} onChange={(event) => setNumber("step_timeout", event.target.value)} />
                <small className="field-hint">How long a step may wait before it is reclaimed.</small>
              </label>
              <label>
                <span>Decide timeout (seconds)</span>
                <input type="number" min="5" value={settings.decide_timeout} onChange={(event) => setNumber("decide_timeout", event.target.value)} />
                <small className="field-hint">How long Decide may run before it times out.</small>
              </label>
            </div>
            <div className="two-col">
              <label>
                <span>Unhealthy worker cooldown (seconds)</span>
                <input
                  type="number"
                  min="1"
                  value={settings.worker_unhealthy_retry_after_seconds}
                  onChange={(event) => setNumber("worker_unhealthy_retry_after_seconds", event.target.value)}
                />
                <small className="field-hint">How long a failed health check keeps a worker out of dispatch.</small>
              </label>
              <label>
                <span>Rejected-task retry interval (seconds)</span>
                <input
                  type="number"
                  min="1"
                  value={settings.worker_rejected_retry_after_seconds}
                  onChange={(event) => setNumber("worker_rejected_retry_after_seconds", event.target.value)}
                />
                <small className="field-hint">How long to wait before offering a task to a worker that just rejected one.</small>
              </label>
            </div>
          </section>

          <section className="settings-section">
            <div className="settings-section-head">
              <div>
                <h3>Authentication and sessions</h3>
                <p>Lockout, session lifetime, and the browser auth window.</p>
              </div>
              <Badge tone="success">Security</Badge>
            </div>
            <div className="three-col">
              <label>
                <span>Lockout threshold</span>
                <input
                  type="number"
                  min="1"
                  value={settings.max_failed_login_attempts}
                  onChange={(event) => setNumber("max_failed_login_attempts", event.target.value)}
                />
                <small className="field-hint">Maximum failures for one account inside the window.</small>
              </label>
              <label>
                <span>Rate-limit window (minutes)</span>
                <input
                  type="number"
                  min="1"
                  value={settings.rate_limit_window_minutes}
                  onChange={(event) => setNumber("rate_limit_window_minutes", event.target.value)}
                />
                <small className="field-hint">Further sign-in attempts are blocked for the rest of the window.</small>
              </label>
              <label>
                <span>Session length (hours)</span>
                <input
                  type="number"
                  min="1"
                  value={settings.session_duration_hours}
                  onChange={(event) => setNumber("session_duration_hours", event.target.value)}
                />
                <small className="field-hint">Sliding expiry for a valid session.</small>
              </label>
            </div>
          </section>

          <section className="settings-section">
            <div className="settings-section-head">
              <div>
                <h3>Retention and cleanup</h3>
                <p>Clears history, export records, and read notifications. Facts, goals, steps, and findings stay.</p>
              </div>
              <Badge tone="medium">Maintenance</Badge>
            </div>
            <div className="three-col">
              <label>
                <span>Log retention (days)</span>
                <input type="number" min="1" value={settings.log_retention_days} onChange={(event) => setNumber("log_retention_days", event.target.value)} />
                <small className="field-hint">Audit log, worker history, and sign-in attempts.</small>
              </label>
              <label>
                <span>Export retention (days)</span>
                <input
                  type="number"
                  min="1"
                  value={settings.export_retention_days}
                  onChange={(event) => setNumber("export_retention_days", event.target.value)}
                />
                <small className="field-hint">Clears export history only. Export itself still works.</small>
              </label>
              <label>
                <span>Notification retention (days)</span>
                <input
                  type="number"
                  min="1"
                  value={settings.notification_retention_days}
                  onChange={(event) => setNumber("notification_retention_days", event.target.value)}
                />
                <small className="field-hint">Clears read notifications. Unread ones stay.</small>
              </label>
            </div>
            <div className="two-col">
              <label>
                <span>Idle project alert (hours)</span>
                <input
                  type="number"
                  min="1"
                  value={settings.project_idle_alert_hours}
                  onChange={(event) => setNumber("project_idle_alert_hours", event.target.value)}
                />
                <small className="field-hint">Alerts when an active project has no new fact, hint, step, or Decide heartbeat.</small>
              </label>
              <div className="settings-action-card">
                <div>
                  <strong>Clean history now</strong>
                  <p>Deletes expired logs, read notifications, export records, and dead sessions using the current policy.</p>
                </div>
                <button className="ghost-button compact" type="button" onClick={runCleanup} disabled={cleaning}>
                  {cleaning ? <Loader2 className="spin" size={16} /> : <Trash2 size={16} />}
                  Clean now
                </button>
              </div>
            </div>
          </section>

          <section className="settings-section">
            <div className="settings-section-head">
              <div>
                <h3>System health</h3>
                <p>API, database, dispatcher, and worker status.</p>
              </div>
              <button className="ghost-button compact" type="button" onClick={loadHealth} disabled={healthLoading}>
                {healthLoading ? <Loader2 className="spin" size={16} /> : <RefreshCw size={16} />}
                Refresh status
              </button>
            </div>

            {health ? (
              <>
                <div className="settings-health-grid">
                  <article className={cn("settings-health-card", health.summary.status)}>
                    <span>System status</span>
                    <strong>{healthLabel(health.summary.status)}</strong>
                    <small>Updated {formatTime(health.generated_at)}</small>
                  </article>
                  <article className="settings-health-card">
                    <span>Active projects</span>
                    <strong>{health.summary.active_projects}</strong>
                    <small>Projects {health.stats.projects}</small>
                  </article>
                  <article className="settings-health-card">
                    <span>Online workers</span>
                    <strong>{health.summary.online_workers}</strong>
                    <small>Offline {health.summary.offline_workers}</small>
                  </article>
                  <article className="settings-health-card">
                    <span>Unread notifications</span>
                    <strong>{health.stats.notifications_unread}</strong>
                    <small>Audit log {health.stats.audit_entries}</small>
                  </article>
                </div>

                <div className="settings-check-list">
                  {health.checks.map((check) => (
                    <article key={check.key} className={cn("settings-check-item", check.status)}>
                      <div className="settings-check-head">
                        <strong>{check.label}</strong>
                        <Badge tone={healthTone(check.status)}>{healthLabel(check.status)}</Badge>
                      </div>
                      <p>{check.summary}</p>
                      {check.detail && <small>{check.detail}</small>}
                    </article>
                  ))}
                </div>

                <div className="settings-alert-block">
                  <div className="settings-alert-head">
                    <strong>Alerts</strong>
                    <span>{health.alerts.length}</span>
                  </div>
                  {health.alerts.length === 0 ? (
                    <div className="soft-box">No system alerts need attention.</div>
                  ) : (
                    <div className="settings-alert-list">
                      {health.alerts.map((alert, index) => (
                        <article key={`${alert.title}-${index}`} className={cn("settings-alert-item", alert.level)}>
                          <div className="settings-alert-title">
                            <AlertTriangle size={16} />
                            <strong>{alert.title}</strong>
                          </div>
                          {alert.detail && <p>{alert.detail}</p>}
                        </article>
                      ))}
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="soft-box">System health is unavailable. Refresh and try again.</div>
            )}
          </section>

          <div className="modal-footer">
            <button className="ghost-button" type="button" onClick={onClose}>
              Close
            </button>
            <button className="primary-button compact" type="submit" disabled={saving}>
              {saving ? <Loader2 className="spin" size={18} /> : <Save size={18} />}
              Save
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}

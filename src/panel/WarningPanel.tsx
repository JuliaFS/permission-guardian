import { useState, useEffect } from "react";
import type { RiskSignal } from "../engine/types";
import { QUIZ_QUESTIONS, BADGE_DEFINITIONS } from "../engine/learningEngine";
import "./panel.css";

const runtime =
  (globalThis as any).chrome?.runtime ?? (globalThis as any).browser?.runtime;
const storage =
  (globalThis as any).chrome?.storage?.local ??
  (globalThis as any).browser?.storage?.local;

type ExtensionSummaryItem = {
  id: string;
  name: string;
  enabled: boolean;
  hasActivity: boolean;
  riskScore: number;
  lastUsed?: number;
};

type SitePermissionItem = {
  origin: string;
  permissions: string[];
};

type DashboardData = {
  extensionSummary: ExtensionSummaryItem[];
  sitePermissions: SitePermissionItem[];
};

type ExtensionActivityItem = {
  type: "extension_injection" | "network_request" | "data_access" | (string & {});
  detail: string;
};

type Education = {
  title: string;
  why: string[];
  safer: string[];
};

const EDUCATION_BY_SIGNAL_ID: Record<string, Education> = {
  ext_host_all_urls: {
    title: "Runs on all websites (<all_urls>)",
    why: [
      "It can execute on every site you visit, including banking, email, and internal work tools.",
      "Even a small bug or a compromised update can impact all browsing, not just one site.",
    ],
    safer: [
      "Prefer extensions scoped to specific sites (least privilege).",
      "If an extension needs broad access, make sure it’s from a highly trusted publisher and actively maintained.",
    ],
  },
  ext_background_service_worker: {
    title: "Has background code (service worker)",
    why: [
      "Background code can run outside a specific page and react to browser events.",
      "That can be used for helpful automation, but also for tracking or data collection if misused.",
    ],
    safer: [
      "Review what permissions it has together with background capabilities.",
      "Be extra careful with broad host access + background together.",
    ],
  },
  ext_background_persistent: {
    title: "Persistent background page",
    why: [
      "A persistent background page stays alive longer, which increases always-on tracking potential.",
      "It increases the impact of compromise because code is effectively always running.",
    ],
    safer: [
      "Prefer MV3-style service workers when possible, and avoid persistent background unless necessary.",
      "If you don’t need the extension daily, disable it.",
    ],
  },
  ext_perm_tabs: {
    title: "Permission: tabs",
    why: [
      "Can access tab URLs/titles and sometimes more detailed tab metadata depending on context.",
      "This can reveal what you browse, including sensitive pages.",
    ],
    safer: ["Prefer extensions that work with activeTab only, or are scoped to specific sites."],
  },
  ext_perm_cookies: {
    title: "Permission: cookies",
    why: [
      "Cookies can include session identifiers; stealing them can allow account takeover (session hijacking).",
      "Cookie access also enables tracking across sites.",
    ],
    safer: ["Avoid cookie access unless the extension’s core purpose requires it (e.g., cookie managers)."],
  },
  ext_perm_webRequest: {
    title: "Permission: webRequest",
    why: [
      "Can observe (and in some cases modify) network traffic, which may expose what you do online.",
      "Can be abused to inject, redirect, or fingerprint your browsing.",
    ],
    safer: ["Only trust this permission for well-known blockers/security tools with clear purpose."],
  },
  ext_perm_history: {
    title: "Permission: history",
    why: [
      "Your history can expose health, finance, work, and personal interests.",
      "History access can be combined with profiling and tracking.",
    ],
    safer: ["Avoid granting this unless the extension is a history/search tool you explicitly want."],
  },
  ext_perm_activeTab: {
    title: "Permission: activeTab",
    why: [
      "This is safer than blanket host access, but still powerful on the tab you click the extension on.",
      "On a login or payment page, it could read page content or interact with forms.",
    ],
    safer: ["Use on trusted pages; prefer site-scoped permissions where possible."],
  },
  ext_perm_clipboardRead: {
    title: "Permission: clipboardRead",
    why: [
      "Clipboard often contains passwords, 2FA codes, crypto addresses, and private text.",
      "Attackers can read clipboard silently after certain user interactions.",
    ],
    safer: ["Avoid this permission unless you fully trust the extension and need clipboard features."],
  },
  ext_perm_clipboardWrite: {
    title: "Permission: clipboardWrite",
    why: [
      "Can replace what you copy (e.g., a payment address or a link) without obvious warning.",
      "This is a common tactic in crypto/payment malware.",
    ],
    safer: ["Double-check pasted content on sensitive actions (payments, logins, recovery codes)."],
  },
  ext_perm_scripting: {
    title: "Permission: scripting",
    why: [
      "Allows injecting code into pages, which can read what’s on the page and interact with the DOM.",
      "Combined with broad host access, it can affect many sites.",
    ],
    safer: ["Prefer extensions that inject only on specific sites and have minimal permissions."],
  },
  password_field: {
    title: "Password input detected",
    why: [
      "Phishing pages often look identical to real login pages but send your password to attackers.",
      "Even on legitimate sites, passwords can be stolen by malicious scripts, compromised extensions, or insecure connections.",
    ],
    safer: [
      "Double‑check the domain (not just the page design).",
      "Prefer password managers (they match on the real domain).",
      "If unsure, open the site by typing it yourself instead of clicking the link.",
    ],
  },
  url_at_symbol: {
    title: "URL contains “@”",
    why: [
      "In URLs, text before “@” can be used to mislead you about the real destination.",
      "Attackers use this to show a trustworthy-looking prefix while the real host is after “@”.",
    ],
    safer: [
      "Look at the actual domain after “@” (and before the first “/”).",
      "When in doubt, don’t log in—navigate to the site manually.",
    ],
  },
  url_length: {
    title: "Unusually long URL",
    why: [
      "Very long URLs can hide the real domain or include tracking/redirect parameters.",
      "Phishing links often add extra path/query text to look “official” or to bypass filters.",
    ],
    safer: [
      "Focus on the domain first; ignore the long path/query.",
      "If it’s a login or payment page, open the site from bookmarks or typing the address.",
    ],
  },
  ip_address: {
    title: "Uses an IP address instead of a domain",
    why: [
      "Legitimate services usually use domain names; raw IPs are more common for malicious or temporary hosting.",
      "Certificates and brand signals are harder to verify when a site is addressed by IP.",
    ],
    safer: [
      "Avoid entering credentials on IP-based URLs.",
      "If you expect a real service, search for its official domain and compare.",
    ],
  },
  website_http_connection: {
    title: "Connection is not secure (HTTP)",
    why: [
      "HTTP connections send data in plain text, making it vulnerable to eavesdropping and tampering.",
      "Sensitive information (passwords, credit card numbers) can be intercepted by attackers.",
    ],
    safer: [
      "Avoid entering any sensitive information on HTTP sites.",
      "Look for 'HTTPS' in the URL and a padlock icon in your browser's address bar.",
    ],
  },
  website_new_domain: {
    title: "This domain appears to be very new or recently registered",
    why: [
      "Many phishing and scam sites use newly registered domains to avoid detection.",
      "New domains lack established reputation, making them inherently riskier.",
    ],
    safer: [
      "Exercise extreme caution. Verify the site's legitimacy through other trusted sources.",
      "Avoid logging in or sharing personal data unless you are absolutely certain of its authenticity.",
    ],
  },
  website_typosquatting: {
    title: "This site may be impersonating a popular service",
    why: [
      "Typosquatting (or URL hijacking) uses slight variations of popular domain names to trick users.",
      "Attackers aim to steal credentials or spread malware by mimicking trusted brands.",
    ],
    safer: [
      "Carefully check the URL for any misspellings, swapped characters, or unusual characters.",
      "Always type sensitive URLs directly or use bookmarks instead of clicking suspicious links.",
    ],
  },
  website_phishing_list: {
    title: "This site is on a known phishing list",
    why: [
      "This site has been identified by security services as hosting phishing content or malware.",
      "Visiting this site can lead to account compromise, data theft, or malware infection.",
    ],
    safer: ["Do NOT proceed to this site. Close the tab immediately.", "Report the site if possible."],
  },
  perm_camera_mic: {
    title: "Suspicious Camera + Microphone combo",
    why: [
      "Requesting both simultaneously is a common pattern for eavesdropping or unauthorized recording.",
      "Unknown domains asking for these together carry higher risk of privacy invasion.",
    ],
    safer: [
      "Deny if you aren't about to start a video call.",
      "Check if the site's primary purpose justifies this level of hardware access.",
    ],
  },
  perm_location: {
    title: "Location tracking request",
    why: [
      "Your precise location can be used for physical tracking or building a detailed profile of your movements.",
    ],
    safer: ["Only allow for maps, local weather, or services where geography is essential."],
  },
  perm_clipboard: {
    title: "Clipboard access requested",
    why: [
      "Malicious sites can read sensitive data (passwords, keys) or replace content (wallet addresses) in your clipboard.",
    ],
    safer: ["Be wary of sites requesting clipboard access unless you specifically triggered a paste action."],
  },
  perm_notifications: {
    title: "Notification permission request",
    why: [
      "Often used by scam sites to deliver 'your computer is infected' fake alerts or spam directly to your desktop.",
    ],
    safer: ["Deny unless you explicitly want updates from a trusted news or messaging site."],
  },
};

function getEducation(signal: RiskSignal): Education {
  if (signal.id.endsWith("_mismatch")) {
    return {
      title: "Permission-purpose mismatch",
      why: [
        "If a permission doesn’t match the extension’s stated purpose, it could indicate overreach.",
        "Overbroad permissions increase the impact if the extension is compromised.",
      ],
      safer: [
        "Ask: could the extension work with fewer permissions?",
        "If you can’t justify it, avoid installing or keep it disabled until needed.",
      ],
    };
  }

  return (
    EDUCATION_BY_SIGNAL_ID[signal.id] ?? {
      title: signal.message,
      why: ["This pattern is commonly associated with scams, data theft, or unwanted tracking."],
      safer: ["Verify the domain and avoid entering sensitive data until you trust the page."],
    }
  );
}

function getRiskCategory(score: number) {
  if (score >= 70) return { label: 'High Risk', color: '#dc2626' };
  if (score >= 30) return { label: 'Medium Risk', color: '#b45309' };
  return { label: 'Low Risk', color: '#059669' };
}

export function WarningPanel({
  overall,
  page,
  extension,
  pageSignals,
  extensionSignals,
  behavior,
  extensionActivity,
  onClose,
  showCloseButton,
}: {
  overall: { score: number; level: string };
  page: { score: number; level: string };
  extension: { score: number; level: string };
  pageSignals: RiskSignal[];
  extensionSignals: RiskSignal[];
  behavior?: {
    score: number;
    habits: string[];
    suggestions: string[];
  };
  extensionActivity?: ExtensionActivityItem[];
  onClose: () => void;
  showCloseButton: boolean;
}) {
  const [view, setView] = useState<'signals' | 'dashboard' | 'learn'>('signals');
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [unlockedBadges, setUnlockedBadges] = useState<string[]>([]);
  const [quizIdx, setQuizIdx] = useState(0);
  const [quizFeedback, setQuizFeedback] = useState<string | null>(null);
  const [mode, setMode] = useState<'strict' | 'balanced' | 'silent'>('balanced');

  useEffect(() => {
    runtime?.sendMessage?.({ type: 'GET_DASHBOARD_DATA' }, (response: any) => {
      if (response) setDashboardData(response);
    });

    storage?.get?.(['unlockedBadges', 'pg_mode'], (result: any) => {
      let badges = result.unlockedBadges || ['guardian_initiate'];
      if (behavior && behavior.score > 90 && !badges.includes('privacy_pro')) {
        badges.push('privacy_pro');
      }
      setUnlockedBadges(badges);
      if (result.pg_mode) setMode(result.pg_mode);
    });
  }, []);

  const removeExtension = (id: string) => {
    runtime?.sendMessage?.({ type: 'REMOVE_EXTENSION', id });
  };

  const revokeSite = (origin: string) => {
    runtime?.sendMessage?.({ type: 'CLEAR_SITE_DATA', origin });
  };

  const changeMode = (m: 'strict' | 'balanced' | 'silent') => {
    setMode(m);
    storage?.set?.({ pg_mode: m });
  };

  const handleQuizAnswer = (idx: number) => {
    const question = QUIZ_QUESTIONS[quizIdx];
    if (idx === question.correctIndex) {
      setQuizFeedback("✅ Correct! " + question.explanation);
      if (!unlockedBadges.includes('eagle_eye')) {
        const next = [...unlockedBadges, 'eagle_eye'];
        setUnlockedBadges(next);
        storage?.set?.({ unlockedBadges: next });
      }
    } else {
      setQuizFeedback("❌ Incorrect. " + question.explanation);
    }
  };

  const getSuggestions = () => {
    const list: string[] = [];
    if (behavior?.suggestions) list.push(...behavior.suggestions);
    
    const unusedExts = dashboardData?.extensionSummary.filter(e => !e.hasActivity && e.enabled).length || 0;
    if (unusedExts > 0) list.push(`Remove or disable ${unusedExts} unused extensions`);

    const heavySites = dashboardData?.sitePermissions.filter(s => s.permissions.length > 2).length || 0;
    if (heavySites > 0) list.push(`Revoke excessive permissions from ${heavySites} sites`);

    return list;
  };

  return (
    <div className="guardian-panel">
      {showCloseButton ? (
        <button
          type="button"
          className="guardian-panel__close"
          aria-label="Close Permission Guardian panel"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            onClose();
          }}
        >
          ×
        </button>
      ) : null}
      <h3>🛡️ Permission Guardian</h3>

      <div className="guardian-panel__tabs" style={{ display: 'flex', gap: '4px', marginBottom: '16px' }}>
        <button 
          className={`guardian-panel__tab ${view === 'signals' ? 'active' : ''}`}
          onClick={() => setView('signals')}
          style={{ flex: 1, padding: '4px', cursor: 'pointer', border: '1px solid #ddd', borderRadius: '4px', background: '#fff', color: '#111' }}
        >
          Live Analysis
        </button>
        <button 
          className={`guardian-panel__tab ${view === 'dashboard' ? 'active' : ''}`}
          onClick={() => setView('dashboard')}
          style={{ flex: 1, padding: '4px', cursor: 'pointer', border: '1px solid #ddd', borderRadius: '4px', background: '#fff', color: '#111' }}
        >
          Dashboard
        </button>
        <button 
          className={`guardian-panel__tab ${view === 'learn' ? 'active' : ''}`}
          onClick={() => setView('learn')}
          style={{ flex: 1, padding: '4px', cursor: 'pointer', border: '1px solid #ddd', borderRadius: '4px', background: '#fff', color: '#111' }}
        >
          Learn
        </button>
      </div>

      {view === 'learn' ? (
        <div className="guardian-panel__learn">
          <h4>🏆 Your Badges</h4>
          <div style={{ display: 'flex', gap: '10px', marginBottom: '20px', flexWrap: 'wrap' }}>
            {BADGE_DEFINITIONS.map(badge => (
              <div key={badge.id} style={{ 
                opacity: unlockedBadges.includes(badge.id) ? 1 : 0.3,
                textAlign: 'center', width: '60px'
              }} title={badge.description}>
                <div style={{ fontSize: '24px' }}>{badge.icon}</div>
                <div style={{ fontSize: '10px' }}>{badge.name}</div>
              </div>
            ))}
          </div>

          <h4>🧩 Quick Quiz</h4>
          <div style={{ background: '#f3f4f6', color: '#111', padding: '12px', borderRadius: '8px' }}>
            <p style={{ margin: '0 0 10px 0', fontSize: '13px', fontWeight: 'bold' }}>
              {QUIZ_QUESTIONS[quizIdx].text}
            </p>
            {QUIZ_QUESTIONS[quizIdx].options.map((opt, i) => (
              <button 
                key={i} 
                onClick={() => handleQuizAnswer(i)}
                style={{ 
                  display: 'block', width: '100%', textAlign: 'left', 
                  marginBottom: '5px', padding: '6px', fontSize: '12px',
                  cursor: 'pointer', borderRadius: '4px', border: '1px solid #ccc',
                  background: '#fff', color: '#111'
                }}
              >
                {opt}
              </button>
            ))}
            {quizFeedback && (
              <div style={{ fontSize: '11px', marginTop: '10px', fontStyle: 'italic', color: '#374151' }}>
                {quizFeedback}
                <button 
                  onClick={() => { setQuizIdx((quizIdx + 1) % QUIZ_QUESTIONS.length); setQuizFeedback(null); }}
                  style={{ display: 'block', marginTop: '5px', background: 'none', border: 'none', color: '#2563eb', cursor: 'pointer', padding: 0 }}
                >
                  Next Question →
                </button>
              </div>
            )}
          </div>
          
          <div style={{ marginTop: '15px', fontSize: '12px', color: '#9ca3af' }}>
            Tip: Always hover over links to see the real destination in the bottom corner of your browser.
          </div>
        </div>
      ) : view === 'dashboard' ? (
        <div className="guardian-panel__dashboard">
          <h4>🛡️ Protection Mode</h4>
          <div style={{ display: 'flex', gap: '4px', marginBottom: '16px' }}>
            {[
              { id: 'strict', label: '🛑 Strict', desc: 'Warn everything' },
              { id: 'balanced', label: '⚖️ Balanced', desc: 'Risky only' },
              { id: 'silent', label: '💤 Silent', desc: 'Logs only' }
            ].map(m => (
              <button
                key={m.id}
                onClick={() => changeMode(m.id as any)}
                style={{
                  flex: 1, padding: '6px 2px', fontSize: '11px', cursor: 'pointer',
                  border: '1px solid #ddd', borderRadius: '4px',
                  background: mode === m.id ? '#e5e7eb' : '#fff',
                  color: '#111',
                  fontWeight: mode === m.id ? 'bold' : 'normal'
                }}
                title={m.desc}
              >
                {m.label}
              </button>
            ))}
          </div>

          <div className="guardian-panel__scoreCard" style={{ textAlign: 'center', background: '#f9fafb', padding: '16px', borderRadius: '8px', marginBottom: '16px' }}>
             <div style={{ fontSize: '12px', color: '#6b7280' }}>Global Security Score</div>
             <div style={{ fontSize: '32px', fontWeight: 'bold', color: (behavior?.score || 100) > 70 ? '#059669' : '#dc2626' }}>
               {behavior?.score || 100}/100
             </div>
          </div>

          <h4>🛠️ Improvement Suggestions</h4>
          <ul style={{ paddingLeft: '20px', fontSize: '13px' }}>
            {getSuggestions().map((s, i) => <li key={i} style={{ marginBottom: '4px' }}>{s}</li>)}
          </ul>

          <h4 style={{ display: 'flex', justifyContent: 'space-between' }}>
            📦 Extension Risk Cleanup
          </h4>
          <div style={{ maxHeight: '200px', overflowY: 'auto', fontSize: '12px', background: '#fff', borderRadius: '8px', padding: '8px', border: '1px solid #eee' }}>
            {dashboardData?.extensionSummary
              .slice()
              .sort((a, b) => b.riskScore - a.riskScore)
              .map((ext) => {
                const cat = getRiskCategory(ext.riskScore);
                const isUnused = ext.lastUsed && (Date.now() - ext.lastUsed > 30 * 24 * 60 * 60 * 1000);
                return (
                  <div key={ext.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #f3f4f6', alignItems: 'center' }}>
                    <div>
                      <div style={{ fontWeight: 'bold', color: '#111' }}>{ext.name}</div>
                      <div style={{ fontSize: '10px', color: cat.color }}>{cat.label} {isUnused ? '• ⏳ Unused > 30d' : ''}</div>
                    </div>
                    <button 
                      onClick={() => removeExtension(ext.id)}
                      style={{ background: '#fee2e2', color: '#dc2626', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: 'pointer', fontSize: '10px', fontWeight: 'bold' }}
                    >
                      Remove
                    </button>
                  </div>
                );
              })}
          </div>

          <h4 style={{ marginTop: '16px' }}>📍 Site Permissions</h4>
          <div style={{ maxHeight: '150px', overflowY: 'auto', fontSize: '12px' }}>
            {dashboardData?.sitePermissions.map((site, i) => (
              <div key={i} style={{ borderBottom: '1px solid #eee', padding: '6px 0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ maxWidth: '180px' }}>
                  <strong>{site.origin.replace('https://', '').replace('http://', '')}</strong>
                  <div style={{ fontSize: '10px', color: '#6b7280' }}>{site.permissions.join(', ')}</div>
                </div>
                <button 
                  onClick={() => revokeSite(site.origin)}
                  style={{ background: 'none', border: '1px solid #ccc', padding: '2px 6px', borderRadius: '4px', cursor: 'pointer', fontSize: '10px', color: '#111' }}
                >
                  Revoke
                </button>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <>
          <p>
            Overall Risk: <strong>{overall.level}</strong>{" "}
            <span className="guardian-panel__subtle">(score {overall.score})</span>
          </p>
      
      <p className="guardian-panel__subtle">
        Page: <strong>{page.level}</strong> (score {page.score}) · Extension:{" "}
        <strong>{extension.level}</strong> (score {extension.score})
      </p>

      <p className="guardian-panel__subtle">
        Explains what looks risky. It does not block anything yet.
      </p>

      {behavior && (
        <div className="guardian-panel__behavior">
          <h4>🧠 Behavior Analysis</h4>
          <p>
            Weekly Security Score: <strong>{behavior.score}/100</strong>
          </p>
          {behavior.habits.length > 0 && (
            <div className="guardian-panel__habits">
              <div className="guardian-panel__sectionTitle">Identified Patterns</div>
              <ul className="guardian-panel__habitList">
                {behavior.habits.map((h, i) => (
                  <li key={i} className="guardian-panel__habit">🚨 {h}</li>
                ))}
              </ul>
            </div>
          )}
          {behavior.suggestions.length > 0 && (
            <div className="guardian-panel__suggestions">
              <div className="guardian-panel__sectionTitle">Habit Improvement</div>
              <ul className="guardian-panel__suggestionList">
                {behavior.suggestions.map((s, i) => (
                  <li key={i}>💡 {s}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {extensionActivity && extensionActivity.length > 0 && (
        <div className="guardian-panel__activity">
          <h4>📡 Live Extension Activity</h4>
          <div className="guardian-panel__timeline">
            {extensionActivity.slice(-5).reverse().map((act, i) => (
              <div key={i} className="guardian-panel__activityItem">
                <span className="guardian-panel__activityType">
                  {act.type === 'extension_injection' ? '💉 Script Injected' : 
                   act.type === 'network_request' ? '🌐 Network Call' : '🍪 Data Access'}
                </span>
                <div className="guardian-panel__subtle" style={{fontSize: '11px'}}>
                  {act.detail}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <h4>Extension permissions</h4>
      {extensionSignals.length === 0 ? (
        <p className="guardian-panel__subtle">
          Couldn’t read extension manifest (or no relevant signals).
        </p>
      ) : (
        <div className="guardian-panel__signals">
          {extensionSignals.map((s) => {
            const education = getEducation(s);
            return (
              <details key={s.id} className="guardian-panel__signal" open={extensionSignals.length === 1}>
                <summary className="guardian-panel__signalSummary">
                  <span className="guardian-panel__signalTitle">{education.title}</span>
                  <span className="guardian-panel__signalMeta">
                    {s.category} · weight {s.weight}
                  </span>
                </summary>
                <div className="guardian-panel__signalBody">
                  <div className="guardian-panel__sectionTitle">Why this can be risky</div>
                  <ul>
                    {education.why.map((line, idx) => (
                      <li key={idx}>{line}</li>
                    ))}
                  </ul>
                  <div className="guardian-panel__sectionTitle">Safer next step</div>
                  <ul>
                    {education.safer.map((line, idx) => (
                      <li key={idx}>{line}</li>
                    ))}
                  </ul>
                </div>
              </details>
            );
          })}
        </div>
      )}

      <h4>Page signals</h4>
      {pageSignals.length === 0 ? (
        <p className="guardian-panel__subtle">No risk signals detected on this page.</p>
      ) : (
        <div className="guardian-panel__signals">
          {pageSignals.map((s) => {
            const education = getEducation(s);
            return (
              <details key={s.id} className="guardian-panel__signal" open={pageSignals.length === 1}>
                <summary className="guardian-panel__signalSummary">
                  <span className="guardian-panel__signalTitle">{education.title}</span>
                  <span className="guardian-panel__signalMeta">
                    {s.category} · weight {s.weight}
                  </span>
                </summary>
                <div className="guardian-panel__signalBody">
                  <div className="guardian-panel__sectionTitle">Why this can be risky</div>
                  <ul>
                    {education.why.map((line, idx) => (
                      <li key={idx}>{line}</li>
                    ))}
                  </ul>
                  <div className="guardian-panel__sectionTitle">Safer next step</div>
                  <ul>
                    {education.safer.map((line, idx) => (
                      <li key={idx}>{line}</li>
                    ))}
                  </ul>
                </div>
              </details>
            );
          })}
        </div>
      )}
        </>
      )}
    </div>
  );
}

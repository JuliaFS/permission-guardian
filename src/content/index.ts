import { analyzeDOM } from '../engine/domAnalyzer'
import { analyzeExtensionManifest } from '../engine/extensionPermissionsAnalyzer'
import { calculateRisk } from '../engine/riskScorer'
import { analyzeUrl } from '../engine/urlAnalyzer'
import { injectPanel } from '../panel/injectPanel'
import { initExtensionActivityTracker } from '../engine/extensionActivityTracker'

if (window.top !== window.self) {
  // Avoid injecting into iframes.
  // (Also keeps analysis cost down on complex pages.)
  // eslint-disable-next-line no-console
  console.debug('Permission Guardian: skipping iframe')
} else {
  initPermissionTracker()
  initExtensionActivityTracker()

  const runtime =
    (globalThis as any).chrome?.runtime ?? (globalThis as any).browser?.runtime

  function compute() {
    const url = window.location.href
    const urlSignals = analyzeUrl(url)
    const domSignals = analyzeDOM()
    const pageSignals = [...urlSignals, ...domSignals]

    const manifest = runtime?.getManifest?.()
    const extensionSignals = manifest ? analyzeExtensionManifest(manifest) : []

    const allSignals = [...pageSignals, ...extensionSignals]
    const overall = calculateRisk(allSignals)
    const pageRisk = calculateRisk(pageSignals)
    const extensionRisk = calculateRisk(extensionSignals)

    return { overall, pageRisk, extensionRisk, pageSignals, extensionSignals }
  }

  function reportBadgeRisk() {
    const { overall } = compute()
    runtime?.sendMessage?.({
      type: 'PG_RISK_UPDATE',
      level: overall.level,
      score: overall.score,
    })
  }

  function togglePanel() {
    const existing = document.getElementById('guardian-root')
    if (existing) {
      existing.remove()
      return
    }

    const showCloseButton =
      globalThis.localStorage?.getItem('pg_show_close_button') === '1'

    const { overall, pageRisk, extensionRisk, pageSignals, extensionSignals } =
      compute()

    runtime?.sendMessage?.({
      type: 'PG_RISK_UPDATE',
      level: overall.level,
      score: overall.score,
    })

    injectPanel(
      {
        overall,
        page: pageRisk,
        extension: extensionRisk,
      },
      { page: pageSignals, extension: extensionSignals },
      { showCloseButton },
    )
  }

  runtime?.onMessage?.addListener((message: any) => {
    if (message?.type === 'PG_TOGGLE_PANEL') {
      togglePanel()
    }
  })

  // Update the toolbar badge for this tab once the page is ready.
  // (Keeps the icon informative even when the panel is closed.)
  if (document.readyState === 'complete') {
    reportBadgeRisk()
  } else {
    window.addEventListener(
      'load',
      () => {
        reportBadgeRisk()
      },
      { once: true },
    )
  }
}

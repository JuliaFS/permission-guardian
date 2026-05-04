import { analyzeDOM } from '../engine/domAnalyzer'
import { calculateRisk } from '../engine/riskScorer'
import { analyzeUrl } from '../engine/urlAnalyzer'
import { injectPanel } from '../panel/injectPanel'

if (window.top !== window.self) {
  // Avoid injecting into iframes.
  // (Also keeps analysis cost down on complex pages.)
  // eslint-disable-next-line no-console
  console.debug('Permission Guardian: skipping iframe')
} else {
  const runtime =
    (globalThis as any).chrome?.runtime ?? (globalThis as any).browser?.runtime

  function togglePanel() {
    const existing = document.getElementById('guardian-root')
    if (existing) {
      existing.remove()
      return
    }

    const showCloseButton =
      globalThis.localStorage?.getItem('pg_show_close_button') === '1'

    const url = window.location.href
    const urlSignals = analyzeUrl(url)
    const domSignals = analyzeDOM()
    const allSignals = [...urlSignals, ...domSignals]
    const result = calculateRisk(allSignals)

    injectPanel(result, allSignals, { showCloseButton })
  }

  runtime?.onMessage?.addListener((message: any) => {
    if (message?.type === 'PG_TOGGLE_PANEL') {
      togglePanel()
    }
  })
}

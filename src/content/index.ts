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
  const url = window.location.href

  const urlSignals = analyzeUrl(url)
  const domSignals = analyzeDOM()

  const allSignals = [...urlSignals, ...domSignals]

  const result = calculateRisk(allSignals)

  injectPanel(result, allSignals)
}

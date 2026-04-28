import { createRoot } from 'react-dom/client'
import { WarningPanel } from './WarningPanel'

export function injectPanel(result: any, signals: any[]) {
  const existing = document.getElementById('guardian-root')
  if (existing) existing.remove()

  const container = document.createElement('div')
  container.id = 'guardian-root'
  document.body.appendChild(container)

  const root = createRoot(container)

  root.render(<WarningPanel level={result.level} signals={signals} />)
}

import { createRoot } from 'react-dom/client'
import { WarningPanel } from './WarningPanel'
import type { RiskSignal } from '../engine/types'
import { analyzeBehavior } from '../engine/behaviorAnalyzer'

export async function injectPanel(
  result: {
    overall: { score: number; level: string }
    page: { score: number; level: string }
    extension: { score: number; level: string }
  },
  signals: { page: RiskSignal[]; extension: RiskSignal[] }, // Renamed from 'pageSignals' to 'signals.page' for clarity
  options?: { showCloseButton?: boolean },
) {
  const storage = (globalThis as any).chrome?.storage?.local ?? (globalThis as any).browser?.storage?.local
  const behaviorMetrics = await analyzeBehavior()
  const activityData = await storage?.get(['pg_extension_activity'])
  const activityLogs = activityData?.pg_extension_activity || []

  const existing = document.getElementById('guardian-root')
  if (existing) existing.remove()

  const container = document.createElement('div')
  container.id = 'guardian-root'
  document.body.appendChild(container)

  const root = createRoot(container)

  const close = () => {
    document.removeEventListener('pointerdown', onDocumentPointerDown, true)
    document.removeEventListener('keydown', onDocumentKeyDown, true)
    root.unmount()
    container.remove()
  }

  const onDocumentPointerDown = (event: Event) => {
    const target = event.target
    if (!(target instanceof Node)) return
    if (container.contains(target)) return
    close()
  }

  const onDocumentKeyDown = (event: KeyboardEvent) => {
    if (event.key === 'Escape') close()
  }

  document.addEventListener('pointerdown', onDocumentPointerDown, true)
  document.addEventListener('keydown', onDocumentKeyDown, true)

  root.render(
    <WarningPanel
      overall={result.overall}
      page={result.page}
      extension={result.extension}
      pageSignals={signals.page}
      extensionSignals={signals.extension}
      behavior={behaviorMetrics}
      extensionActivity={activityLogs}
      onClose={close}
      showCloseButton={options?.showCloseButton ?? false}
    />,
  )
}

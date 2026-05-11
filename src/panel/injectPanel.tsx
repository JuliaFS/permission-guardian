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
  const runtime = (globalThis as any).chrome?.runtime ?? (globalThis as any).browser?.runtime
  if (!runtime?.id) return

  const storage = (globalThis as any).chrome?.storage?.local ?? (globalThis as any).browser?.storage?.local

  try {
    const behaviorMetrics = await analyzeBehavior()
    const activityData = await storage?.get(['pg_extension_activity'])
    const activityLogs = activityData?.pg_extension_activity || []

    const existing = document.getElementById('guardian-root')
    if (existing) existing.remove()

    const container = document.createElement('div')
    container.id = 'guardian-root'
    document.body.appendChild(container)

    const shadowRoot = container.attachShadow({ mode: 'open' })

    // The panel.css is injected by Chrome via manifest.json into the main document.
    // Shadow DOM by default inherits styles from the host document.
    // Dynamically loading it here is redundant and can cause issues.
    // const cssHref = runtime?.getURL?.('panel.css')
    // if (cssHref) {
    //   const link = document.createElement('link')
    //   link.rel = 'stylesheet'
    //   link.href = cssHref
    //   shadowRoot.appendChild(link)
    // }

    const mount = document.createElement('div')
    shadowRoot.appendChild(mount)

    const root = createRoot(mount)

    const close = () => {
      document.removeEventListener('pointerdown', onDocumentPointerDown, true)
      document.removeEventListener('keydown', onDocumentKeyDown, true)
      root.unmount()
      container.remove()
    }

    const onDocumentPointerDown = (event: Event) => {
      const path = (event as any).composedPath?.() as EventTarget[] | undefined
      if (path && path.includes(container)) return

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
  } catch (error) {
    console.error('Permission Guardian: Error injecting panel:', error);
  }
}

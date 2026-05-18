import { createRoot } from 'react-dom/client'
import { WarningPanel } from './WarningPanel'
import type { RiskSignal, InjectedSignal } from '../engine/types'
import { analyzeBehavior } from '../engine/behaviorAnalyzer'
import { extensionApi } from '../utils/extensionApi'

export async function injectPanel(
  result: {
    overall: { score: number; level: string }
    page: { score: number; level: string }
    extension: { score: number; level: string }
  },
  signals: { page: RiskSignal[]; extension: RiskSignal[] },
  options?: { showCloseButton?: boolean; injectedSignals?: InjectedSignal[] },
) {
  if (!extensionApi.isAvailable) return

  try {
    const behaviorMetrics = await analyzeBehavior()
    const activityData = await extensionApi.getStorage(['pg_extension_activity'])
    const activityLogs = activityData?.pg_extension_activity || []

    const existing = document.getElementById('guardian-root')
    if (existing) existing.remove()

    const container = document.createElement('div')
    container.id = 'guardian-root'

    // Apply fixed positioning to float in the top-right corner
    Object.assign(container.style, {
      position: 'fixed',
      top: '20px',
      right: '20px',
      zIndex: '2147483647', // Ensure it stays above all other site elements
      width: '400px',
      maxWidth: 'calc(100vw - 40px)',
    })

    document.body.appendChild(container)

    const shadowRoot = container.attachShadow({ mode: 'open' })

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
        injectedSignals={options?.injectedSignals || []}
        onClose={close}
        showCloseButton={options?.showCloseButton ?? false}
      />,
    )
  } catch (error) {
    console.error('Permission Guardian: Error injecting panel:', error);
  }
}

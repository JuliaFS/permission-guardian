import { createRoot } from 'react-dom/client'
import { WarningPanel } from './WarningPanel'

export function injectPanel(
  result: any,
  signals: any[],
  options?: { showCloseButton?: boolean },
) {
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
      level={result.level}
      signals={signals}
      onClose={close}
      showCloseButton={options?.showCloseButton ?? false}
    />,
  )
}

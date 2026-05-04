const runtime =
  (globalThis as any).chrome?.runtime ?? (globalThis as any).browser?.runtime

runtime?.onInstalled?.addListener(() => {
  // eslint-disable-next-line no-console
  console.log('Permission Guardian installed')
})

const action =
  (globalThis as any).chrome?.action ?? (globalThis as any).browser?.action
const tabs = (globalThis as any).chrome?.tabs ?? (globalThis as any).browser?.tabs

action?.onClicked?.addListener(async (tab: any) => {
  const tabId = tab?.id
  if (typeof tabId !== 'number') return

  try {
    await tabs?.sendMessage?.(tabId, { type: 'PG_TOGGLE_PANEL' })
  } catch (error) {
    // eslint-disable-next-line no-console
    console.debug('Permission Guardian: failed to toggle panel', error)
  }
})

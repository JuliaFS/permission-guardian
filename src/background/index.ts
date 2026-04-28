const runtime =
  (globalThis as any).chrome?.runtime ?? (globalThis as any).browser?.runtime

runtime?.onInstalled?.addListener(() => {
  // eslint-disable-next-line no-console
  console.log('Permission Guardian installed')
})

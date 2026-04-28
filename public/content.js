(() => {
  const runtime =
    globalThis.chrome?.runtime ?? globalThis.browser?.runtime

  if (!runtime?.getURL) {
    console.error('Permission Guardian: extension runtime API not found')
    return
  }

  const url = runtime.getURL('assets/content-module.js')
  import(url).catch((error) => {
    console.error('Permission Guardian: failed to load content module', error)
  })
})()


# Permission Guardian (Browser Extension)

## Build a loadable `dist/` extension

Prereqs: Node.js 18+ and npm.

1. `npm install`
2. `npm run build`
3. In Chrome/Edge: Extensions → enable Developer mode → Load unpacked → select `dist/`

`dist/` contains:
- `manifest.json` (MV3)
- `popup.html` (extension action popup)
- `content.js` (bootstrap that loads the bundled content module)
- `panel.css` (content-script CSS for the injected panel)

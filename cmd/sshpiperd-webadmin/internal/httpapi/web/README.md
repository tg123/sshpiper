# sshpiperd-webadmin frontend

Hand-rolled vanilla-JS dashboard for `sshpiperd-webadmin`. Bundled with
[esbuild](https://esbuild.github.io/) and embedded into the Go binary
via `//go:embed`.

## Layout

```
web/
├── index.html         entry point served at /
├── src/
│   ├── app.js         JS source (uses ES module imports)
│   └── style.css      hand-rolled dashboard styles
├── assets/
│   └── logo.png       static images served at /assets/
├── package.json       npm deps + build script
├── build.mjs          esbuild driver
└── dist/              build output (gitignored, embedded by Go)
    ├── app.js
    └── app.css
```

## Building

You need Node.js (any LTS, ≥18) and npm.

```sh
npm ci          # install pinned deps from package-lock.json
npm run build   # produce dist/app.js + dist/app.css
```

For local development with rebuild-on-save:

```sh
npm run watch
```

The Go `//go:embed all:web/dist` directive in
`internal/httpapi/httpapi.go` requires `dist/` to contain at least one
file at compile time. `dist/.gitkeep` is committed so a fresh checkout
satisfies the embed rule, but the served UI will be empty until you run
`npm run build`. The Dockerfile and CI run the build automatically.

## Bumping versions

```sh
npm install @xterm/xterm@latest @xterm/addon-fit@latest
npm run build
git add package.json package-lock.json
```

`package-lock.json` pins exact versions and integrity hashes, giving
reproducible builds.

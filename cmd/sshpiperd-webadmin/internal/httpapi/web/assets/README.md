# Vendored web assets

These files are vendored verbatim from npm so that `sshpiperd-webadmin`
works in air-gapped environments without any third-party CDN at runtime.

| File                       | Source                                              |
| -------------------------- | --------------------------------------------------- |
| `pico.min.css`             | `@picocss/pico` 2.0.6 — `css/pico.min.css`          |
| `xterm.css`                | `@xterm/xterm` 5.5.0 — `css/xterm.css`              |
| `xterm.js`                 | `@xterm/xterm` 5.5.0 — `lib/xterm.js`               |
| `xterm-addon-fit.js`       | `@xterm/addon-fit` 0.10.0 — `lib/addon-fit.js`      |

Each asset ships with its upstream license alongside it
(`pico.LICENSE.md`, `xterm.LICENSE`, `xterm-addon-fit.LICENSE`).

## Refreshing

The assets are pure-static files — no Node toolchain is required to
build the UI. To bump a version, download the new tarball from
`https://registry.npmjs.org/<pkg>/-/<pkg>-<version>.tgz`, replace the
files in this directory, and update the table above. For example:

```sh
cd $(mktemp -d)
curl -sSL -o p.tgz https://registry.npmjs.org/@picocss/pico/-/pico-2.0.6.tgz
tar -xzf p.tgz package/css/pico.min.css package/LICENSE.md
mv package/css/pico.min.css   .../web/assets/pico.min.css
mv package/LICENSE.md         .../web/assets/pico.LICENSE.md
```

After replacing JS files, strip any `//# sourceMappingURL=...` trailer
since the maps are not vendored.

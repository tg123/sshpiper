// esbuild driver for the sshpiperd-webadmin dashboard.
//
// Reads src/app.js and src/style.css, bundles them into dist/app.js and
// dist/app.css. The Go side picks up dist/* via //go:embed.
//
// Run via:  npm run build       (one-shot)
//           npm run watch       (rebuild on change for local dev)

import { build, context } from 'esbuild';

const watch = process.argv.includes('--watch');

const opts = {
  entryPoints: {
    app: 'src/app.js',
  },
  bundle: true,
  outdir: 'dist',
  format: 'iife',
  target: ['es2020'],
  minify: !watch,
  sourcemap: watch ? 'inline' : false,
  legalComments: 'none',
  loader: {
    '.css': 'css',
  },
  logLevel: 'info',
};

if (watch) {
  const ctx = await context(opts);
  await ctx.watch();
  console.log('esbuild: watching for changes…');
} else {
  await build(opts);
}

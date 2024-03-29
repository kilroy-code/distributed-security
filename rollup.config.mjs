import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import eslint from '@rollup/plugin-eslint';
import terser from '@rollup/plugin-terser';

const devMode = (process.env.NODE_ENV === 'development');
// E.g., npx rollup -c --environment NODE_ENV:development
console.log(`${ devMode ? 'development' : 'production' } mode bundle`);

function target(input, output) { // roll up input to output
  return {
    input,
    output: {
      file: output,
      format: 'es',
      sourcemap: devMode ? 'inline' : false
    },
    plugins: [
      eslint({
	exclude: [
	  "**/*bundle.mjs",
	  "lib/package-loader.mjs"
	  ]
      }),
      json(),
      nodeResolve({browser: true, preferBuiltins: false}),
      commonjs(),
      !devMode && terser()
    ]
  };
}

export default [
  // Browsers need three files:
  // index.mjs, and the following files relative to it:
  // ./lib/vault-bundle.mjs
  // ./lib/worker-bundle.mjs

  // The following two are not necessary for any of the above, but it can be convenient for
  // development/debugging to edit securitySpec.mjs to appear directly in a jasmine test.html.
  // However, securitySpec.mjs references @kilroy-code/distributed-security
  // and #internals, and these won't work in a browser. Internally, they use further
  // imports from the package.json that need to be resolved to work in a browser.
  // One way to do that is to replace these first two references with one of the
  // following pre-processed bundles.
  // Indeed, the standard checked-in version of securitySpec DOES depend on #internals.
  target('lib/api.mjs',                'lib/api-browser-bundle.mjs'),
  target('spec/support/internals.mjs', 'spec/support/internal-browser-bundle.mjs'),

  // The last of the required files listed above, and the only one that is of any substantial size.
  target('lib/worker.mjs',             'lib/worker-bundle.mjs'),

  // fixme
  target('lib/vault.mjs',              'lib/vault-bundle.mjs'),

  // This "application" (the unit tests) incorporate index.mjs, and also internals, below.
  // Note that even though this bundle includes index.mjs, it does not include
  // the three files enumerated above that index.mjs references, and so they must have
  // the same relative placement as this bundle.
  target('spec/securitySpec.mjs',      'securitySpec-bundle.mjs')
];

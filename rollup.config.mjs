import { nodeResolve } from '@rollup/plugin-node-resolve';
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
      nodeResolve({browser: true, preferBuiltins: false}), // Resolve package.json imports.
      // api.mjs => package-loader.mjs pulls in the package.json to report the name and version.
      // Some system's implementations of 'import' do not yet support that, so unroll it here.
      json(), 
      !devMode && terser() // minify for production.
    ]
  };
}

// Browsers need three files: index.mjs, and the following bundles relative to it.
// SEE NEXT COMMENT!
const productionBundles = [
  target('index.mjs',                  'dist/index-bundle.mjs'),
  target('lib/worker.mjs',             'dist/worker-bundle.mjs'),
  target('lib/vault.mjs',              'dist/vault-bundle.mjs')
];

// `npm run test` will run jasmine on spec/securitySpec.mjs directly in node, which resolves
// any subpath imports (e.g., #localStore) using package.json.
//
// However, browsers don't look at package.json, so we need to pre-process securitySpec.mjs.
// This "application" (the unit tests) references the package by name, which resolves by
// the exports in package.json to reference index.mjs in browser.
//
// Note that even though this bundle includes index.mjs, it does not bundle the two bundles
// enumerated above, which are referenced by bundle name in the code. (They are bypassed
// completely in node.) So the above bundles  must have the same relative placement as this bundle.
//
// In our case, securitySpec.mjs also references #internals, which package.json resolves to an
// .mjs file that gets included directly in the "application" bundle (securitySpec-bundle.mjs).
const unitTestBundles = [
  target('spec/securitySpec.mjs',      'dist/securitySpec-bundle.mjs')
];

// When developing the distributed-security module itself, it is sometimes convenient to
// edit securitySpec to refer directly to these bundles:
const additionalModuleDevelopmentBundles = [
  target('lib/api.mjs',                'dist/api-browser-bundle.mjs'),
  target('spec/support/internals.mjs', 'dist/internal-browser-bundle.mjs')
];

export default [
  ...productionBundles,
  ...unitTestBundles,
  ...(devMode ? additionalModuleDevelopmentBundles : [])
];


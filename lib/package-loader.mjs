// Because eslint doesn't recognize import assertions
import * as pkg from "../package.json" with { type: 'json' };
export const {name, version} = pkg.default;

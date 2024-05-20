import * as path from 'node:path';
import * as fs from 'node:fs/promises';

export async function mkdir(pathname) { // Make pathname exist, including any missing directories.
  await fs.mkdir(pathname, {recursive: true});
  // Subtle: On some machines (e.g., my mac with file system encryption), mkdir does not flush,
  // and a subsequent read gets an error for missing directory.
  // We can't control what happens in express.static, so let's ensure here that reading works the way we think.
  let dummy = path.join(pathname, 'dummy');
  await fs.writeFile(dummy, '', {flush: true});
  await fs.unlink(dummy)
}

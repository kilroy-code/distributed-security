import * as path from 'node:path';
import * as fs from 'node:fs/promises';
import {randomBytes} from 'node:crypto';

class PersistedCollection {
  // Asynchronous local storage using the Node file system.
  //
  // Each promises a string (including store, or read/remove of non-existent tag).
  //
  // Interleaved store/retrieve/remove are not deterministic between processes, but:
  // - They are still safe between processes - store/remove are atomic
  // - Within a process, the are deterministic because all operationss queued.

  constructor({collectionName = 'collection', dbName = 'asyncLocalStorage', temporarySubdirectory = 'temp'} = {}) {
    this.path = tag => path.join(dbName, collectionName, tag);
    // The temporary files are all in the same temporarySubdirectory which is
    // 1. Created just once when creating the collection.
    // 2. A subdirectory of the collection, so that it on the same file system.
    this.temporaryPath = tag => path.join(dbName, collectionName, temporarySubdirectory,
					  tag + randomBytes(6).readUIntLE(0,6).toString(36));
    // Ensure path to collectionName and it's temporarySubdirectory. No errors if parts exist.
    // Also the first item in our queue. (constructors cannot be async, but we want to ensure the path exists before any ops).
    this.queue = fs.mkdir(path.join(dbName, collectionName, temporarySubdirectory), {recursive: true});
  }

  retrieve(tag) { // Promise to retrieve tag from collectionName.
    return this.queue = this.queue.then(async () => {
      return (await fs.readFile(this.path(tag), {encoding: 'utf8'}).catch(() => ""));
    });
  }
  remove(tag) { // Promise to remove tag from collectionName.
    return this.queue = this.queue.then(async () => {
      // Rename before rm, as rm will fail if there is contention.
      let temp = this.temporaryPath(tag),
	  error = await fs.rename(this.path(tag), temp).catch(error => error);
      if (error?.code === 'ENOENT') return ""; // Not undefined
      if (error) return Project.reject(error);
      await fs.rm(temp);
      return "";
    });
  }
  store(tag, data) { // Promise to store data at tag in collectionName.
    return this.queue = this.queue.then(async () => {
      // Write to temp (as that is not atomic) and then rename (which is atomic).
      let temp = this.temporaryPath(tag);
      await fs.writeFile(temp, data, {flush: true});
      await fs.rename(temp, this.path(tag));
      return "";
    });
  }
};
export default PersistedCollection;

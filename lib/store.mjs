const PersistedCollection = {
  // Asynchronous local storage, available in web workers.
  
  dbName: 'asyncLocalStorage',
  collectionName: 'collection',
  version: 1,
  get db() { // Answer a promise for the database, creating it if needed.
    return this._db ??= new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);
      // createObjectStore can only be called from upgradeneeded, which is only called for new versions.
      request.onupgradeneeded = event => event.target.result.createObjectStore(this.collectionName);
      request.onsuccess = event => resolve(event.target.result);
    });
  },
  transaction(mode = 'read') { // Answer a promise for the named object store on a new transaction.
    const collectionName = this.collectionName;
    return this.db.then(db => db.transaction(collectionName, mode).objectStore(collectionName));
  },
  retrieve(tag) {
    return new Promise(resolve => {
      this.transaction('readonly').then(store => store.get(tag).onsuccess = event => resolve(event.target.result));
    });
  },
  store(tag, data) {
    return new Promise(resolve => {
      this.transaction('readwrite').then(store => store.put(data, tag).onsuccess = event => resolve(event.target.result));
    });
  },
  remove(tag) {
    return new Promise(resolve => {
      this.transaction('readwrite').then(store => store.delete(tag).onsuccess = event => resolve(event.target.result));
    });
  }
};
export default PersistedCollection;

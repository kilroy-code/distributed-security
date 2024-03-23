import {Level} from "level";

class PersistedCollection {
  // Asynchronous local storage, available in web workers and Node.
  constructor({collectionName = 'collection', dbName = 'asyncLocalStorage'} = {}) {
    this.dbName = dbName;
    this.collectionName = collectionName;
    this.db = new Level(dbName);
    this.db.open().then(_ => this.collection = this.db.sublevel(collectionName));
  }
  retrieve(tag) { // Promise to retrieve tag from collectionName.
    return this.collection.get(tag).catch(_ => undefined);
  }
  store(tag, data) { // Promise to store data at tag in collectionName.
    return this.collection.put(tag, data).catch(_ => true);
  }
  remove(tag) { // Promise to remove tag from collectionName.
    return this.collection.del(tag).catch(_ => true);
  }
};
export default PersistedCollection;

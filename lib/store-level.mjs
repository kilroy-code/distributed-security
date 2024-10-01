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
    return this.collection.get(tag).catch(_ => "");
  }
  async store(tag, data) { // Promise to store data at tag in collectionName.
    await this.collection.put(tag, data);
    return ""; // Rather than defined, as put() does. (IndexedDB effectively answers tag.)
  }
  async remove(tag) { // Promise to remove tag from collectionName.
    await this.collection.del(tag);
    return ""; // Rather than undefined, as del() does.
  }
};
export default PersistedCollection;

import MultiKrypto from "./multiKrypto.mjs";
import {Vault, DeviceVault, TeamVault} from "./vault.mjs";

const Security = {
  set Storage(storage) {
    Vault.Storage = storage;
  },
  async create(...members) { // ...
    if (members.length) return await TeamVault.create(members);
    else return await DeviceVault.create();
  },
  async verify(tag, signature, message) { // Promise true if signature was made by tag, else false.
    let verifyingKey = await Vault.verifyingKey(tag);
    return MultiKrypto.verify(verifyingKey, signature, message);
  },
  async encrypt(tag, message) { // Promise text that can only be decrypted back to message by the keypair designated by tag.
    let encryptingKey = await Vault.encryptingKey(tag);
    return await MultiKrypto.encrypt(encryptingKey, message);
  },
  async decrypt(tag, encrypted) { // Promise the original text given to encrypt() IFF the current user has access to the keypair designated by tag, else reject.
    let vault = await Vault.ensure(tag);
    return vault.decrypt(encrypted);
  },
  async sign(tag, message) { // Promise a signature for message suitable for verify() IFF the current user has access to the keypair designated by tag, else reject.
    let vault = await Vault.ensure(tag);
    return vault.sign(message);
  },
  async destroy(tag) { //
    let vault = await Vault.ensure(tag);
    return vault.destroy();
  }
};

export default Security;

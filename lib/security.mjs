import MultiKrypto from "./multiKrypto.mjs";
import {Vault, DeviceVault, RecoveryVault, TeamVault} from "./vault.mjs";

const Security = {
  set Storage(storage) {
    Vault.Storage = storage;
  },
  set getUserDeviceSecret(thunk) {
    Vault.getUserDeviceSecret = thunk;
  },
  async create(...members) { // ...
    if (!members.length) return await DeviceVault.create();
    let prompt = members[0].prompt;
    if (prompt) return await RecoveryVault.create(prompt);
    return await TeamVault.create(members);
  },
  async verify(signature, tag) { // Promise true if signature was made by tag, else false.
    let verifyingKey = await Vault.verifyingKey(tag);
    return MultiKrypto.verify(verifyingKey, signature);
  },
  async encrypt(tag, message) { // Promise text that can only be decrypted back to message by the keypair designated by tag.
    let encryptingKey = await Vault.encryptingKey(tag);
    return await MultiKrypto.encrypt(encryptingKey, message);
  },
  async decrypt(tag, encrypted) { // Promise the original text given to encrypt() IFF the current user has access to the keypair designated by tag, else reject.
    let vault = await Vault.ensure(tag);
    return vault.decrypt(encrypted);
  },
  async sign(message, tag) { // Promise a signature for message suitable for verify() IFF the current user has access to the keypair designated by tag, else reject.
    let vault = await Vault.ensure(tag);
    return vault.sign(message);
  },
  async changeMembership(tag, options) {
    let vault = await Vault.ensure(tag);
    return vault.changeMembership(options);
  },
  clear(tag) {
    Vault.clear(tag);
  },
  async destroy(tag, options) { //
    let vault = await Vault.ensure(tag);
    return vault.destroy(options);
  }
};

export default Security;

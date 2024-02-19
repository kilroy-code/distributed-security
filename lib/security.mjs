import MultiKrypto from "./multiKrypto.mjs";
import {Vault, DeviceVault, RecoveryVault, TeamVault} from "./vault.mjs";

const Security = {
  set Storage(storage) {
    Vault.Storage = storage;
  },
  set getUserDeviceSecret(thunk) {
    Vault.getUserDeviceSecret = thunk;
  },

  // Promise a signature for message suitable for verify() IFF the current user has access to the keypair designated by tag, else reject.
  async sign(message, options, ...tags) {
    if ('string' === typeof options) options = {tags: [options, ...tags]};
    return Vault.sign(message, options);
  },
  async verify(signature, ...tags) { // Promise true if signature was made by tag, else false.
    if (tags.length === 1 && !signature.startsWith('{')) {
      let verifyingKey = await Vault.verifyingKey(tags[0]);
      return MultiKrypto.verify(verifyingKey, signature);
    }
    return Vault.verifyMultikey(signature, ...tags);
  },
  async encrypt(message, tag) { // Promise text that can only be decrypted back to message by the keypair designated by tag.
    let encryptingKey = await Vault.encryptingKey(tag);
    return await MultiKrypto.encrypt(encryptingKey, message);
  },
  async decrypt(encrypted, tag) { // Promise the original text given to encrypt() IFF the current user has access to the keypair designated by tag, else reject.
    let vault = await Vault.ensure(tag);
    return vault.decrypt(encrypted);
  },

  async create(...members) { // ...
    if (!members.length) return await DeviceVault.create();
    let prompt = members[0].prompt;
    if (prompt) return await RecoveryVault.create(prompt);
    return await TeamVault.create(members);
  },
  async changeMembership({tag, ...options}) {
    let vault = await Vault.ensure(tag);
    return vault.changeMembership(options);
  },
  async destroy(tagOrOptions) {
    if ('string' === typeof tagOrOptions) tagOrOptions = {tag: tagOrOptions};
    let {tag, ...options} = tagOrOptions;
    let vault = await Vault.ensure(tag);
    return vault.destroy(options);
  },
  clear(tag) {
    Vault.clear(tag);
  }
};

export default Security;

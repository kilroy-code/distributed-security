import MultiKrypto from "./multiKrypto.mjs";
import {Vault, DeviceVault, RecoveryVault, TeamVault} from "./vault.mjs";

const Security = {
  set Storage(storage) {
    Vault.Storage = storage;
  },
  set getUserDeviceSecret(thunk) {
    Vault.getUserDeviceSecret = thunk;
  },

  async sign(message, ...rest) {
    let options = {}, tags = this.canonicalizeParameters(rest, options);
    return Vault.sign(message, {tags, ...options});
  },
  async verify(signature, ...rest) { // Promise true if signature was made by tag, else false.
    let options = {}, tags = this.canonicalizeParameters(rest, options);
    return Vault.verify(signature, tags, options);
  },
  async encrypt(message, ...rest) { // Promise text that can only be decrypted back to message by the keypair designated by tag.
    let encryptingKey, options = {}, tags = this.canonicalizeParameters(rest, options);
    if (tags.length === 1) {
      let tag = tags[0];
      encryptingKey = await Vault.encryptingKey(tag);
      options.kid = tag;
    } else {
      encryptingKey = {};
      let keys = await Promise.all(tags.map(tag => Vault.encryptingKey(tag)));
      // This isn't done in one step, because we'd like (for debugging and unit tests) to maintain a predictable order.
      tags.forEach((tag, index) => encryptingKey[tag] = keys[index]);
    }
    return MultiKrypto.encrypt(encryptingKey, message, options);
  },
  async decrypt(encrypted, ...rest) { // Promise the original text given to encrypt() IFF the current user has access to the keypair designated by tag, else reject.
    let options = {},
	[tag] = this.canonicalizeParameters(rest, options),
	vault = await Vault.ensure(tag);
    return vault.decrypt(encrypted, options);
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
  },

  canonicalizeParameters(rest, options) { // Return the actual list of tags and bash options.
    let tags = rest;
    let first = rest[0];
    if ((first.tags || first.team) && !rest[1]) {
      let {tags:specifiedTags = [], contentType, time, ...others} = first;
      tags = specifiedTags;
      if (contentType) options.cty = contentType;
      if (time) options.iat = time;
      Object.assign(options, others);
    }
    return tags;
  }
};

export default Security;
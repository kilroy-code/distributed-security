import MultiKrypto from "./multiKrypto.mjs";
import {KeySet, DeviceKeySet, RecoveryKeySet, TeamKeySet} from "./keySet.mjs";


const Security = { // This is the api for the vault. See https://kilroy-code.github.io/distributed-security/docs/implementation.html#creating-the-vault-web-worker-and-iframe

  // Client-defined resources.
  set Storage(storage) {
    KeySet.Storage = storage;
  },
  set getUserDeviceSecret(thunk) {
    KeySet.getUserDeviceSecret = thunk;
  },

  // The four basic operations. ...rest may be one or more tags, or may be {tags, team, member, contentType, ...}
  async sign(message, ...rest) {
    let options = {}, tags = this.canonicalizeParameters(rest, options);
    return KeySet.sign(message, {tags, ...options});
  },
  async verify(signature, ...rest) { // Promise true if signature was made by tag, else false.
    let options = {}, tags = this.canonicalizeParameters(rest, options);
    return KeySet.verify(signature, tags, options);
  },
  async encrypt(message, ...rest) { // Promise text that can only be decrypted back to message by the keypair designated by tag.
    let encryptingKey, options = {}, tags = this.canonicalizeParameters(rest, options);
    if (tags.length === 1) {
      let tag = tags[0];
      encryptingKey = await KeySet.encryptingKey(tag);
      options.kid = tag;
    } else {
      encryptingKey = {};
      let keys = await Promise.all(tags.map(tag => KeySet.encryptingKey(tag)));
      // This isn't done in one step, because we'd like (for debugging and unit tests) to maintain a predictable order.
      tags.forEach((tag, index) => encryptingKey[tag] = keys[index]);
    }
    return MultiKrypto.encrypt(encryptingKey, message, options);
  },
  async decrypt(encrypted, ...rest) { // Promise the original text given to encrypt() IFF the current user has access to the keypair designated by tag, else reject.
    let options = {},
	[tag] = this.canonicalizeParameters(rest, options),
	vault = await KeySet.ensure(tag);
    return vault.decrypt(encrypted, options);
  },

  // Tag maintance.
  async create(...members) { // Promise a newly-created tag with the given members. The member tags (if any) must already exist.
    if (!members.length) return await DeviceKeySet.create();
    let prompt = members[0].prompt;
    if (prompt) return await RecoveryKeySet.create(prompt);
    return await TeamKeySet.create(members);
  },
  async changeMembership({tag, ...options}) { // Promise to add or remove members.
    let vault = await KeySet.ensure(tag);
    return vault.changeMembership(options);
  },
  async destroy(tagOrOptions) { // Promise to remove the tag and any associated data from all storage.
    if ('string' === typeof tagOrOptions) tagOrOptions = {tag: tagOrOptions};
    let {tag, ...options} = tagOrOptions;
    let vault = await KeySet.ensure(tag);
    return vault.destroy(options);
  },
  clear(tag) { // Remove any locally cached KeySet for the tag, or all KeySets if not tag specified.
    KeySet.clear(tag);
  },

  canonicalizeParameters(rest, options) { // Return the actual list of tags, and bash options.
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

import MultiKrypto from "./multiKrypto.mjs";
import {KeySet, DeviceKeySet, RecoveryKeySet, TeamKeySet} from "./keySet.mjs";
import * as pkg from "../package.json" assert { type: 'json' };
const {name, version} = pkg.default;

const Security = { // This is the api for the vault. See https://kilroy-code.github.io/distributed-security/docs/implementation.html#creating-the-vault-web-worker-and-iframe

  // Client-defined resources.
  set Storage(storage) {
    KeySet.Storage = storage;
  },
  set getUserDeviceSecret(thunk) {
    KeySet.getUserDeviceSecret = thunk;
  },
  ready: {name, version},

  // The four basic operations. ...rest may be one or more tags, or may be {tags, team, member, contentType, ...}
  async encrypt(message, ...rest) { // Promise a JWE.
    let options = {}, tags = this.canonicalizeParameters(rest, options),
	key = await KeySet.produceKey(tags, tag => KeySet.encryptingKey(tag), options);
    return MultiKrypto.encrypt(key, message, options);
  },
  async decrypt(encrypted, ...rest) { // Promise {payload, text, json} as appropriate.
    let options = {},
	[tag] = this.canonicalizeParameters(rest, options, encrypted),
	vault = await KeySet.ensure(tag);
    return vault.decrypt(encrypted, options);
  },
  async sign(message, ...rest) { // Promise a JWS.
    let options = {}, tags = this.canonicalizeParameters(rest, options);
    return KeySet.sign(message, {tags, ...options});
  },
  async verify(signature, ...rest) { // Promise {payload, text, json} as appropriate.
    let options = {}, tags = this.canonicalizeParameters(rest, options, signature);
    return KeySet.verify(signature, tags, options);
  },

  // Tag maintance.
  async create(...members) { // Promise a newly-created tag with the given members. The member tags (if any) must already exist.
    if (!members.length) return await DeviceKeySet.create([]);
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

  decodeProtectedHeader: MultiKrypto.decodeProtectedHeader,
  canonicalizeParameters(rest, options, token) { // Return the actual list of tags, and bash options.
    let tags = rest,
	first = rest[0] || (token && (token.recipients?.[0].header || this.decodeProtectedHeader(token.signatures?.[0] || token)).kid);
    if ((first.tags || first.team) && !rest[1]) {
      let {tags:specifiedTags = [], contentType, time, ...others} = first;
      tags = specifiedTags;
      if (contentType) options.cty = contentType;
      if (time) options.iat = time;
      Object.assign(options, others);
    } else if (first && !tags.includes(first)) tags.push(first);
    return tags;
  }
};

export default Security;

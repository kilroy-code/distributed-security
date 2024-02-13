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
  async sign(message, ...tags) {
    let iss, act;
    if (tags[0]?.team) {
      let {team, member} = tags[0];
      iss = team;
      act = member;
      tags = tags.slice(1);
      if (-1 === tags.indexOf(team)) tags.push(team);
      if (-1 === tags.indexOf(member)) tags.push(member);
    }
    if (tags.length === 1) {
      let vault = await Vault.ensure(tags[0]);
      return vault.sign(message);
    }
    let baseHeader = {iss, act},
	jws = MultiKrypto.startSign(baseHeader, message),
	promises = tags.map(async tag => {
	  let vault = await Vault.ensure(tag);
	  vault.signMultikey(baseHeader, jws);
	});
    await Promise.all(promises);
    return await MultiKrypto.finishSignature(jws);
  },
  async verify(signature, ...tags) { // Promise true if signature was made by tag, else false.
    if (tags.length === 1) {
      let verifyingKey = await Vault.verifyingKey(tags[0]);
      return MultiKrypto.verify(verifyingKey, signature);
    }
    let key = {};
    await Promise.all(tags.map(async tag => key[tag] = await Vault.verifyingKey(tag)));
    let result = await MultiKrypto.verify(key, signature),
	{iss, act} = result?.protectedHeader || {};
    // When iss or act are specified in sign(), we always include the sigs. But externally created signatures might not.
    if (iss && !result?.headers.find(sub => sub.kid === iss)) return;
    if (act && !result?.headers.find(sub => sub.kid === act)) return;

    if (iss && act && !(await Vault.isCurrentMember(act, iss))) return;
    return result;
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

import * as JOSE from '../node_modules/jose/dist/browser/index.js';
import MultiKrypto from './multiKrypto.mjs';
import LocalStore from './store.mjs';
import {isEmptyJWS} from './payload-utilities.mjs';

function error(templateFunction, tag, cause = undefined) {
  // Formats tag (e.g., shortens it) and gives it to templateFunction(tag) to get
  // a suitable error message. Answers a rejected promise with that Error.
  let shortenedTag = tag.slice(0, 16) + "...",
      message = templateFunction(shortenedTag);
  return Promise.reject(new Error(message, {cause}));
}
function unavailable(tag) { // Do we want to distinguish between a tag being
  // unavailable at all, vs just the public encryption key being unavailable?
  // Right now we do not distinguish, and use this for both.
  return error(tag => `The tag ${tag} is not available.`, tag);
}
function combineHeader(key, existing, proposed) { // Return a new value for key, or throw an error if it conflicts.
  if (!existing) return proposed;
  if (existing !== proposed) throw new Error(`${proposed} conflicts with ${existing} for ${key} header.`);
  return existing;
}

export class Vault {

  // A Vault maintains two private keys: signingKey and decryptingKey.
  sign(message) { // Promise a signature of message, using our private key.
    return MultiKrypto.sign(this.signingKey, message);
  }
  signMultikey(baseHeader, jws) { // Not the whole signature, just bashes ours into jws.
    let {tag, signingKey} = this;
    MultiKrypto.addSignature(baseHeader, tag, signingKey, jws);
  }
  static async verifyMultikey(jws, ...tags) {
    if (!jws.startsWith('{')) return;
    let key = {}, team, member;
    JSON.parse(jws).signatures.forEach(sub => {
      let {iss, act, kid} = JOSE.decodeProtectedHeader(sub);
      team = combineHeader('iss', team, iss);
      member = combineHeader('act', member, act);
      if (kid && !tags.includes(kid)) tags.push(kid);
    });
    if (team && !tags.includes(team)) tags.push(team);
    if (member && !tags.includes(member)) tags.push(member);
    await Promise.all(tags.map(async tag => key[tag] = await Vault.verifyingKey(tag)));
    let result = await MultiKrypto.verify(key, jws);
    if (result.signers.length !== Object.keys(key).length) return;
    if (team && member && !(await Vault.isCurrentMemberOrEmptyTeam(member, team))) return;
    return result;
  }
  decrypt(encrypted) { // Promise cleartext corresponding to encrypted, using our private key.
    return MultiKrypto.decrypt(this.decryptingKey, encrypted);
  }
  decryptMultikey(multikeyEncrypted) { // If we are a member.
    let {tag, decryptingKey} = this,
	multiKey = {[tag]: decryptingKey};
    return MultiKrypto.decrypt(multiKey, multikeyEncrypted);
  }

  // The corresponding public keys are available publically, outside the vault.
  static verifyingKey(tag) { // Promise the ordinary singular public key corresponding to the signing key, directly from the tag without reference to storage.
    return MultiKrypto.importRaw(tag).catch(_ => unavailable(tag));
  }
  static async encryptingKey(tag) { // Promise the ordinary singular public key corresponding to the decryption key, which depends on public storage.
    let exportedPublicKey = await this.retrieve('EncryptionKey', tag);
    if (!exportedPublicKey) return unavailable(tag);
    return await MultiKrypto.importJWK(JSON.parse(exportedPublicKey));
  }

  static async createKeys() { // Promise a new tag and private keys, and store the encrypting key.
    let {publicKey:verifyingKey, privateKey:signingKey} = await MultiKrypto.generateSigningKey(),
	{publicKey:encryptingKey, privateKey:decryptingKey} = await MultiKrypto.generateEncryptingKey(),
	exportedEncryptingKey = JSON.stringify(await MultiKrypto.exportJWK(encryptingKey)),
	signature = await MultiKrypto.sign(signingKey, exportedEncryptingKey),
	tag = await MultiKrypto.exportRaw(verifyingKey);
    await this.store('EncryptionKey', tag, signature);
    return {signingKey, decryptingKey, tag};
  }
  static vaults = {};
  static clear(tag = null) { // Remove all vault instances or just the specified one, but does not destroy their storage.
    if (!tag) return Vault.vaults = {};
    delete Vault.vaults[tag]
  }
  constructor(tag) {
    this.tag = tag;
    this.memberTags = []; // Used when recursively destroying.
    Vault.vaults[tag] = this;
  }
  static getWrapped(tag) { // Promise the wrapped key appropriate for this class.
    return this.retrieve(this.collection, tag);
  }
  static setWrapped(tag, signature) { // Promise to persist the wrapped key appropriately for this class.
    return this.store(this.collection, tag, signature);
  }
  async setUnwrapped() { // Promise to unwrap our cached keys, if we can, else error.
    let {tag, cached} = this;
    try {
      let unwrapped = await this.unwrap(cached);
      return Object.assign(this, unwrapped);
    } catch (cause) {
      this.constructor.clear(tag);
      return error(tag => `You do not have access to the private key for ${tag}.`, tag, cause);
    }
  }
  static async ensure(tag) { // Promise to resolve to a valid vault, else reject.
    let vault = Vault.vaults[tag],
	stored = await DeviceVault.getWrapped(tag);
    if (stored) {
      vault = new DeviceVault(tag);
    } else if (stored = await TeamVault.getWrapped(tag)) {
      vault = new TeamVault(tag);
    } else if (stored = await RecoveryVault.getWrapped(tag)) {
      vault = new RecoveryVault(tag);
    }
    // If things haven't changed, don't bother with setUnwrapped.
    if (vault?.cached && vault.cached === stored && vault.decryptingKey && vault.signingKey) return vault;
    if (stored) vault.cached = stored;
    else { // Not found. Could be a bogus tag, or one on another computer.
      this.clear(tag);
      return unavailable(tag);
    }
    return vault.setUnwrapped();
  }
  static async create(wrappingData) { // Create a persisted Vault of the correct type, promising the newly created tag.
    let keys = await this.createKeys(),
	{tag} = keys;
    await this.persist(tag, keys, wrappingData);
    return tag;
  }
  static async persist(tag, keys, wrappingData) { // Promise to wrap a set of keys for the wrappingData members, and persist by tag.
    let {signingKey} = keys,
	wrapped = await this.wrap(keys, wrappingData),
	signature = await MultiKrypto.sign(signingKey, wrapped);
    //if (wrappingData && Array.isArray(wrappingData) && wrappingData.every(item => 'string' === typeof item)) console.log(wrappingData.map(tag => Vault.vaults[tag])); // fixme remove
    await this.setWrapped(tag, signature);
  }
  async destroy(options = {}) { // Terminates this vault and associated storage, and same for OWNED recursiveMembers if asked.
    let {tag} = this,
	content = "", // Should storage have a separate operation to delete, other than storing empty?
	signature = await this.sign(content);
    await this.constructor.store('EncryptionKey', tag, signature);
    await this.constructor.store(this.constructor.collection, tag, signature);
    this.constructor.clear(tag);
    if (!options.recursiveMembers) return;
    await Promise.allSettled(this.memberTags.map(async memberTag => {
      let memberVault = await Vault.ensure(memberTag);
      await memberVault.destroy(options);
    }));
  }

  static async fixmeVerify(signature, tag) {
    if (!signature) return;
    if (signature.startsWith('{')) return this.verifyMultikey(signature, tag);
    return MultiKrypto.verify(await Vault.verifyingKey(tag), signature);
  }
  // static fixmePayload(signature) {
  //   if (!signature) return '';
  //   return new TextDecoder().decode(JOSE.base64url.decode(signature.split('.')[1]));
  // }
  static async store(collectionName, tag, signature) {
    if (collectionName === DeviceVault.collection) {
      // We called this. No need to verify here. But see retrieve().
      if (isEmptyJWS(signature)) LocalStore.remove(tag);
      else LocalStore.store(tag, signature);
      return;
    }
    return Vault.Storage.store(collectionName, tag, signature);
  }
  static async retrieve(collectionName, tag) {
    let jwsPromise = (collectionName === DeviceVault.collection) ? LocalStore.retrieve(tag) : Vault.Storage.retrieve(collectionName, tag),
	jws = await jwsPromise,
	// We could just crack the jws open and yank out the payload
	// without verifying. But verifying allows us to be sure that
	// no one has messed with the data, with in the cloud or persisted locally.
	verified = await this.fixmeVerify(jws, tag),
	payload = verified?.text;
    return payload;
  }
  static async isCurrentMemberOrEmptyTeam(memberTag, teamTag) {
    // Promise to answer whether memberTag is either currently a member of teamTag, or if there is no current team.
    // This does not require that we ourselves be a member, so we cannot go trying to build the specified Vaults.
    // Furthermore, we must not use any cached definitions.
    let teamData = await this.retrieve(TeamVault.collection, teamTag);
    if (!teamData) return true; // !
    return JSON.parse(teamData).recipients.find(member => member.header.kid === memberTag);
  }
}

export class SecretVault extends Vault { // Keys are encrypted based on a symmetric secret.
  static async wrap(keys, wrappingData = '') {
    if (wrappingData.includes(MultiKrypto.concatChar)) return Promise.reject("Cannot create recovery tag with a prompt that contains '~'.");
    let {decryptingKey, signingKey, tag} = keys,
	vaultKey = {decryptingKey, signingKey},

	wrappingKey = {[wrappingData]: await this.getSecret(tag, wrappingData)};
    return MultiKrypto.wrapKey(vaultKey, wrappingKey);
  }
  async unwrap(wrapped) {
    let wrappedKey = wrapped;
    let parsed = JSON.parse(wrappedKey),
 	prompt = parsed.recipients[0].header.kid,
	secret = {[prompt]: await this.constructor.getSecret(this.tag, prompt)},
	exported = JSON.parse(await MultiKrypto.decrypt(secret, wrappedKey));
    return await MultiKrypto.importJWK(exported, {decryptingKey: 'decrypt', signingKey: 'sign'});
  }
  static async getSecret(tag, /*iv, */prompt) {
    return Vault.getUserDeviceSecret(tag, prompt);
  }
}

 // The user's answer(s) to a security question forms a secret, and the wrapped keys is stored in the cloude.
export class RecoveryVault extends SecretVault {
  static collection = 'KeyRecovery';
}

// A Vault corresponding to the current hardware. Wrapping secret comes from the app.
export class DeviceVault extends SecretVault {
  static collection = 'Device';
}

export class TeamVault extends Vault { // A Vault corresponding to a team of which the current user is a member (if getTag()).
  static collection = 'Team';
  static async wrap(keys, members) {
    // This is used by persist, which in turn is used to create and changeMembership.
    let {decryptingKey, signingKey, tag} = keys,
	teamKey = {decryptingKey, signingKey},
	wrappingKey = {};
    await Promise.all(members.map(memberTag => Vault.encryptingKey(memberTag).then(key => wrappingKey[memberTag] = key)));
    let wrappedTeam = await MultiKrypto.wrapKey(teamKey, wrappingKey);
    return wrappedTeam;
  }
  async unwrap(wrapped) {
    let {recipients} = JSON.parse(wrapped),
	memberTags = this.memberTags = recipients.map(recipient => recipient.header.kid),
	// We will use recovery tags only if we need to. First step is to identify them.
	// TODO: optimize this. E.g., determine recovery tags at creation and identify them in wrapped.
	recoveryWraps = await Promise.all(memberTags.map(tag => RecoveryVault.getWrapped(tag).catch(_ => null))),
	recoveryTags = memberTags.filter((tag, index) => recoveryWraps[index]),
	nonRecoveryTags = memberTags.filter(tag => !recoveryTags.includes(tag));
    let vault = await Promise.any(nonRecoveryTags.map(memberTag => Vault.ensure(memberTag)))
	.catch(async reason => { // If we failed, use the recovery tags, if any, one at a time.
	  for (let recovery of recoveryTags) {
	    let vault = await Vault.ensure(recovery).catch(_ => null);
	    if (vault) return vault;
	  }
	  return reason;
      });
    let decrypted = await vault.decryptMultikey(wrapped);
    return await MultiKrypto.importJWK(JSON.parse(decrypted));
  }
  async changeMembership({add = [], remove = []} = {}) {
    let memberTags = this.memberTags = this.memberTags.concat(add).filter(tag => !remove.includes(tag));
    await this.constructor.persist(this.tag, this, memberTags);
  }
}

LocalStore.collectionName = DeviceVault.collection;

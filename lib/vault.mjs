import * as JOSE from "../dependency/jose.mjs";
import MultiKrypto from "./multiKrypto.mjs";
import LocalCollection from "./store.mjs";
import {isEmptyJWS} from "./payload-utilities.mjs";

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

  static async sign(message, original) {
    // memberTags and signingKey can be passed in so that this can be used in signing our own keys
    // for storage as the vault is beging created, at which point, we cannot call Vault.ensure!
    let {tags = [], team:iss, member:act, time:iat, memberTags, signingKey, ...options} = original;
    if ((iat === undefined) && iss) iat = Date.now();
    if (iss && !act) { // Supply the value
      if (!memberTags) memberTags = (await Vault.ensure(iss)).memberTags;
      let cachedMember = memberTags.find(tag => Vault.vaults[tag]);
      act = cachedMember || await Promise.any(memberTags.map(tag => Vault.ensure(tag))).then(vault => vault.tag)
    }
    if (iss && !tags.includes(iss)) tags = [iss, ...tags]; // Must be first
    if (act && !tags.includes(act)) tags = [...tags, act];
    if (!act && tags.length === 1) {
      if (!signingKey) signingKey = (await Vault.ensure(tags[0])).signingKey;
      return MultiKrypto.sign(signingKey, message, {iat, ...options});
    }
    let baseHeader = {iss, act, iat, ...options},
	jws = MultiKrypto.startSign(baseHeader, message),
	promises = tags.map(async tag => {
	  if (!signingKey) signingKey = (await Vault.ensure(tag)).signingKey;
	  MultiKrypto.addSignature(baseHeader, tag, signingKey, jws);
	  signingKey = undefined;
	});
    await Promise.all(promises);
    return await MultiKrypto.finishSignature(jws);
  }

  static async verify(signature, tags, options) {
    let key;
    if (options.team && !tags.includes(options.team)) tags = [options.team, ...tags];
    if (!signature.startsWith('{')) {
      if (tags.length === 1) {
	key = await Vault.verifyingKey(tags[0]);
      } else return;
    } else {
      key = {};
      await Promise.all(tags.map(async tag => key[tag] = await Vault.verifyingKey(tag)));
    }
    let result = await MultiKrypto.verify(key, signature, options),
	memberTag = options.member === undefined ? result?.protectedHeader.act : options.member,
	notBefore = options.notBefore;
    if (!result) return;
    if (memberTag) {
      if (options.member === 'team') {
	memberTag = result.protecteHeader.act;
	if (!memberTag) return;
      }
      if (!tags.includes(memberTag)) { // Add to tags and result if not already present
	let memberKey = await Vault.verifyingKey(memberTag),
	    memberMultikey = {[memberTag]: memberKey},
	    aux = await MultiKrypto.verify(memberMultikey, signature, options);
	if (!aux) return;
	tags.push(memberTag);
	result.signers.find(signer => signer.protectedHeader.kid === memberTag).payload = result.payload;
      }
    }
    if (memberTag || notBefore === 'team') {
      let teamTag = result.protectedHeader.iss,
	  verfiedJWS = await this.retrieve(TeamVault.collection, teamTag, 'raw'),
	  jwe = verfiedJWS && JSON.parse(verfiedJWS.text);
      if (memberTag && !teamTag) return;
      if (memberTag && jwe && !jwe.recipients.find(member => member.header.kid === memberTag)) return;
      if (notBefore === 'team') notBefore = verfiedJWS?.protectedHeader.iat;
    }
    if (notBefore) {
      let {iat} = result.protectedHeader;
      if (iat < notBefore) return;
    }
    // Each signer should now be verified.
    if ((result.signers?.filter(signer => signer.payload).length || 1) !== tags.length) return;
    return result;
  }
  decrypt(encrypted, options) { // Promise cleartext corresponding to encrypted, using our private key.
    let key;
    if (encrypted.startsWith('{')) {
      let {tag, decryptingKey} = this;
      key = {[tag]: decryptingKey};
    } else {
      key = this.decryptingKey;
    }
    return MultiKrypto.decrypt(key, encrypted, options);
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

  static async createKeys(memberTags) { // Promise a new tag and private keys, and store the encrypting key.
    let {publicKey:verifyingKey, privateKey:signingKey} = await MultiKrypto.generateSigningKey(),
	{publicKey:encryptingKey, privateKey:decryptingKey} = await MultiKrypto.generateEncryptingKey(),
	tag = await MultiKrypto.exportRaw(verifyingKey),
	exportedEncryptingKey = JSON.stringify(await MultiKrypto.exportJWK(encryptingKey)),
	time = Date.now(),
	signature = await this.signForStorage({message: exportedEncryptingKey, tag, signingKey, memberTags, time});
    await this.store('EncryptionKey', tag, signature);
    return {signingKey, decryptingKey, tag, time};
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
  static async setWrapped(tag, signature) { // Promise to persist the wrapped key appropriately for this class.
    await this.store(this.collection, tag, signature);
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
    let {time, ...keys} = await this.createKeys(wrappingData),
	{tag} = keys;
    await this.persist(tag, keys, wrappingData, time);
    return tag;
  }
  static async persist(tag, keys, wrappingData, time = Date.now()) { // Promise to wrap a set of keys for the wrappingData members, and persist by tag.
    let {signingKey} = keys,
	wrapped = await this.wrap(keys, wrappingData),
	signature = await this.signForStorage({message: wrapped, tag, signingKey, memberTags: wrappingData, time});
    await this.setWrapped(tag, signature);
  }
  async destroy(options = {}) { // Terminates this vault and associated storage, and same for OWNED recursiveMembers if asked.
    let {tag, memberTags, signingKey} = this,
	content = "", // Should storage have a separate operation to delete, other than storing empty?
	signature = await this.constructor.signForStorage({message: content, tag, memberTags, signingKey, time: Date.now()});
    await this.constructor.store('EncryptionKey', tag, signature);
    await this.constructor.store(this.constructor.collection, tag, signature);
    this.constructor.clear(tag);
    if (!options.recursiveMembers) return;
    await Promise.allSettled(this.memberTags.map(async memberTag => {
      let memberVault = await Vault.ensure(memberTag);
      await memberVault.destroy(options);
    }));
  }

  static async store(collectionName, tag, signature) {
    if (collectionName === DeviceVault.collection) {
      // We called this. No need to verify here. But see retrieve().
      if (isEmptyJWS(signature)) LocalStore.remove(tag);
      else LocalStore.store(tag, signature);
      return;
    }
    return Vault.Storage.store(collectionName, tag, signature);
  }
  static async retrieve(collectionName, tag, raw = false) {
    let promise = (collectionName === DeviceVault.collection) ? LocalStore.retrieve(tag) : Vault.Storage.retrieve(collectionName, tag),
	signature = await promise,
	key = signature && await Vault.verifyingKey(tag);
    if (!signature) return;
    // While we rely on the Storage and LocalStore implementations to deeply check signatures during write,
    // here we still do a shallow verification check just to make sure that the data hasn't been messed with after write.
    if (signature.startsWith('{')) key = {[tag]: key}; // Prepare a multi-key
    let verfied = await MultiKrypto.verify(key, signature);
    return raw ? verfied : verfied.text;
  }
}

export class SecretVault extends Vault { // Keys are encrypted based on a symmetric secret.
  static signForStorage({message, tag, signingKey, time}) {
    // Create a simple signature that does not specify iss or act.
    // There are no true memberTags to pass on and they are not used in simple signatures. However, the caller does
    // generically pass wrappingData as memberTags, and for RecoveryVaults, wrappingData is the prompt. 
    // We don't store multiple times, so there's also no need for iat (which can be used to prevent replay attacks).
    return this.sign(message, {tags: [tag], signingKey, time});
  }
  static async wrap(keys, wrappingData = '') {
    if (wrappingData.includes(MultiKrypto.concatChar)) return Promise.reject("Cannot create recovery tag with a prompt that contains '~'.");
    let {decryptingKey, signingKey, tag} = keys,
	vaultKey = {decryptingKey, signingKey},

	wrappingKey = {[wrappingData]: await this.getSecret(tag, wrappingData)};
    return MultiKrypto.wrapKey(vaultKey, wrappingKey);
  }
  async unwrap(wrappedKey) {
    let parsed = JSON.parse(wrappedKey),
 	prompt = parsed.recipients[0].header.kid,
	secret = {[prompt]: await this.constructor.getSecret(this.tag, prompt)},
	exported = JSON.parse(await MultiKrypto.decrypt(secret, wrappedKey));
    return await MultiKrypto.importJWK(exported, {decryptingKey: 'decrypt', signingKey: 'sign'});
  }
  static async getSecret(tag, prompt) {
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
const LocalStore = new LocalCollection({collectionName: DeviceVault.collection});

export class TeamVault extends Vault { // A Vault corresponding to a team of which the current user is a member (if getTag()).
  static collection = 'Team';
  static signForStorage({message, tag, ...options}) {
    return this.sign(message, {team: tag, ...options});
  }
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
    let decrypted = await vault.decrypt(wrapped);
    return await MultiKrypto.importJWK(JSON.parse(decrypted));
  }
  async changeMembership({add = [], remove = []} = {}) {
    let memberTags = this.memberTags = this.memberTags.concat(add).filter(tag => !remove.includes(tag));
    await this.constructor.persist(this.tag, this, memberTags);
  }
}

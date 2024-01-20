import MultiKrypto from "./multiKrypto.mjs";

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

export class Vault {

  // A Vault maintains two private keys: signingKey and decryptingKey.
  sign(message) { // Promise a signature of message, using our private key.
    return MultiKrypto.sign(this.signingKey, message);
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
    return MultiKrypto.importKey(tag, 'verify').catch(_ => unavailable(tag));
  }
  static async encryptingKey(tag) { // Promise the ordinary singular public key corresponding to the decryption key, which depends on public storage.
    // Doing a multi-key encryption requires more space for the encryption, and so we don't encrypt EVERY message to be directly decryptable
    // by members. Instead, we only encrypt (wrap) the TeamVault's key to be readable by each member.
    let exportedPublicKey = await Vault.Storage.retrieve('EncryptionKey', tag);
    if (!exportedPublicKey) return unavailable(tag);
    return await MultiKrypto.importKey(exportedPublicKey, 'encrypt');
  }

  static async createKeys() { // Promise a new tag and private keys, and store the encrypting key.
    let {publicKey:verifyingKey, privateKey:signingKey} = await MultiKrypto.generateSigningKey(),
	{publicKey:encryptingKey, privateKey:decryptingKey} = await MultiKrypto.generateEncryptingKey(),
	exportedEncryptingKey = await MultiKrypto.exportKey(encryptingKey),
	signature = await MultiKrypto.sign(signingKey, exportedEncryptingKey),
	tag = await MultiKrypto.exportKey(verifyingKey);
    await Vault.Storage.store('EncryptionKey', tag, exportedEncryptingKey, signature);
    return {signingKey, decryptingKey, tag};
  }
  static vaults = {};
  static clear(tag = null) { // Remove all vault instances or just the specified one, but does not destory their storage.
    if (!tag) return this.vaults = {};
    delete this.vaults[tag]
  }
  constructor(tag) {
    this.tag = tag;
    this.memberTags = []; // Used when recursively destroying.
    Vault.vaults[tag] = this;
  }
  static getWrapped(tag) {
    return Vault.Storage.retrieve(this.collection, tag);
  }
  static setWrapped(tag, wrapped, signature) {
    return Vault.Storage.store(this.collection, tag, wrapped, signature);
  }
  async setUnwrapped() {
    let {tag, stored} = this;
    try {
      let unwrapped = await this.unwrap(stored);
      return Object.assign(this, unwrapped);
    } catch (cause) {
      this.constructor.clear(tag);
      return error(tag => `You do not have access to the private key for ${tag}.`, tag, cause);
    }
  }
  static async ensure(tag) { // Promise to resolve to a valid vault, else reject.
    let vault = this.vaults[tag],
	stored = await DeviceVault.getWrapped(tag);
    if (stored) {
      vault = new DeviceVault(tag);
    } else if (stored = await TeamVault.getWrapped(tag)) {
      vault = new TeamVault(tag);
    } else if (stored = await RecoveryVault.getWrapped(tag)) {
      vault = new RecoveryVault(tag);
    }
    // If things haven't changed, don't bother with setUnwrapped.
    if (vault?.stored && vault.stored === stored && vault.decryptingKey && vault.signingKey) return vault;
    if (stored) vault.stored = stored;
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
  static async persist(tag, keys, wrappingData) {
    let {signingKey} = keys,
	wrapped = await this.wrap(keys, wrappingData),
	signature = await MultiKrypto.sign(signingKey, wrapped);
    await this.setWrapped(tag, wrapped, signature);
  }
  async destroy(options = {}) { // Terminates this vault and associated storage, and same for OWNED recursiveMembers if asked.
    let {tag} = this,
	content = "", // Should storage have a separate operation to delete, other than storing empty?
	signature = await this.sign(content);
    await Vault.Storage.store('EncryptionKey', tag, content, signature);
    await Vault.Storage.store(this.constructor.collection, tag, content, signature);
    this.constructor.clear(tag);
    if (!options.recursiveMembers) return;
    await Promise.allSettled(this.memberTags.map(async memberTag => {
      let memberVault = await Vault.ensure(memberTag);
      await memberVault.destroy(options);
    }));
  }
}

export class SecretVault extends Vault { // Keys are encrypted based on a symmetric secret.
  static async wrap(keys, wrappingData = '') {
    if (wrappingData.includes(MultiKrypto.concatChar)) return Promise.reject("Cannot create recovery tag with a prompt that contains '~'.");
    let {decryptingKey, signingKey, tag} = keys,
	vaultKey = {decryptingKey, signingKey},
	exported = await MultiKrypto.exportKey(vaultKey),
	iv = MultiKrypto.arrayBuffer2base64string(MultiKrypto.iv()),
	secret = await this.getSecret(tag, iv, wrappingData),
	encrypted = await MultiKrypto.encrypt(secret, exported);
    return MultiKrypto.concatBase64(iv, encrypted, wrappingData);
  }
  async unwrap(wrapped) {
    let [iv, wrappedKey, wrappingData] = MultiKrypto.splitBase64(wrapped),
	secret = await this.constructor.getSecret(this.tag, iv, wrappingData),
	exported = await MultiKrypto.decrypt(secret, wrappedKey);
    return await MultiKrypto.importKey(exported, {decryptingKey: 'decrypt', signingKey: 'sign'});
  }
  static async getSecret(tag, iv, prompt) {
    let userDeviceSecret = await Vault.getUserDeviceSecret(tag, prompt);
    return await MultiKrypto.generateSymmetricKey(userDeviceSecret, {salt: tag, iv});
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
	nonRecoveryTags = memberTags.filter(tag => !recoveryTags.includes(tag)),
	use = {decryptingKey: 'decrypt', signingKey: 'sign'};
    let vault = await Promise.any(nonRecoveryTags.map(memberTag => Vault.ensure(memberTag)))
	.catch(async reason => { // If we failed, use the recovery tags, if any, one at a time.
	  for (let recovery of recoveryTags) {
	    let vault = await Vault.ensure(recovery).catch(_ => null);
	    if (vault) return vault;
	  }
	  return reason;
      });
    let decrypted = await vault.decryptMultikey(wrapped);
    return await MultiKrypto.importKey(decrypted, use);
  }
  async changeMembership({add = [], remove = []} = {}) {
    let memberTags = this.memberTags = this.memberTags.concat(add).filter(tag => !remove.includes(tag));
    await this.constructor.persist(this.tag, this, memberTags);
    await this.constructor.clear();
  }
}

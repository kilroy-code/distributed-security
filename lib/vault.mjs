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
  static async encryptingKey(tag) { // Promise the ordinary singular public key corresponding to the decryption key, which depend on public storage.
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
    Vault.vaults[tag] = this;
  }
  static getWrapped(tag) {
    return Vault.Storage.retrieve(this.collection, tag);
  }
  static setWrapped(tag, wrapped, signature) {
    Vault.Storage.store(this.collection, tag, wrapped, signature);
  }
  static async ensure(tag) { // Promise to resolve to a valid vault, else reject.
    let vault = this.vaults[tag],
	stored = await DeviceVault.getWrapped(tag);
    if (stored) {
      vault = new DeviceVault(tag);
    } else {
      stored = await TeamVault.getWrapped(tag);
      vault = new TeamVault(tag);
    }
    if (!stored) {
      this.clear(tag);
      return unavailable(tag);
    }
    try {
      let unwrapped = await vault.unwrap(stored); // FIXME: don't re-init if it hasn't changed
      Object.assign(vault, unwrapped);
    } catch (cause) {
      this.clear(tag);
      return error(tag => `You do not have access to the private key for ${tag}.`, tag, cause);
    }
    return vault;
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
    await this.destroyAux(tag, content, signature);
    this.constructor.clear(tag);
    if (!options.recursiveMembers) return;
    await Promise.allSettled(this.memberTags.map(async memberTag => {
      let memberVault = await Vault.ensure(memberTag);
      await memberVault.destroy(options);
    }));
  }
  destroyAux() { }
}

export class DeviceVault extends Vault { // A Vault corresponding to the current hardware.
  static collection = 'Device';
  static async getSecret(tag, signingKey = null) {
    // Only need to sign when creating, in which case we started with the signingKey
    let userDeviceSecret = await Vault.getUserDeviceSecret(),
	salt = import.meta.url,
	resourceTagForStorage = 'DeviceIV',
	iv = await Vault.Storage.retrieve(resourceTagForStorage, tag);
    if (!iv) {
      if (!signingKey) throw new Error('No stored key for device.');
      iv = MultiKrypto.ab2str(MultiKrypto.iv());
      let signature =  await MultiKrypto.sign(signingKey, iv);
      await Vault.Storage.store(resourceTagForStorage, tag, iv, signature);
    }
    return  await MultiKrypto.generateSymmetricKey(userDeviceSecret, {salt, iv});
  }
  static async wrap(keys) { // FIXME use app-supplied secret
    let {decryptingKey, signingKey, tag} = keys,
	vaultKey = {decryptingKey, signingKey},
	exported = await MultiKrypto.exportKey(vaultKey),
	secret = await this.getSecret(tag, signingKey);
    return await MultiKrypto.encrypt(secret, exported);
  }
  async unwrap(wrapped) {
    let secret = await this.constructor.getSecret(this.tag),
	exported = await MultiKrypto.decrypt(secret, wrapped);
    return await MultiKrypto.importKey(exported, {decryptingKey: 'decrypt', signingKey: 'sign'});
  }
  get memberTags() { return []; }
  async destroyAux(tag, content, signature) {
    await Vault.Storage.store('DeviceIV', tag, content, signature);
  }
}

export class TeamVault extends Vault { // A Vault corresponding to a team of which the current user is a member (if getTag()).
  static collection = 'Team';
  static async wrap(keys, members) { // Create a new publically persisted TeamVault with the specified member tags, promising the newly created tag.
    let {decryptingKey, signingKey, tag} = keys,
	teamKey = {decryptingKey, signingKey},
	wrappingKey = {};
    await Promise.all(members.map(memberTag => Vault.encryptingKey(memberTag).then(key => wrappingKey[memberTag] = key)));
    return await MultiKrypto.wrapKey(teamKey, wrappingKey);
  }
  async unwrap(wrapped) { // fixme verify?
    let {roster} = JSON.parse(wrapped),
	memberTags = this.memberTags = Object.keys(roster),
	firstConfirmedMemberVault = await Promise.any(memberTags.map(memberTag => Vault.ensure(memberTag))),
	use = {decryptingKey: 'decrypt', signingKey: 'sign'},
	// The next two lines are basicall unwrap, but splitting out the decrypt so that strings rather than keys are transported between vaults.
	decrypted = await firstConfirmedMemberVault.decryptMultikey(wrapped);
    return await MultiKrypto.importKey(decrypted, use);
  }
  async changeMembership({add = [], remove = []} = {}) {
    let memberTags = this.memberTags = this.memberTags.concat(add).filter(tag => !remove.includes(tag));
    await this.constructor.persist(this.tag, this, memberTags);
    await this.constructor.clear();
  }
}

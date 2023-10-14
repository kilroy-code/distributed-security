import MultiKrypto from "./multiKrypto.mjs";

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
    return MultiKrypto.importKey(tag, 'verify');
  }
  static async encryptingKey(tag) { // Promise the ordinary singular public key corresponding to the decryption key, which depend on public storage.
    // Doing a multi-key encryption requires more space for the encryption, and so we don't encrypt EVERY message to be directly decryptable
    // by members. Instead, we only encrypt (wrap) the TeamVault's key to be readable by each member.
    let exportedPublicKey = await Vault.Storage.retrieve('EncryptionKey', tag);
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
  constructor(tag) {
    this.tag = tag;
    Vault.vaults[tag] = this;
  }
  static async ensure(tag) { // Promise to resolve to a valid vault, else reject.
    let vault = this.vaults[tag],
	stored = await Vault.Storage.retrieve(DeviceVault.collection, tag);
    if (stored) {
      vault = new DeviceVault(tag);
    } else {
      vault = new TeamVault(tag);
      stored = await Vault.Storage.retrieve(TeamVault.collection, tag)
    }
    try {
      let unwrapped = await vault.unwrap(stored); // FIXME: don't re-init if it hasn't chagned
      Object.assign(vault, unwrapped);
    } catch (e) {
      delete this.vaults[tag];
      throw new Error(`You do not have access to the private key corresponding to ${tag}.`)
    }
    return vault;
  }
  static async create(wrappingData) { // Create a persisted Vault of the correct type, promising the newly created tag.
    let keys = await this.createKeys(),
	{signingKey, tag} = keys,
	wrapped = await this.wrap(keys, wrappingData),
	signature = await MultiKrypto.sign(signingKey, wrapped);
    await Vault.Storage.store(this.collection, tag, wrapped, signature);
    return tag;
  }
  async destroy() { // Terminates this vault and 
    let {tag} = this,
	content = "", // Should storage have a separate operation to delete, other than storing empty?
	signature = await this.sign(content);
    await Vault.Storage.store('EncryptionKey', tag, content, signature);
    await Vault.Storage.store(this.constructor.collection, tag, content, signature);
    delete Vault.vaults[tag];
  }
}

export class DeviceVault extends Vault { // A Vault corresponding to the current hardware.
  static collection = 'Device';
  static async getSecret() { // FIXME use app-supplied secret
    let {secret} = this;
    if (!secret) {
      secret = this.secret = await MultiKrypto.generateEncryptingKey();
    }
    return secret;
  }
  static async wrap(keys) { // FIXME use app-supplied secret
    let {decryptingKey, signingKey, tag} = keys,
	vaultKey = {decryptingKey, signingKey},
	exported = await MultiKrypto.exportKey(vaultKey),
	secret = await this.getSecret();
    return await MultiKrypto.encrypt(secret.publicKey, exported);
  }
  async unwrap(wrapped) {
    let secret = await this.constructor.getSecret(),
	exported = await MultiKrypto.decrypt(secret.privateKey, wrapped);
    return await MultiKrypto.importKey(exported, {decryptingKey: 'decrypt', signingKey: 'sign'});
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
	memberTags = Object.keys(roster),
	firstConfirmedMemberVault = await Promise.any(memberTags.map(memberTag => Vault.ensure(memberTag))),
	use = {decryptingKey: 'decrypt', signingKey: 'sign'},
	// The next two lines are basicall unwrap, but splitting out the decrypt so that strings rather than keys are transported between vaults.
	decrypted = await firstConfirmedMemberVault.decryptMultikey(wrapped);
    return await MultiKrypto.importKey(decrypted, use);
  }
}

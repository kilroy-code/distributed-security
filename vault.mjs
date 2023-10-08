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
	stored = DeviceVault.localStore[tag]; // Check local storage first, because it is fast.
    if (stored) {
      vault = new DeviceVault(tag);
    } else {
      vault = new TeamVault(tag);
      stored = await Vault.Storage.retrieve('Team', tag)
    }
    try {
      await vault.init(stored); // FIXME: don't re-init if it hasn't chagned
    } catch (e) {
      delete this.vaults[tag];
      throw new Error(`You do not have access to the private key corresponding to ${tag}.`)
    }
    return vault;
  }
  async destroy() { // Terminates this vault and 
    let {tag} = this,
	content = "", // Should storage have a separate operation to delete, other than storing empty?
	signature = await this.sign(content); 
    await Vault.Storage.store('EncryptionKey', tag, content, signature);
    delete Vault.vaults[tag];
  }
}

export class DeviceVault extends Vault { // A Vault corresponding to the current hardware.
  static localStore = {}; // fixme
  static async create() { // Create a new locally persisted DeviceVault, promising the newly created tag.
    let {decryptingKey, signingKey, tag} = await Vault.createKeys(),
	vaultKey = {decryptingKey, signingKey},
	exportedKey = await MultiKrypto.exportKey(vaultKey);
    DeviceVault.localStore[tag] = exportedKey;
    return tag;
  }
  async init(exportedKey) {
    Object.assign(this, await MultiKrypto.importKey(exportedKey, {decryptingKey: 'decrypt', signingKey: 'sign'}));
  }
  destroy() {
    delete DeviceVault.localStore[this.tag];
    return super.destroy();
  }
}

export class TeamVault extends Vault { // A Vault corresponding to a team of which the current user is a member (if getTag()).
  static async create(members) { // Create a new publically persisted TeamVault with the specified member tags, promising the newly created tag.
    let {decryptingKey, signingKey, tag} = await Vault.createKeys(),
	teamKey = {decryptingKey, signingKey},
	wrappingKey = {};
    await Promise.all(members.map(memberTag => Vault.encryptingKey(memberTag).then(key => wrappingKey[memberTag] = key)));
    let wrappedKey = await MultiKrypto.wrapKey(teamKey, wrappingKey),
	signature = await MultiKrypto.sign(signingKey, wrappedKey); // Same as Vault.sign(message), but the Vault doesn't exist yet.
    await Vault.Storage.store('Team', tag, wrappedKey, signature);
    return tag;
  }
  async init(wrapped) { // fixme verify?
    let {roster} = JSON.parse(wrapped),
	memberTags = Object.keys(roster),
	firstConfirmedMemberVault = await Promise.any(memberTags.map(memberTag => Vault.ensure(memberTag))),
	use = {decryptingKey: 'decrypt' , signingKey: 'sign'},
	// The next two lines are basicall unwrap, but splitting out the decrypt so that strings rather than keys are transported between vaults.
	decrypted = await firstConfirmedMemberVault.decryptMultikey(wrapped),
	keyData = await MultiKrypto.importKey(decrypted, use);
    Object.assign(this, keyData);
  }
  async destroy() {
    let {tag} = this,
	signature = await this.sign("");
    await Vault.Storage.store('Team', tag, "", signature);
    await super.destroy();
  }
}

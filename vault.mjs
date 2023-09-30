import MultiKrypto from "./multiKrypto.mjs";
import Security from "./security.mjs";

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
    let exportedPublicKey = await Security.retrieve('EncryptionKey', tag);
    return await MultiKrypto.importKey(exportedPublicKey, 'encrypt');
  }

  static async addEncryptionKeys(tag, signingKey) {
    let {publicKey:encryptingKey, privateKey:decryptingKey} = await MultiKrypto.generateEncryptingKey(),
	exportedEncryptingKey = await MultiKrypto.exportKey(encryptingKey),
	signature = await MultiKrypto.sign(signingKey, exportedEncryptingKey);
    await Security.store('EncryptionKey', tag, exportedEncryptingKey, signature);
    return decryptingKey;
  }
  static vaults = {};
  static async ensure(tag) { // Promise to resolve to a valid vault, else reject.
    let vault = this.vaults[tag] || new TeamVault(tag);
    if (await vault?.confirm()) return vault;
    delete this.vaults[tag];
    throw new Error(`You do not have access to the private key corresponding to ${tag}.`)
  }

  async confirm() { // Is this device still authenticated? Answers vault, which is convenient for chaining to answer the tag when true.
    if (this.signingKey) return this;
    await this.init();
    if (this.signingKey) return this;
  }
  async getTag() {
    if (await this.confirm()) return this.tag;
  }
}

export class DeviceVault extends Vault { // A Vault corresponding to the current hardware.
  async init() {
    let {publicKey:verifyingKey, privateKey:signingKey} = await MultiKrypto.generateSigningKey();
    this.signingKey = signingKey;
    let tag = this.tag = await MultiKrypto.exportKey(verifyingKey);
    this.decryptingKey = await Vault.addEncryptionKeys(tag, signingKey);
    Vault.vaults[tag] = this;
  }
}

export class TeamVault extends Vault { // A Vault corresponding to a team of which the current user is a member (if getTag()).
  constructor(tag) {
    super();
    this.tag = tag;
    Vault.vaults[tag] = this;
  }
  static async create(members) {
    let {publicKey:verifyingKey, privateKey:signingKey} = await MultiKrypto.generateSigningKey(),
	tag = await MultiKrypto.exportKey(verifyingKey),
	decryptingKey = await Vault.addEncryptionKeys(tag, signingKey),
	teamKey = {decryptingKey, signingKey},
	wrappingKey = {};
    await Promise.all(members.map(memberTag => Vault.encryptingKey(memberTag).then(key => wrappingKey[memberTag] = key)));
    let wrappedKey = await MultiKrypto.wrapKey(teamKey, wrappingKey),
	signature = await MultiKrypto.sign(signingKey, wrappedKey); // Same as Vault.sign(message), but the Vault doesn't exist yet.
    await Security.store('Team', tag, wrappedKey, signature);
    return tag;
  }
  async init() {
    let wrapped = await Security.retrieve('Team', this.tag), // FIXME: verify?
	{roster} = JSON.parse(wrapped),
	memberTags = Object.keys(roster),
	firstConfirmedMemberVault = await Promise.any(memberTags.map(memberTag => Vault.ensure(memberTag))),
	use = {decryptingKey: 'decrypt' , signingKey: 'sign'},
	// The next two lines are basicall unwrapp, but splitting out they decrypt so that string rather than keys are transported between vaults.
	decrypted = await firstConfirmedMemberVault.decryptMultikey(wrapped),
	keyData = await MultiKrypto.importKey(decrypted, use);
    Object.assign(this, keyData);
  }
}

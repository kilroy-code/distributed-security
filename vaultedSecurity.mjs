import Security from "./security.mjs";

const VaultedSecurity = {
  verify(tag, signature, message) { // Promise true if signature was made by tag, else false.
    return Security.verify(tag, signature, message);
  },
  async encrypt(tag, message) { // Promise text that can only be decrypted back to message by the keypair designated by tag.
    return Security.encrypt(tag, message);
  },
  async decrypt(tag, encrypted) { // Promise the original text given to encrypt() IFF the current user has access to the keypair designated by tag, else reject.
    return Security.decrypt(tag, encrypted);
  },
  async sign(tag, message) { // Promise a signature for message suitable for verify() IFF the current user has access to the keypair designated by tag, else reject.
    return Security.sign(tag, message);
  }
};

export default VaultedSecurity;

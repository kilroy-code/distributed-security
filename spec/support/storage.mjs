const Storage = {
  origin: new URL(import.meta.url).origin, // diagnostic, reported in ready
  async store(resourceTag, ownerTag, signature) {
    let verified = await this.Security.verify(signature, {team: ownerTag, notBefore: 'team'});
    if (!verified) throw new Error(`Signature ${signature} does not match owner of ${ownerTag}.`);
    if (verified.payload.length) {
      this[resourceTag][ownerTag] = signature;
    } else {
      delete this[resourceTag][ownerTag];
    }
    return null; // Must not return undefined for jsonrpc.
  },
  async retrieve(resourceTag, ownerTag) {
    // We do not verify and get the original data out here, because the caller has
    // the right to do so without trusting us.
    return this[resourceTag][ownerTag];
  },
  Team: {},
  KeyRecovery: {},
  EncryptionKey: {}
};
export default Storage;

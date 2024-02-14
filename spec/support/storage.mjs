import Security from "../../index.mjs";
const Storage = {
  async store(resourceTag, ownerTag, signature) {
    let verified = await Security.verify(signature, ownerTag);
    if (!verified) throw new Error(`Signature ${signature} does not match owner of ${ownerTag}.`);
    if (!verified.text) {
      // FIXME? Is it ever meaningful to store an empty payload? If so, we'll need a separate delete operation.
      delete this[resourceTag][ownerTag];
      return null;
    }
    this[resourceTag][ownerTag] = signature;
    // FIXME: Return a receipt consisting of a signed message+timestamp from us.
    return null;
  },
  async retrieve(resourceTag, ownerTag) {
    return this[resourceTag][ownerTag];
  },
  Team: {},
  Device: {},
  KeyRecovery: {},
  EncryptionKey: {}
};
export default Storage;

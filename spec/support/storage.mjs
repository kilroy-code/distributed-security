import Security from "../../lib/security.mjs";
const Storage = {
  async store(resourceTag, ownerTag, _string, signature) {
    let verified = await Security.verify(signature, ownerTag),
	string = verified?.text;
    if (!verified) throw new Error(`Signature ${signature} for ${string} does not match owner of ${ownerTag}.`);
    if (!string) {
      // FIXME? Is it ever meaningful to store an empty payload? If so, we'll need a separate delete operation.
      delete this[resourceTag][ownerTag];
      return null;
    }
    this[resourceTag][ownerTag] = string;
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

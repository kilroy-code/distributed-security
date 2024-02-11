import Security from "../../lib/security.mjs";
const Storage = {
  async store(resourceTag, ownerTag, string, signature) {
    // Note: This trivial storage mechanism assumes one ownerTag per resourceTag, and the resourceTag is a global string. A real resourceTag is likely to be a path.
    if (!await Security.verify(signature, ownerTag)) throw new Error(`Signature ${signature} for ${string} does not match owner of ${ownerTag}.`);
    // FIXME: if there is already content there, we must prevent a third party from reverting to an earlier version with a replay.
    //   Require the inclusion of some form of signed timestamp that is between the existing antecendent timestamp and now?
    //   See https://crypto.stackexchange.com/questions/107003/is-there-a-way-to-get-time-from-signature-or-is-it-possible-to-ensure-the-messa and links.
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

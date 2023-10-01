import Security from "./security.mjs";
const Storage = {
  async store(resourceTag, ownerTag, string, signature) {
    // Note: This trivial storage mechanism assumes one ownerTag per resourceTag, and the resourceTag is a global string. A real resourceTag is likely to be a path.
    if (!await Security.verify(ownerTag, signature, string)) throw new Error(`Signature ${signature} for ${string} does not match owner of ${ownerTag}.`);
    this[resourceTag][ownerTag] = string;
  },
  async retrieve(resourceTag, ownerTag) {
    return this[resourceTag][ownerTag];
  },
  Team: {},
  EncryptionKey: {}
};
export default Storage;

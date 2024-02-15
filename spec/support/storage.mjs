import Security from "../../index.mjs";
const Storage = {
  async store(resourceTag, ownerTag, signature) {
    let verified = await Security.verify(signature, ownerTag);
    if (!verified) throw new Error(`Signature ${signature} does not match owner of ${ownerTag}.`);
    if (!verified.payload.length) {
      delete this[resourceTag][ownerTag];
      return null;
    }
    this[resourceTag][ownerTag] = signature;
    // We were given the signature, and not the payload. By returning the original payload, we
    // give the caller a reasonable expectation that the storage implementation -- which
    // the app does not necessarily control -- has examined the signature in some way.
    // Note that json will be define if and only if the signature cty specifies json,
    // and otherwise text will be defined if cty specifies text.
    return verified.json ?? verified.text ?? verfied.payload;
  },
  async retrieve(resourceTag, ownerTag) {
    // We do not verify and get the original data out here, because the caller has
    // the right to do so without trusting us.
    return this[resourceTag][ownerTag];
  },
  Team: {},
  Device: {},
  KeyRecovery: {},
  EncryptionKey: {}
};
export default Storage;

import { Security, companyDbWrite, companyDbRead } from './toy-sar.mjs';
Security.Storage.companyName = 'companyB';
await Security.ready;

// At Company B, the webserver wakes up and does the following in getPOST().
// Again, the database key and SDK key associations are not critical here:
const {To, Subject, Body:{tag:GroupATag, pubkeyForEncryption}} = await companyDbRead("operations@companyB.com.json");
const signed = await companyDbRead(encodeURIComponent("https://orderapi.companyb.com/order") + ".json");

// Even though E1 at Company A signed it, we can verify using the PARENT
// group key!   This is super important; Company B does not care about E1,
// only about Company A.  And verification requires no passphrases, so the
// webserver needs no special credentials:

const verified = await Security.verify(signed, GroupATag);
if (!verified) throw new Error("Reject workflow");

//  Webserver now activates processing workflow and sends verified material
//  to enployee E2.

//  E2 only knows his tag and passphrase; he is operationally
//  unconcerned with the verification process; that happened "ahead of him".
//  E2 is a member of Company B Group tag which means any material
//  encrypted to the Group tag can be decrypted by him.  This means no
//  shared keys AND any actions taken on the decrypted material are
//  nonrepudiatively associated with E2, not with a generic group!

const {GroupBTag} = await companyDbRead("companyBInternalData.json");
var normalSecretFunction = Security.getUserDeviceSecret;
Security.getUserDeviceSecret = (key) => "E2 passphrase";
const decrypted = await Security.decrypt(verified.text, GroupBTag);
Security.getUserDeviceSecret = normalSecretFunction;

console.log(decrypted.text);

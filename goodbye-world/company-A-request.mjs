import { Security, companyDbWrite, companyDbRead } from './toy-sar.mjs';
Security.Storage.companyName = 'companyA';
await Security.ready;

//  Now, Company A needs to send data to Company B.  E1 at Company is using
//  the following application to send a sales order to Company B.
//  It is not important here to worry about the database lookup key used to
//  fetch an SDK key; assume some model exists:
const {To, Subject, Body:{tag:GroupBTag, pubkeyForEncryption}} = await companyDbRead("operations@companyA.com.json");
// We're going to encrypt for GroupB, in a moment, but GroupB is in Company B's SAR. Let's get it into ours.
// (Note: alternatively, the two companies could use a shared SAR, but that's not the scenario in this example.)
await Security.Storage.store('EncryptionKey', GroupBTag, pubkeyForEncryption);

//  E1 needs no further materials to encrypt to the  Company B tag:
const encrypted = await Security.encrypt("Sales order from Company A", GroupBTag);

const {GroupATag, E1Tag} = await companyDbRead("companyAInternalData.json");

// Only E1 knows his passphrase to enable signing with his tag.  Assume the
// passphrase is entered into popup in the app.  It is important for
// Company A to know that specifically and nonrepudiatively it was E1
// performing this function.  Remember:  E1 is a member of GroupATag...

var normalSecretFunction = Security.getUserDeviceSecret;
Security.getUserDeviceSecret = (key) => "E1 passphrase";

let signed; // We're going to get signed in a number of different ways here, for exposition purposes.
// In this scenario, the company A server created all the company keys and is thus able to sign and decrypt for them.
// I.e., the server has "custodial possession" of the admin and employee keys, and can freely use them on behalf of the employees.
// Here the server will sign for BOTH the GroupAtag and the E1Tag. I.e., the signature result contains two cryptographic signature strings.
signed = await Security.sign(encrypted, GroupATag, E1Tag);
// Here is another syntax for exactly the same thing. Use whichever is more convenient:
signed = await Security.sign(encrypted, {tags: [GroupATag, E1Tag]});
// We're going to give signed to Company B, who will verify that it was signed by GroupATag, of which E1Tag is a member. (See company-A-setup.mjs)
// But here at Company A, we might later by interested in verifying that it was specically signed by E1Tag:
if (!await Security.verify(signed, E1Tag)) throw new Error("Not signed by E1");
// This one is very similar to the previous signature, but it specifically indicates that E1 is member of GroupA:
signed = await Security.sign(encrypted, {team: GroupATag, member: E1Tag});
// And the difference is that when verifying, the system will make sure that E1 is STILL a member of GroupA at the time of verification, which does not happen for the previous signature.
if (!await Security.verify(signed, {team: GroupATag, member: E1Tag})) throw new Error("Not signed by E1");

Security.getUserDeviceSecret = normalSecretFunction;

// Transmit signed_material to Company B:
const post = {
  url: "https://orderapi.companyb.com/order",
  body: signed
};
await companyDbWrite(encodeURIComponent(post.url) + ".json", post.body); // Simulate the post with the file system.


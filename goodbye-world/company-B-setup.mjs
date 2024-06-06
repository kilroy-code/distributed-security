// This happens to be identical to company A setup, but with A <=> B and E1 <=> E2.

//  Company B setup:
//

import { Security, companyDbWrite } from './toy-sar.mjs';
Security.Storage.companyName = 'companyB';
await Security.ready;

//  This would nominally be done once and the serverDeviceTag would be
//  stored in a DB.  In other words, it is normal to make many recovery and group
//  tags but typically fewer device tags:
const adminTag = await Security.create();

// //  Create a master group:
const GroupBTag = await Security.create(adminTag);

//  Share this tag with Company B.  Remember: no secrets are revealed or accessible here:
const email = {
  To: "operations@companyA.com",
  Subject: "Our New Company B Tag",
  Body: {
    tag: GroupBTag,
    pubkeyForEncryption: await Security.Storage.retrieve('EncryptionKey', GroupBTag)
  }
};
await companyDbWrite(email.To + ".json", email); // Simulate the email with the file system.

//
//  The underlying private keys are protected by a secret provided by the application:
//  - When such keys are kept at the user's device for end-to-end encryption, this hook function
//    is called at the device to encrypt and decrypt the local keys.
//  - In this example, the keys are kept and used at the company server, but are still encrypted
//    and decrypted individually for each employee using this function. It will do that, too.
//
// Grab the current hook function.
var normalSecretFunction = Security.getUserDeviceSecret;
// Replace it here at the company server with one that responds with what the user enters at their terminal.
Security.getUserDeviceSecret = (key) => "E2 passphrase";
// Create the user's key, which will be encrypted with this value.
const E2Tag = await Security.create();
// And restore the hook. The server will now not be able to sign or decrypt for this user without again getting the user's passphrase.
Security.getUserDeviceSecret = normalSecretFunction;

await Security.changeMembership({tag: GroupBTag, add: [E2Tag]});

await companyDbWrite("companyBInternalData.json", {adminTag, GroupBTag, E2Tag}); // Store in "database" for later operations.

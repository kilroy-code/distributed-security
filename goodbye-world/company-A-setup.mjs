//  Company A setup:
//

import { Security, companyDbWrite } from './toy-sar.mjs';
Security.Storage.companyName = 'companyA';
await Security.ready;

//  This would nominally be done once and the serverDeviceTag would be
//  stored in a DB.  In other words, it is normal to make many recovery and group
//  tags but typically fewer device tags:
const adminTag = await Security.create();

// //  Create a master group:
const GroupATag = await Security.create(adminTag);

//  Share this tag with Company A.  Remember: no secrets are revealed or accessible here:
const email = {
  To: "operations@companyB.com",
  Subject: "Our New Company A Tag",
  Body: {
    tag: GroupATag,
    pubkeyForEncryption: await Security.Storage.retrieve('EncryptionKey', GroupATag)
  }
};
await companyDbWrite(email.To + ".json", email); // Simulate the email with the file system.

//  Add Employee E1 at Company A to the Group.  Obviously, this (and its
//  reciprocal, remove) happen far more often than Group creation.  The whole
//  point of the Group is that it remains relatively static.
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
Security.getUserDeviceSecret = (key) => "E1 passphrase";
// Create the user's key, which will be encrypted with this value.
const E1Tag = await Security.create();
// And restore the hook. The server will now not be able to sign or decrypt for this user without again getting the user's passphrase.
Security.getUserDeviceSecret = normalSecretFunction;

await Security.changeMembership({tag: GroupATag, add: [E1Tag]});

await companyDbWrite("companyAInternalData.json", {adminTag, GroupATag, E1Tag}); // Store in "database" for later operations.


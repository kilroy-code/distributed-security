import Security from '@ki1r0y/distributed-security';
import * as fs from 'node:fs/promises';

// A silly unscalable SAR, specific to a companyName even though we store in the same file system for this example.

// In this scenario, the two companies operate separately, each with their own internal applications, including
// their own SAR for each. Here we have created a toy implementation of a SAR that creates a .json file for each resource
// it stores, so that you can see what is being stored, while at the same time making it clear that the two are operating
// independently. (See the .json file names.)
// Alternatively, the two companies could share a common SAR.

function resourceName(dbName, resourceTag, ownerTag) {
  return `${dbName}-${resourceTag}-${ownerTag}.json`;
}

const Storage = {
  companyName: undefined,
  Security,
  async store(resourceTag, ownerTag, signature) {

    // We don't need to do verify. The scenario for this demo is that the server at each company and its intranet is trusted.
    // The cryptography is really for the purpose of communication between the companies.
    // Nonetheless, defense-in-depth is always a good thing, and a general SAR SHOULD verify items being stored.
    // This is how it is done. Note that the rules for verify work even in the case of company A doing:
    //    Security.Storage.store('EncryptionKey', tag, pubkeyForEncryption) // in company-A-request.mjs
    if (!await this.Security.verify(signature, {team: ownerTag, notBefore: 'team'})) throw new Error(`Bad ${resourceTag}: ${signature}`);

    let payload = JSON.stringify(signature),
        payloadName = resourceName(this.companyName, resourceTag, ownerTag);
    await fs.writeFile(payloadName, payload);
    return null; // Must not return undefined for jsonrpc.
  },
  async retrieve(resourceTag, ownerTag) {
    // We do not verify and get the original data out here, because the caller has
    // the right to do so without trusting us.
    let payloadName = resourceName(this.companyName, resourceTag, ownerTag),
        payload = await fs.readFile(payloadName).catch(_ => undefined);
    return payload && JSON.parse(payload);
  }
};

Security.Storage = Storage;

function companyDbWrite(name, value) {
  return fs.writeFile(name, JSON.stringify(value, null, 2));
}
async function companyDbRead(name) {
  return JSON.parse(await fs.readFile(name, {encoding: 'utf8'}));
}

export {Security, companyDbWrite, companyDbRead};

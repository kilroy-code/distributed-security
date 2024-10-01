# Distributed Security

This is a Javascript SDK for **browsers and Node** that makes it easy for developers to correctly and safely use the four standard cryptographic operations (**encrypt, decrypt, sign, and verify**).  It uses only battle-tested, industry standard cryptoalgorithms
(e.g., ES384, RSA-OAEP-256) and key representations (e.g. JOSE/JWS/JWE) but layers in
additional important and valuable features:

 *  Individual keys can be members of any number of groups, which in turn
    can be nested members of other groups.  Groups themselves have keys associated
    with them and this enables a very valuable use case:
    
    >  Individual signing for nonrepudiation and individual decryption for
    security/entitlement<br>
    ...but with group-wide encryption and group-wide signature
    verification for operational robustness and ease of key management

    In this use case, parties A and B using encryption and signatures are no
    longer exposed to the internal key/personnel management of the counterparty.
    Individual key holders at party A or B can be added or removed locally without
    forcing key exchange between A and B.  Each party internally, however, can associate
    signing and decryption with a specific actor; individuals do not share personal keys.


 *  Creating key pairs in traditional PKI environments is "easy"; securing and
    managing the generated private key is not.
    A robust cryptosystem needs a way to provide security for the private key, both in
    terms of use (e.g. passphrase) and integrity of the physical media storing it.
    The SDK has an abstraction for a **secure, addressable, and reliable** ("SAR")
    storage facility into which encrypted materials including those required for
    key recovery can be written:

     *  It is secure because the materials stored there are encrypted and do
     	not create a data leak vulnerability

     *  By addressable we mean there is a well-known location and communications protocol
        to access the materials

     *  By reliable we mean that the media at the location offers very high
     	availability (including perhaps disk mirroring) to significantly reduce the
	effect of physical media loss
	
    The SAR facility clearly has a natural implementation using basic bucket resources
    of any of the cloud providers.  For testing and experimentation, a local filesystem
    based SAR also exists.

    Note that sensitive key materials are
    securely and performantly stored locally (in Node and in browsers);
    the SAR provides access across clients and defends against loss of local media and/or damage to the local storage.
    
 * Every invididual or group key is available for end-to-end encryption and signatures on whatever device it has been authorized - and only on those devices. E.g., once authorized on each of a person's devices (including back-end systems if desired), that person can use their tag from any of them. And yet a device can be remotely de-authorized when needed.
 
 *  The actual physical strings used in the app-facing SDK API are not actual key objects but instead string proxies called **tags.**  Tags have a number of
    benefits over the low-level cryptosystem keys:

     *  Tags insulate the application from the actual technical implementation of the
     	underlying keys, enabling a variety of different algorithms to be used, as well
	as future-proofing the SDK from new algorithms

     *  Tags are designed as plain ASCII strings
     	with no special characters and no whitespace (e.g. "AxY9qnu8e038m4vwN..."). They
	are easy to copy-and-paste, programmatically manipulate, pass as an option
	in an http URL, store in databases, pass on message buses, etc.

     *  Tags can (and do) contain additional metadata required for the SDK and
        do so in an opaque fashion i.e. they can be treated as plain identifiers,
	not smart keys
     	
     
	
The group and device design elements of the SDK coupled with tags enable a new
paradigm in cryptosystems:
role-based, data-domain driven cryptography instead of low level key-based cryptography.

## Hello World
```
let myDeviceTag = await Security.create();
let myRecoveryTag = await Security.create({prompt: "What is the air-speed velocity of an unladen swallow?"});
let myIndividualTag = await Security.create(myDeviceTag, myRecoveryTag);

encrypted = await Security.encrypt("A secret message", myIndividualTag);
decrypted = await Security.decrypt(encrypted);
console.log(encrypted, decrypted);
```

## Goodbye World

(See runnable code in [goodbye-world](goodbye-world).)

```
//  Company A:
//  
//  This would nominally be done once and the serverDeviceTag would be
//  stored in a DB.  In other words, it is normal to make many recovery and group
//  tags but typically fewer device tags:
let serverDeviceTag = await Security.create(); 

//  Create a master group:
let GroupRecoveryTag = await Security.create({prompt: "Question?"});
let GroupATag = await Security.create(serverDeviceTag, GroupRecoveryTag);

//  Share this tag with Company B.  Remember: no secrets are revealed or
//  accessible here:
//    To: operations@companyB.com
//    Subject:  Our New Company A Tag
//    Body:  (copy and paste of GroupATag, the 132 character friendly string)
//

//  Add Employee E1 at Company A to the Group.  Obviously, this (and its
//  reciprocal, remove) happen far more often than Group creation.  The whole
//  point of the Group is that it remains relatively static.
let E1RecoveryTag = await Security.create({prompt: "E1 favorite food?"});
let E1Tag = await Security.create(serverTag, E1RecoveryTag);
Security.changeMembership({tag: GroupATag, add: E1Tag});



//  Meanwhile, Company B does essentially the same thing:  A device key is
//  created, a group created, and employee E2 added to the group.   The groupTag
//  is emailed or otherwise transmitted to Company A which stores it in a DB.



//  Now, Company A needs to send data to Company B.  E1 at Company is using
//  the following application to send a sales order to Company B.
//  It is not important here to worry about the database lookup key used to
//  fetch an SDK key; assume some model exists:

let GroupBTag = tagDB.fetch("some_identifier_for_company_B");


//  E1 needs no passphrases or other materials to encrypt to the
//  Company B tag:
encrypted = Security.encrypt(GroupBTag, "Sales order from Company A");

E1Tag = tagDB.fetch("E1_tag");
// Only E1 knows his passphrase to enable signing with his tag.  Assume the
// passphrase is entered into popup in the app.  It is important for
// Company A to know that specifically and nonrepudiatively it was E1
// performing this function.  Remember:  E1 is a member of GroupATag... 
signed_material = Security.sign(E1Tag, E1passphrase, encrypted);

// Transmit signed_material to Company B:
curl -X POST @signed_material https://orderapi.companyb.com/order



// At Company B, the webserver wakes up and does the following in getPOST().
// Again, the database key and SDK key associations are not critical here:
let GroupATag = tagDB.fetch("some_identifier_fo_company_A");

// Even though E1 at Company A signed it, we can verify using the PARENT
// group key!   This is super important; Company B does not care about E1,
// only about Company A.  And verification requires no passphrases, so the
// webserver needs no special credentials:

if ( BAD == Security.verify(GroupATag, signed_material) ) {
    perform_reject_workflow();
} else ...

//  Webserver now activates processing workflow and sends verified material
//  to enployee E2.

//  E2 only knows his tag and passphrase; he is operationally
//  unconcerned with the verification process; that happened "ahead of him".
//  E2 is a member of Company B Group tag which means any material
//  encrypted to the Group tag can be decrypted by him.  This means no
//  shared keys AND any actions taken on the decrypted material are
//  nonrepudiatively associated with E2, not with a generic group!

E2Tag = tagDB.fetch("E2_tag");
decrypted = Security.decrypt(E2Tag, E2passphrase, signed_material);

// decrypted is "Sales order from Company A"
```



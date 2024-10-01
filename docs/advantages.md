Advantages of Key-Based Security

Stateless at server: Each request can be verified at the server without regard to any additional information as to proof that the user is the one associated with the tag. (Just verify that the request, tag, and anti-replay mechanism (e.g., timestamp or counter) matches the accompanying signature. No other network activity is required, as the public key is embedded directly in the tag. However:

- The server does have to keep track of the current counter or timestamp - a single value among all users, plus some means to know what recent value is still in flight.
- The server still needs to know what tags are supposed to have access to what services. This can often be looked up once and then exchanged for a server-side session cookie. Alternatively, in some cases a user can be added to a well-known team for each application service, of which all members are allowed to use it.

End-to-end encryption: Storing unencrypted data creates a risk to the user that the custodian might not keep the key safe, and a risk to the custodian that they may be forced to divulge the key under threat of violence or legal action. End-to-end encryption avoids these problems by encrypting the data at the user's device, and only decrypting in the intended-user's device. There are many specialized communications apps and protocols that do this. Distributed Security makes this much easier for all apps to do so, and importantly, it makes it much easier for users to encrypt content - not just p2p messages - for a whole group of people. We do this by spontaneously creating a team of individuals with anencrypting tag for the whole team that any member of the team can use to decrypt the content at their device.

Stateless helps decentralization.

maybe useful definition: a token is a string that contains some information that can be verified securely. It could be a random set of alphanumeric characters which point to an ID in the database, or it could be an encoded JSON that can be self-verified by the client (known as JWTs).


should we map ki1r0y concepts to jwt claims? e.g., should [tag, owner, author] maybe be called [sub, aud, iss]? What about userId?  What does rostr do?	
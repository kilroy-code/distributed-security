# Why Cryptography

Let's look at how Distributed Security achieves each of the benefits listed at the top of the [README.md](../README.md).


## Privacy

- No tracking by login or viewing of content, including private content.

The general idea of a login is to confirm _who_ you are at the beginning of your session, and then use that identity to track everything you do. A lifetime ago, logins were an easy solution to the problem of accounting for time spent on early expensive multi-user computers. The name comes from ancient ships' activity records that note the speed estimate given by the time spent watching a floating log pass down the known length of the side of a ship. Eventually, the ship owners wanted the captain to note everything that happened that might be important.

Once our activities are exposed, we don't know how that information will be used, and continue to be used. Some activity, such as looking at health information or products, can be markers for things that we do not understand ourselves, which can then be used to deny or cost us. Activity can be misconstrued, and it can be used to manipulate us by presenting us with tailored content or results that use our profiled succeptabilities against us (or against someone else by someone who pretends to know us). All without us being aware.

Even if a site or app does not itself sell your activity, the site may use an outside vendor for login or other services such as usage analytics. Such vendors often provide their software for free to developers, because the vendors make their money by selling your activity patterns to advertisers. Vendors can track your activity on one site, based on the site's use of a non-login service such as analytics, and then correlate that activity with your identify from the vendor's login service used on another site. The result is that the innocent reading you are doing in one place is then put into the model provided to people that neither you nor the site are aware of.

 We can do better now using verifiable signatures and receipts.

## Verifiable Receipts

- A receipt for activity that proves who authorized the activity (by pseudonym), and when.
- No passwords.
- No transaction costs.
- No browser extensions.

For important transactions, an application might display a text confirmation that the user can save as text or a picture. Of course, these can be edited. To examine the real record, the user and any other interested parties are dependent on the integrity of the company's records: that it was legitimately created, and not modified later by the company or a hacker, and indeed that the login hadn't been stolen in the first place. Examining the transaction also requires that the database is still running, and that the company lets you examine the record. This might be practical for a company in a well-regulated industry, but not for smaller companies, organizations, or individuals running their own software.

With cryptography, software can sign the transaction record with a key that only you have. You control access to your phone or computer, and the computer controls access to the key used for signing. The software can work in milliseconds without asking you anything, or it can be written to ask you for a PIN or some such - that's up to the application. Similarly, the application server can sign the same request to show that the transaction was indeed accepted by them.

Copies of this signed record can be copied out anywhere - even to paper - and anyone with the copy and appropriate software can verify that the specified transaction was indeed authorized by the specified tag. Signatures use standardized algorithms that can be verified by software that is different from the original software that created the signature.

Note that this record does not identify you by name or account number - just by tag. In some applications, it is not necessary to know _who_ entered into the transaction, but only that you can securly redeem the result by proving that you still control the same tag. You just sign a challenge later with the same tag. 

In other cases, it may be necessary for the site to recognize the tag in order to accept the transaction in the first place. There are two ways that the application might do this:

- One is to register your tag with the site when you sign up. In this case, the site can track your transactions with them, but no one else can. You don't have to log in to merely view the site, and you only get "tagged" when you make some transaction there. This kind of behavior can be used by any cryptography system, and it makes sense when the transaction requires delivering a specific thing to a specific identifiable human.
- In other cases, it is only necessary for the application to know that the user is authorized for the activity - such as entering a private chat room or building on some specific virtual land. For this, Distributed Security allows the application to make a team that has the permission, and to add the user's tag to that team. Thereafter, it only need keep track of the team tag, and it checks for permission by asking the user's software to sign a request with this team's tag.

Outside of distributed security, the [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) uses cryptographic verification to confirm your identity for login without passwords. In that approach, you register your tag with the provider, and on subsequent visits the software uses that tag to sign a login challenge and they verify the result. 

It's easy to see why avoiding passwords is popular. People either forget them, or use the same password everywhere such that a theft of passwords at one company makes acccess available to all sites, or they use paper, or get locked in to a password manager or identity vendor. All this without actually being sufficient to stop breaches. Many sites now use alternatives such as magic links sent to a user's email or phone number. These require giving up your email or phone, and they send users outside the app right at the moment the user is trying to get in. They also typically require third party services (for email or messaging) that bring in extra costs, complexity, and privacy issues. 

Cryptographic signatures avoid all of this for login _identity_, but unlike Web Authentication, they also allows applications to do away with login altogether by instead signing for specific activity rather than signing _browser sessions_.

The self-contained receipt is one of the application areas of blockchain, but blockchain comes with other baggage that isn't necessary for receipts by themselves. First, the algorithms used in popular blockchains are not supported in browsers. These only works in connection with either installed applications (rather than Web pages), browser extensions (which have access to your browsing activity), or "trusted" conventional Web sites that conduct your activity for you on their servers, using their own sets of conventional records. Additionally, signed receipts are not the primary purpose of blockchains, but merely one side-effect of their approach to distributed ledgers. Another side-effect of their approach to ledgers is that they _must_ charge a transaction fee to create a new entry, or else their whole model of how ledgers are reconciled falls apart. These fees are typicaly much too high for frequent everyday activity.  Distributed Security doesn't make use of these ledger-related activities, and makes provable receipts available to all browser software, for free.

## A Better Cloud

- No theft of private content, nor risk to cloud providers that they will be forced to turn over content by threat of violence or legal action.
- Faster cloud data access.
- No centralized authority.

It really isn't a good idea to store private content on a server, and then gate access to that server with a login. In such cases, the people operating the server have access to the content, and users are relying on the server operators to gate access properly. 
This creates a problem for the server operators as well, as it makes them a target for theft, and for violent criminals or law enforcement to compell them to provide the content. It is much better for everyone if the creator encrypts the content on their own machine, and that it stay encrypted and unreadable through transmission and at rest on the servers, and only be decrypted by the intended audience within the authorized user's browser.

Cloud access can also be faster overall when using encryption. With private content being encrypted, there is no need to check for read permission. In modern infrastructure, lookups of user permissions takes more time for database lookup than does on-the-fly decryption at the browser. The absence of an authorization step or authorization state allows a lot of implementation flexibility in the serving of the data, including caching at server, network edge, and client.

Similarly, on-the-fly verfication of self-contained signed requests or transactions is faster when there is no account lookup. Indeed, many sites are now using a signed token - e.g., a so-called [JWT](https://jwt.io/) - as a means of conveying self-contained, stateless authority. However, many sites use this to convey identity, and still need to separately lookup the signed user id to check specific authorizations! A better approach with Distributed Security is to convey each kind of authorization with it's own well-known tag, and add the user's tag as a member to this authorized team. The runtime "lookup" for membership is then done by the client when the Distributed Security vault gets access to the team key. The server needs only to verify the signature and compare test tag string against one known at startup.

There is no fixed limit to the number of members on a team. Changing team membership doesn't happen nearly as often other activities, but when it does happen, the time is proportional to the number of members. If this is a problem, large teams can be composed in a tree of teams, each with a manageable size. Checking a signature still takes just one computation for the well-known key at the top of the tree, and the client's own latency to decrypt the root key is logarithmic - proportional to the depth of the tree rather than the total number of entries. (The tests of ownership of each member happens in parallel.)

Applications can allow clients to create new tags on their own, without going through any central bottleneck, as there is usually no need to record new tags in a database. The storage of encrypted keys can be a completely different service from where the main application business logic is run.
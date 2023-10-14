# Risks facing Distributed Security, and how they are mitigated

assertions, why they are true, and why it comes down to protecting locally stored device keys, and why that comes down to xss

## distributed storage co-dependency
assertions by distributed storage that are required by distributed security

- authorization for change
- replay protection

maybe also cover how distributed storage relies on distributed security?

## non-problems
the asteroid headed towards earth: all bets are off if quantum computing breaks crypto
lifecycle: create, modify, destroy of teams
durability, loss, and recovery of teams and devices, and effect on outstanding persistent content
desktop browser extensions (at least, by design, but see browser bugs)

## real problems
false implementations of distributed security (e.g., on a pkg distribution site)
xss hijack usage, but not steal keys
developer tools
browser bugs
roster membership is not secret

internal: review literature, e.g.:
https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
https://web.dev/csp/
https://crypto.stackexchange.com/questions/35530/where-and-how-to-store-private-keys-in-web-applications-for-private-messaging-wi and the links there.
see attack scenarios in:

- https://owasp.org/www-community/attacks/Man-in-the-browser_attack
- https://owasp.org/www-community/attacks/xss/
- https://www.geeksforgeeks.org/clickjacking-ui-redressing/

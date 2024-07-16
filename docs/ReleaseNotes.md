# Distributed-Security Release Notes

## 1.1.0

- A hash of the payload is included as the 'sub' header in signatures. This can be suppressed with a falsey 'signature' option.
- Some common utilities are exported from the package: hashBuffer, hashText, encodeBase64url, decodeBase64url, and decodeClaims.
- Performance improvements. (The test suite run time is about 25% shorter.)
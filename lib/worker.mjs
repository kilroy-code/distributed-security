import Security from "./api.mjs";
import dispatch from "../dependency/jsonrpc.mjs";

// See https://kilroy-code.github.io/distributed-security/docs/implementation.html#web-worker-and-iframe

const postClient = dispatch({
  dispatcherLabel: import.meta.url,
  target: self,
  targetLabel: 'vault',
  namespace: Security  // jsonrpc requests from the client are handled by Security.
});

// Provide Secrutiy with three operations that are handled by making jsonrpc requests to the client.
Security.Storage = {
  store(...args) {
    return postClient('store', ...args);
  },
  retrieve(...args) {
    return postClient('retrieve', ...args);
  }
}
Security.getUserDeviceSecret = (...args) => postClient('getUserDeviceSecret', ...args);

postClient('ready'); // Tell the client that we are loaded.

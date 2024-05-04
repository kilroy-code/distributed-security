import Security from "./api.mjs";
import dispatch from "@kilroy-code/jsonrpc";

// See https://kilroy-code.github.io/distributed-security/docs/implementation.html#web-worker-and-iframe

// self is a Worker: we will postMessage to that and listen for 'message' on that.
const postClient = dispatch({
  targetLabel: 'vault@' + self.name.split('@')[1], // A debugging label for the window we are communicating with.
  namespace: Security  // jsonrpc requests from the client are handled by calling the specified method on Security.
});

// Provide Security with three operations that are handled by making jsonrpc requests to the client.
// If Security (api.mjs) is running outside a browser (e.g., in node), it supplies its own default
// implementation of Storage and getUserDeviceSecret. Here (in a browser worker), we override these
// with implementations that post the requests to the client.
Security.Storage = {
  store(...args) {
    return postClient('store', ...args);
  },
  retrieve(...args) {
    return postClient('retrieve', ...args);
  }
}
Security.getUserDeviceSecret = (tag, prompt = '') => postClient('getUserDeviceSecret', tag, prompt);

postClient('ready', Security.ready); // Tell the client that everything is now in place for operations.

import Security from "./api.mjs";
import dispatch from "../../jsonrpc/index.mjs";
const postClient = dispatch({target: self, namespace: Security});

Security.Storage = {
  store(...args) {
    return postClient('store', ...args);
  },
  retrieve(...args) {
    return postClient('retrieve', ...args);
  }
}
Security.getUserDeviceSecret = (...args) => postClient('getUserDeviceSecret', ...args);

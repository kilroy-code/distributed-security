import Security from "./security.mjs";
import dispatch from "../../jsonrpc/index.mjs";
const request = dispatch({target: self, namespace: Security});

Security.Storage = {
  store(...args) {
    return request('store', ...args);
  },
  retrieve(...args) {
    return request('retrieve', ...args);
  }
}

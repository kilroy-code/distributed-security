import origin from '#origin'; // When running in a browser, location.origin will be defined. Here we allow for NodeJS.

function uri(collectionName, tag) {
  // Pathname expected by our signed-cloud-server.
  return `${origin}/db/${collectionName}/${tag}.json`; // fixme origin
}
async function responseHandler(response) {
  // Reject if server does, else response.text().
  if (response.status === 404) return '';
  if (!response.ok) return Promise.reject(response.statusText);
  let text = await response.text();
  if (!text) return text; // Result of store can be empty.
  return JSON.parse(text);
}

const Storage = {
  get origin() { return origin; },
  store(collectionName, tag, signature) {
    // Store the signed content on the signed-cloud-server, rejecting if
    // the server is unable to verify the signature following the rules of
    // https://kilroy-code.github.io/distributed-security/#storing-keys-using-the-cloud-storage-api
    return fetch(uri(collectionName, tag), {
      method: 'PUT',
      body: JSON.stringify(signature),
      headers: {'Content-Type': 'application/json'}
    }).then(responseHandler);
  },
  retrieve(collectionName, tag) {
    // We do not verify and get the original data out here, because the caller has
    // the right to do so without trusting us.
    return fetch(uri(collectionName, tag), {
      cache: 'default',
      headers: {'Accept': 'application/json'}
    }).then(responseHandler);
  }
};
export default Storage;

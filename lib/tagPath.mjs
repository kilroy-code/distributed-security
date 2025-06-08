export function tagPath(collectionName, tag, extension = 'json') { // Pathname to tag resource.
  // Used in Storage URI. Bottlenecked here to provide consistent alternate implementations.
  // Path is .json so that static-file web servers will supply a json mime type.
  //
  // NOTE: changes here must be matched by the PUT route specified in signed-cloud-server/storage.mjs and tagName.mjs
  if (!tag) return collectionName;
  return `${collectionName}/${tag}.${extension}`;
}

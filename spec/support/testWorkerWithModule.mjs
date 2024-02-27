import testModule from "./testModuleWithFoo.mjs";
import dispatch from "../../dependency/jsonrpc.mjs";
dispatch({target: self, namespace: {getFoo() { return testModule.foo; }}});

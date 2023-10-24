import testModule from "./testModuleWithFoo.mjs";
import dispatch from "../../../jsonrpc/index.mjs";
dispatch({target: self, namespace: {getFoo() { return testModule.foo; }}});

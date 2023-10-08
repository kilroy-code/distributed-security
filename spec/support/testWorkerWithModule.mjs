import testModule from "./testModuleWithFoo.mjs";
import dispatch from "../../../jsonrpc/index.mjs";
dispatch(self, {getFoo() { return testModule.foo; }});

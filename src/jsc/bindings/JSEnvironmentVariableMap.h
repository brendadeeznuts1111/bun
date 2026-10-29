#include "root.h"

extern "C" bool Bun__Process__environmentRestricted();

namespace Zig {
class GlobalObject;
}

namespace JSC {
class JSValue;
class JSObject;
}

namespace Bun {

JSC::JSValue createEnvironmentVariablesMap(Zig::GlobalObject* globalObject);
JSC::JSObject* createEnvironmentVariablesObject(Zig::GlobalObject*, size_t capacity);
bool isEnvironmentVariableAllowed(const WTF::String&);

}

#include "root.h"
#include "ZigGlobalObject.h"
#include "JSEnvironmentVariableMap.h"

#include "helpers.h"

#include <JavaScriptCore/JSObject.h>
#include <JavaScriptCore/ObjectConstructor.h>
#include <JavaScriptCore/JSArray.h>
#include <JavaScriptCore/JSArrayInlines.h>
#include <JavaScriptCore/JSString.h>
#include <JavaScriptCore/JSStringInlines.h>
#include <JavaScriptCore/PropertyNameArray.h>
#include <JavaScriptCore/PropertyDescriptor.h>

#include "BunClientData.h"
#include "wtf/Compiler.h"
#include "wtf/Forward.h"
#include "WebCoreJSBuiltins.h"

using namespace JSC;

extern "C" size_t Bun__getEnvCount(JSGlobalObject* globalObject, void** list_ptr);
extern "C" size_t Bun__getEnvKey(void* list, size_t index, unsigned char** out);

extern "C" bool Bun__getEnvValue(JSGlobalObject* globalObject, const ZigString* name, ZigString* value);
extern "C" bool Bun__getEnvValueBunString(JSGlobalObject* globalObject, const BunString* name, BunString* value);
extern "C" void Bun__setEnvValue(JSGlobalObject* globalObject, const BunString* name, const BunString* value);
extern "C" bool Bun__Process__permissionHas(const uint8_t*, size_t, const uint8_t*, size_t);
extern "C" bool Bun__Process__environmentRestricted();
#if OS(WINDOWS)
extern "C" void Bun__Process__editWindowsEnvVar(BunString, BunString);
#endif

namespace Bun {

using namespace WebCore;

bool isEnvironmentVariableAllowed(const String& name)
{
    if (!Bun__Process__environmentRestricted()) return true;
    auto bytes = name.utf8();
    return Bun__Process__permissionHas(reinterpret_cast<const uint8_t*>("env"), 3,
        reinterpret_cast<const uint8_t*>(bytes.data()), bytes.length());
}

class RestrictedEnvironment final : public JSNonFinalObject {
public:
    using Base = JSNonFinalObject;
    static constexpr unsigned StructureFlags = Base::StructureFlags | OverridesGetOwnPropertySlot | OverridesGetOwnPropertyNames | OverridesPut | ProhibitsPropertyCaching | InterceptsGetOwnPropertySlotByIndexEvenWhenLengthIsNotZero;
    DECLARE_INFO;

    template<typename, SubspaceAccess mode> static GCClient::IsoSubspace* subspaceFor(VM& vm)
    {
        if constexpr (mode == SubspaceAccess::Concurrently)
            return nullptr;
        return WebCore::subspaceForImpl<RestrictedEnvironment, WebCore::UseCustomHeapCellType::No>(vm, [](auto& spaces) { return spaces.m_clientSubspaceForRestrictedEnvironment.get(); }, [](auto& spaces, auto&& space) { spaces.m_clientSubspaceForRestrictedEnvironment = std::forward<decltype(space)>(space); }, [](auto& spaces) { return spaces.m_subspaceForRestrictedEnvironment.get(); }, [](auto& spaces, auto&& space) { spaces.m_subspaceForRestrictedEnvironment = std::forward<decltype(space)>(space); });
    }

    static RestrictedEnvironment* create(VM& vm, JSGlobalObject* globalObject)
    {
        auto* structure = Structure::create(vm, globalObject, jsNull(), TypeInfo(ObjectType, StructureFlags), info());
        auto* object = new (NotNull, allocateCell<RestrictedEnvironment>(vm)) RestrictedEnvironment(vm, structure);
        object->finishCreation(vm);
        return object;
    }

    static bool getOwnPropertySlot(JSObject* object, JSGlobalObject* globalObject, PropertyName name, PropertySlot& slot)
    {
        if (!allows(name)) return false;
        return Base::getOwnPropertySlot(object, globalObject, normalize(globalObject->vm(), name), slot);
    }

    static bool getOwnPropertySlotByIndex(JSObject* object, JSGlobalObject* globalObject, unsigned index, PropertySlot& slot)
    {
        if (!allows(Identifier::from(globalObject->vm(), index))) return false;
        return Base::getOwnPropertySlotByIndex(object, globalObject, index, slot);
    }

    static bool put(JSCell* cell, JSGlobalObject* globalObject, PropertyName name, JSValue value, PutPropertySlot& slot)
    {
        if (!allows(name)) return deny(globalObject);
#if OS(WINDOWS)
        auto scope = DECLARE_THROW_SCOPE(globalObject->vm());
        auto string = value.toWTFString(globalObject);
        RETURN_IF_EXCEPTION(scope, false);
        value = jsString(globalObject->vm(), string);
#endif
        bool result = Base::put(cell, globalObject, normalize(globalObject->vm(), name), value, slot);
#if OS(WINDOWS)
        RETURN_IF_EXCEPTION(scope, false);
        if (result && !name.isPrivateName()) Bun__Process__editWindowsEnvVar(Bun::toString(name.publicName()), Bun::toString(string));
#endif
        return result;
    }

    static bool putByIndex(JSCell* cell, JSGlobalObject* globalObject, unsigned index, JSValue value, bool shouldThrow)
    {
        auto name = Identifier::from(globalObject->vm(), index);
        if (!allows(name)) return deny(globalObject);
#if OS(WINDOWS)
        auto scope = DECLARE_THROW_SCOPE(globalObject->vm());
        auto string = value.toWTFString(globalObject);
        RETURN_IF_EXCEPTION(scope, false);
        value = jsString(globalObject->vm(), string);
#endif
        bool result = Base::putByIndex(cell, globalObject, index, value, shouldThrow);
#if OS(WINDOWS)
        RETURN_IF_EXCEPTION(scope, false);
        if (result) Bun__Process__editWindowsEnvVar(Bun::toString(name.string()), Bun::toString(string));
#endif
        return result;
    }

    static bool deleteProperty(JSCell* cell, JSGlobalObject* globalObject, PropertyName name, DeletePropertySlot& slot)
    {
        if (!allows(name)) return deny(globalObject);
        bool result = Base::deleteProperty(cell, globalObject, normalize(globalObject->vm(), name), slot);
#if OS(WINDOWS)
        if (result && !name.isPrivateName()) Bun__Process__editWindowsEnvVar(Bun::toString(name.publicName()), { .tag = BunStringTag::Dead });
#endif
        return result;
    }

    static bool deletePropertyByIndex(JSCell* cell, JSGlobalObject* globalObject, unsigned index)
    {
        auto name = Identifier::from(globalObject->vm(), index);
        if (!allows(name)) return deny(globalObject);
        bool result = Base::deletePropertyByIndex(cell, globalObject, index);
#if OS(WINDOWS)
        if (result) Bun__Process__editWindowsEnvVar(Bun::toString(name.string()), { .tag = BunStringTag::Dead });
#endif
        return result;
    }

    static bool defineOwnProperty(JSObject* object, JSGlobalObject* globalObject, PropertyName name, const PropertyDescriptor& descriptor, bool shouldThrow)
    {
        if (!allows(name)) return deny(globalObject);
#if OS(WINDOWS)
        auto scope = DECLARE_THROW_SCOPE(globalObject->vm());
        auto normalizedDescriptor = descriptor;
        String string;
        if (descriptor.value() && !name.isPrivateName()) {
            string = descriptor.value().toWTFString(globalObject);
            RETURN_IF_EXCEPTION(scope, false);
            normalizedDescriptor.setValue(jsString(globalObject->vm(), string));
        }
        bool result = Base::defineOwnProperty(object, globalObject, normalize(globalObject->vm(), name), normalizedDescriptor, shouldThrow);
        RETURN_IF_EXCEPTION(scope, false);
        if (result && !string.isNull()) Bun__Process__editWindowsEnvVar(Bun::toString(name.publicName()), Bun::toString(string));
        return result;
#else
        return Base::defineOwnProperty(object, globalObject, normalize(globalObject->vm(), name), descriptor, shouldThrow);
#endif
    }

    static void getOwnPropertyNames(JSObject* object, JSGlobalObject* globalObject, PropertyNameArrayBuilder& names, DontEnumPropertiesMode mode)
    {
        auto& vm = globalObject->vm();
        PropertyNameArrayBuilder candidates(vm, names.propertyNameMode(), names.privateSymbolMode());
        Base::getOwnPropertyNames(object, globalObject, candidates, mode);
        for (const auto& name : candidates) {
            if (allows(name)) names.add(name);
        }
    }

    static bool setPrototype(JSObject*, JSGlobalObject* globalObject, JSValue, bool)
    {
        return deny(globalObject);
    }

private:
    RestrictedEnvironment(VM& vm, Structure* structure)
        : Base(vm, structure)
    {
    }

    static bool allows(PropertyName name)
    {
        return name.isPrivateName() || (!name.isSymbol() && isEnvironmentVariableAllowed(name.publicName()));
    }

    static Identifier normalize(VM& vm, PropertyName name)
    {
#if OS(WINDOWS)
        if (!name.isSymbol()) return Identifier::fromString(vm, name.publicName().convertToASCIIUppercase());
#endif
        return Identifier::fromUid(vm, name.uid());
    }

    static bool deny(JSGlobalObject* globalObject)
    {
        auto scope = DECLARE_THROW_SCOPE(globalObject->vm());
        throwTypeError(globalObject, scope, "Environment permission denied"_s);
        return false;
    }
};

const ClassInfo RestrictedEnvironment::s_info = { "Environment"_s, &Base::s_info, nullptr, nullptr, CREATE_METHOD_TABLE(RestrictedEnvironment) };

JSObject* createEnvironmentVariablesObject(Zig::GlobalObject* globalObject, size_t capacity)
{
    auto& vm = globalObject->vm();
    if (Bun__Process__environmentRestricted()) return RestrictedEnvironment::create(vm, globalObject);
    if (capacity < 63) return constructEmptyObject(globalObject, globalObject->objectPrototype(), capacity);
    return constructEmptyObject(globalObject, globalObject->objectPrototype());
}

JSC_DEFINE_CUSTOM_GETTER(jsGetterEnvironmentVariable, (JSGlobalObject * globalObject, JSC::EncodedJSValue thisValue, PropertyName propertyName))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    auto* thisObject = dynamicDowncast<JSObject>(JSValue::decode(thisValue));
    if (!thisObject) [[unlikely]]
        return JSValue::encode(jsUndefined());

    ZigString name = toZigString(propertyName.publicName());
    ZigString value = { nullptr, 0 };

    if (name.len == 0) [[unlikely]]
        return JSValue::encode(jsUndefined());

    if (!Bun__getEnvValue(globalObject, &name, &value)) {
        return JSValue::encode(jsUndefined());
    }

    JSValue result = jsString(vm, Zig::toStringCopy(value));
#if OS(WINDOWS)
    if (Bun__Process__environmentRestricted()) {
        auto name = Identifier::fromString(vm, propertyName.publicName().convertToASCIIUppercase());
        thisObject->putDirect(vm, name, result, 0);
        return JSValue::encode(result);
    }
#endif
    thisObject->putDirect(vm, propertyName, result, 0);
    return JSValue::encode(result);
}

JSC_DEFINE_CUSTOM_SETTER(jsSetterEnvironmentVariable, (JSGlobalObject * globalObject, JSC::EncodedJSValue thisValue, JSC::EncodedJSValue value, PropertyName propertyName))
{
    VM& vm = globalObject->vm();
    JSC::JSObject* object = JSValue::decode(thisValue).getObject();
    if (!object)
        return false;

    auto string = JSValue::decode(value).toString(globalObject);
    if (!string) [[unlikely]]
        return false;

    object->putDirect(vm, propertyName, string, 0);
    return true;
}

// Proxy-related env vars (HTTP_PROXY, HTTPS_PROXY, NO_PROXY and lowercase
// variants) are read by fetch()'s native proxy resolution via
// env_loader.getHttpProxyFor(). Writes from JS must sync back to the native env
// map so runtime changes take effect. Unlike the generic getter, this does
// NOT cache on the JS object — the native env map is the single source of truth
// so set-then-get stays consistent and the CustomAccessor isn't clobbered.
JSC_DEFINE_CUSTOM_GETTER(jsGetterProxyEnvironmentVariable, (JSGlobalObject * globalObject, JSC::EncodedJSValue thisValue, PropertyName propertyName))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);
    auto* thisObject = dynamicDowncast<JSObject>(JSValue::decode(thisValue));
    if (!thisObject) [[unlikely]]
        return JSValue::encode(jsUndefined());

    BunString name = Bun::toStringView(propertyName.publicName());
    BunString value = { BunStringTag::Dead };
    if (!Bun__getEnvValueBunString(globalObject, &name, &value)) {
        return JSValue::encode(jsUndefined());
    }
    RELEASE_AND_RETURN(scope, JSValue::encode(jsString(vm, value.toWTFString())));
}

JSC_DEFINE_CUSTOM_SETTER(jsSetterProxyEnvironmentVariable, (JSGlobalObject * globalObject, JSC::EncodedJSValue thisValue, JSC::EncodedJSValue value, PropertyName propertyName))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);
    JSC::JSObject* object = JSValue::decode(thisValue).getObject();
    if (!object)
        return false;

    auto* string = JSValue::decode(value).toString(globalObject);
    RETURN_IF_EXCEPTION(scope, false);
    if (!string) [[unlikely]]
        return false;

    auto view = string->view(globalObject);
    RETURN_IF_EXCEPTION(scope, false);

    BunString name = Bun::toStringView(propertyName.publicName());
    BunString val = Bun::toStringView(view);
    Bun__setEnvValue(globalObject, &name, &val);

    // The proxy-var accessors are added with `DontEnum` when the var was not
    // present in the OS env at startup. The regular env-var setter
    // (`jsSetterEnvironmentVariable`) makes a written var enumerable by
    // replacing the accessor with a data property; this setter keeps the
    // accessor (so the native env map stays the source of truth) but must
    // still clear `DontEnum` — otherwise `process.env.HTTP_PROXY = "..."`
    // followed by `Bun.spawn({env: {...process.env}})` silently drops the var
    // (the spread skips non-enumerable properties).
    unsigned attributes;
    JSValue existing = object->getDirect(vm, propertyName, attributes);
    if (existing && (attributes & JSC::PropertyAttribute::DontEnum)) {
        // putDirectCustomAccessor asserts NewProperty, so delete first.
        object->deleteProperty(globalObject, propertyName);
        RETURN_IF_EXCEPTION(scope, false);
        object->putDirectCustomAccessor(vm, propertyName, existing,
            attributes & ~JSC::PropertyAttribute::DontEnum);
    }
    return true;
}

JSC_DEFINE_CUSTOM_GETTER(jsTimeZoneEnvironmentVariableGetter, (JSGlobalObject * globalObject, JSC::EncodedJSValue thisValue, PropertyName propertyName))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    auto* thisObject = dynamicDowncast<JSObject>(JSValue::decode(thisValue));
    if (!thisObject) [[unlikely]]
        return JSValue::encode(jsUndefined());

    auto* clientData = WebCore::clientData(vm);

    ZigString name = toZigString(propertyName.publicName());
    ZigString value = { nullptr, 0 };

    auto hasExistingValue = thisObject->getIfPropertyExists(globalObject, clientData->builtinNames().dataPrivateName());
    RETURN_IF_EXCEPTION(scope, {});
    if (hasExistingValue) {
        return JSValue::encode(hasExistingValue);
    }

    if (!Bun__getEnvValue(globalObject, &name, &value) || value.len == 0) {
        return JSValue::encode(jsUndefined());
    }

    JSValue out = jsString(vm, Zig::toStringCopy(value));
    thisObject->putDirect(vm, clientData->builtinNames().dataPrivateName(), out, 0);

    return JSValue::encode(out);
}

// In Node.js, the "TZ" environment variable is special.
// Setting it automatically updates the timezone.
// We also expose an explicit setTimeZone function in bun:jsc
JSC_DEFINE_CUSTOM_SETTER(jsTimeZoneEnvironmentVariableSetter, (JSGlobalObject * globalObject, JSC::EncodedJSValue thisValue, JSC::EncodedJSValue value, PropertyName propertyName))
{
    VM& vm = globalObject->vm();
    JSC::JSObject* object = JSValue::decode(thisValue).getObject();
    if (!object)
        return false;

    JSValue decodedValue = JSValue::decode(value);
    if (decodedValue.isString()) {
        auto timeZoneName = decodedValue.toWTFString(globalObject);
        if (timeZoneName.length() < 32) {
            if (WTF::setTimeZoneOverride(timeZoneName)) {
                vm.dateCache.resetIfNecessarySlow();
            }
        }
    }

    auto* clientData = WebCore::clientData(vm);
    auto* builtinNames = &clientData->builtinNames();
    auto privateName = builtinNames->dataPrivateName();
    object->putDirect(vm, privateName, JSValue::decode(value), 0);

    // TODO: this is an assertion failure
    // Recreate this because the property visibility needs to be set correctly
    // object->putDirectWithoutTransition(vm, propertyName, JSC::CustomGetterSetter::create(vm, jsTimeZoneEnvironmentVariableGetter, jsTimeZoneEnvironmentVariableSetter), JSC::PropertyAttribute::CustomAccessor | 0);
    return true;
}

extern "C" int Bun__getTLSRejectUnauthorizedValue();
extern "C" int Bun__setTLSRejectUnauthorizedValue(int value);
extern "C" int Bun__getVerboseFetchValue();
extern "C" int Bun__setVerboseFetchValue(int value);

ALWAYS_INLINE static Identifier NODE_TLS_REJECT_UNAUTHORIZED_PRIVATE_PROPERTY(VM& vm)
{
    auto* clientData = WebCore::clientData(vm);
    auto& builtinNames = clientData->builtinNames();
    // We just pick one to reuse. This will never be exposed to a user. And we
    // don't want to pay the cost of adding another one.
    return builtinNames.textDecoderStreamDecoderPrivateName();
}

ALWAYS_INLINE static Identifier BUN_CONFIG_VERBOSE_FETCH_PRIVATE_PROPERTY(VM& vm)
{
    auto* clientData = WebCore::clientData(vm);
    auto& builtinNames = clientData->builtinNames();
    // We just pick one to reuse. This will never be exposed to a user. And we
    // don't want to pay the cost of adding another one.
    return builtinNames.textEncoderStreamEncoderPrivateName();
}

JSC_DEFINE_CUSTOM_GETTER(jsNodeTLSRejectUnauthorizedGetter, (JSGlobalObject * globalObject, JSC::EncodedJSValue thisValue, PropertyName propertyName))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    auto* thisObject = dynamicDowncast<JSObject>(JSValue::decode(thisValue));
    if (!thisObject) [[unlikely]]
        return JSValue::encode(jsUndefined());

    const auto& privateName = NODE_TLS_REJECT_UNAUTHORIZED_PRIVATE_PROPERTY(vm);
    JSValue result = thisObject->getDirect(vm, privateName);
    if (result) [[unlikely]] {
        return JSValue::encode(result);
    }

    ZigString name = toZigString(propertyName.publicName());
    ZigString value = { nullptr, 0 };

    if (!Bun__getEnvValue(globalObject, &name, &value) || value.len == 0) {
        return JSValue::encode(jsUndefined());
    }

    return JSValue::encode(jsString(vm, Zig::toStringCopy(value)));
}

JSC_DEFINE_CUSTOM_SETTER(jsNodeTLSRejectUnauthorizedSetter, (JSGlobalObject * globalObject, JSC::EncodedJSValue thisValue, JSC::EncodedJSValue value, PropertyName propertyName))
{
    VM& vm = globalObject->vm();
    JSC::JSObject* object = JSValue::decode(thisValue).getObject();
    auto scope = DECLARE_THROW_SCOPE(vm);
    if (!object)
        return false;

    JSValue decodedValue = JSValue::decode(value);
    WTF::String str = decodedValue.toWTFString(globalObject);
    RETURN_IF_EXCEPTION(scope, false);

    // TODO: only check "0". Node doesn't check both. But we already did. So we
    // should wait to do that until Bun v1.2.0.
    if (str == "0"_s || str == "false"_s) {
        Bun__setTLSRejectUnauthorizedValue(0);
    } else {
        Bun__setTLSRejectUnauthorizedValue(1);
    }

    const auto& privateName = NODE_TLS_REJECT_UNAUTHORIZED_PRIVATE_PROPERTY(vm);
    object->putDirect(vm, privateName, JSValue::decode(value), 0);

    // TODO: this is an assertion failure
    // Recreate this because the property visibility needs to be set correctly
    // object->putDirectWithoutTransition(vm, propertyName, JSC::CustomGetterSetter::create(vm, jsTimeZoneEnvironmentVariableGetter, jsTimeZoneEnvironmentVariableSetter), JSC::PropertyAttribute::CustomAccessor | 0);
    return true;
}

JSC_DEFINE_CUSTOM_GETTER(jsBunConfigVerboseFetchGetter, (JSGlobalObject * globalObject, JSC::EncodedJSValue thisValue, PropertyName propertyName))
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    auto* thisObject = dynamicDowncast<JSObject>(JSValue::decode(thisValue));
    if (!thisObject) [[unlikely]]
        return JSValue::encode(jsUndefined());

    const auto& privateName = BUN_CONFIG_VERBOSE_FETCH_PRIVATE_PROPERTY(vm);
    JSValue result = thisObject->getDirect(vm, privateName);
    if (result) [[unlikely]] {
        return JSValue::encode(result);
    }

    ZigString name = toZigString(propertyName.publicName());
    ZigString value = { nullptr, 0 };

    if (!Bun__getEnvValue(globalObject, &name, &value) || value.len == 0) {
        return JSValue::encode(jsUndefined());
    }

    return JSValue::encode(jsString(vm, Zig::toStringCopy(value)));
}

JSC_DEFINE_CUSTOM_SETTER(jsBunConfigVerboseFetchSetter, (JSGlobalObject * globalObject, JSC::EncodedJSValue thisValue, JSC::EncodedJSValue value, PropertyName propertyName))
{
    VM& vm = globalObject->vm();
    JSC::JSObject* object = JSValue::decode(thisValue).getObject();
    auto scope = DECLARE_THROW_SCOPE(vm);
    if (!object)
        return false;

    JSValue decodedValue = JSValue::decode(value);
    WTF::String str = decodedValue.toWTFString(globalObject);
    RETURN_IF_EXCEPTION(scope, false);

    if (str == "1"_s || str == "true"_s) {
        Bun__setVerboseFetchValue(1);
    } else if (str == "curl"_s) {
        Bun__setVerboseFetchValue(2);
    } else {
        Bun__setVerboseFetchValue(0);
    }

    const auto& privateName = BUN_CONFIG_VERBOSE_FETCH_PRIVATE_PROPERTY(vm);
    object->putDirect(vm, privateName, JSValue::decode(value), 0);

    // TODO: this is an assertion failure
    // Recreate this because the property visibility needs to be set correctly
    // object->putDirectWithoutTransition(vm, propertyName, JSC::CustomGetterSetter::create(vm, jsTimeZoneEnvironmentVariableGetter, jsTimeZoneEnvironmentVariableSetter), JSC::PropertyAttribute::CustomAccessor | 0);
    return true;
}

#if OS(WINDOWS)
extern "C" void Bun__Process__editWindowsEnvVar(BunString, BunString);

JSC_DEFINE_HOST_FUNCTION(jsEditWindowsEnvVar, (JSGlobalObject * global, JSC::CallFrame* callFrame))
{
    auto scope = DECLARE_THROW_SCOPE(global->vm());
    ASSERT(callFrame->argumentCount() == 2);
    ASSERT(callFrame->uncheckedArgument(0).isString());
    WTF::String string1 = callFrame->uncheckedArgument(0).toWTFString(global);
    RETURN_IF_EXCEPTION(scope, {});
    JSValue arg2 = callFrame->uncheckedArgument(1);
    ASSERT(arg2.isNull() || arg2.isString());
    if (arg2.isCell()) {
        WTF::String string2 = arg2.toWTFString(global);
        RETURN_IF_EXCEPTION(scope, {});
        Bun__Process__editWindowsEnvVar(Bun::toString(string1), Bun::toString(string2));
    } else {
        Bun__Process__editWindowsEnvVar(Bun::toString(string1), { .tag = BunStringTag::Dead });
    }
    RELEASE_AND_RETURN(scope, JSValue::encode(jsUndefined()));
}
#endif

JSValue createEnvironmentVariablesMap(Zig::GlobalObject* globalObject)
{
    VM& vm = globalObject->vm();
    auto scope = DECLARE_THROW_SCOPE(vm);

    void* list;
    size_t count = Bun__getEnvCount(globalObject, &list);
    JSC::JSObject* object = createEnvironmentVariablesObject(globalObject, count);

#if OS(WINDOWS)
    JSArray* keyArray = constructEmptyArray(globalObject, nullptr, count);
    RETURN_IF_EXCEPTION(scope, {});
#endif

    static NeverDestroyed<String> TZ = MAKE_STATIC_STRING_IMPL("TZ");
    String NODE_TLS_REJECT_UNAUTHORIZED = String("NODE_TLS_REJECT_UNAUTHORIZED"_s);
    String BUN_CONFIG_VERBOSE_FETCH = String("BUN_CONFIG_VERBOSE_FETCH"_s);
    bool hasTZ = false;
    bool hasNodeTLSRejectUnauthorized = false;
    bool hasBunConfigVerboseFetch = false;

    // Proxy-related env vars need write-back to the native env map so that
    // fetch()'s getHttpProxyFor() observes runtime changes.
    static constexpr ASCIILiteral proxyVarNames[] = {
        "HTTP_PROXY"_s,
        "http_proxy"_s,
        "HTTPS_PROXY"_s,
        "https_proxy"_s,
        "NO_PROXY"_s,
        "no_proxy"_s,
    };
    constexpr size_t proxyVarCount = std::size(proxyVarNames);
    bool hasProxyVar[proxyVarCount] = {};

    auto isProxyVar = [&](const String& name) -> std::optional<size_t> {
        for (size_t j = 0; j < proxyVarCount; j++) {
            if (name == proxyVarNames[j]) return j;
        }
#if OS(WINDOWS)
        // Windows env var names are case-insensitive, so the OS env block can
        // carry any casing (`Http_Proxy`, `HTTP_proxy`, ...). Without this
        // fallback the per-key loop falls through, the bottom loop then adds
        // the canonical accessor with `DontEnum` (because hasProxyVar[*] stayed
        // false), and `{...process.env}` (which most spawn env merges do) drops
        // the var even though `process.env.HTTP_PROXY` reads it fine.
        for (size_t j = 0; j < proxyVarCount; j++) {
            if (equalIgnoringASCIICase(name, proxyVarNames[j])) return j;
        }
#endif
        return std::nullopt;
    };

    auto* cached_getter_setter = JSC::CustomGetterSetter::create(vm, jsGetterEnvironmentVariable, nullptr);
    auto* proxy_getter_setter = JSC::CustomGetterSetter::create(vm, jsGetterProxyEnvironmentVariable, jsSetterProxyEnvironmentVariable);

    for (size_t i = 0; i < count; i++) {
        unsigned char* chars;
        size_t len = Bun__getEnvKey(list, i, &chars);
        // We can't really trust that the OS gives us valid UTF-8
        auto name = String::fromUTF8ReplacingInvalidSequences(std::span { chars, len });
        if (!isEnvironmentVariableAllowed(name)) continue;
#if OS(WINDOWS)
        keyArray->putByIndexInline(globalObject, (unsigned)i, jsString(vm, name), false);
#endif
        if (name == TZ) {
            hasTZ = true;
            continue;
        }
        if (name == NODE_TLS_REJECT_UNAUTHORIZED) {
            hasNodeTLSRejectUnauthorized = true;
            continue;
        }
        if (name == BUN_CONFIG_VERBOSE_FETCH) {
            hasBunConfigVerboseFetch = true;
            continue;
        }
        if (auto idx = isProxyVar(name)) {
            hasProxyVar[*idx] = true;
            continue;
        }
        ASSERT(len > 0);
#if OS(WINDOWS)
        String idName = name.convertToASCIIUppercase();
#else
        String idName = name;
#endif
        Identifier identifier = Identifier::fromString(vm, idName);

        // CustomGetterSetter doesn't support indexed properties yet.
        // This causes strange issues when the environment variable name is an integer.
        if (chars[0] >= '0' && chars[0] <= '9') [[unlikely]] {
            if (auto index = parseIndex(identifier)) {
                ZigString valueString = { nullptr, 0 };
                ZigString nameStr = toZigString(name);
                if (Bun__getEnvValue(globalObject, &nameStr, &valueString)) {
                    JSValue value = jsString(vm, Zig::toStringCopy(valueString));
                    RETURN_IF_EXCEPTION(scope, {});
                    object->putDirectIndex(globalObject, *index, value, 0, PutDirectIndexLikePutDirect);
                    RETURN_IF_EXCEPTION(scope, {});
                }
                continue;
            }
        }

        // JSC::PropertyAttribute::CustomValue calls the getter ONCE (the first
        // time) and then sets it onto the object, subsequent calls to the
        // getter will not go through the getter and instead will just do the
        // property lookup.
        object->putDirectCustomAccessor(vm, identifier, cached_getter_setter, JSC::PropertyAttribute::CustomValue | 0);
    }

    unsigned int TZAttrs = JSC::PropertyAttribute::CustomAccessor | 0;
    if (!hasTZ) {
        TZAttrs |= JSC::PropertyAttribute::DontEnum;
    }
    if (isEnvironmentVariableAllowed(TZ)) object->putDirectCustomAccessor(
        vm,
        Identifier::fromString(vm, TZ), JSC::CustomGetterSetter::create(vm, jsTimeZoneEnvironmentVariableGetter, jsTimeZoneEnvironmentVariableSetter), TZAttrs);

    unsigned int NODE_TLS_REJECT_UNAUTHORIZED_Attrs = JSC::PropertyAttribute::CustomAccessor | 0;
    if (!hasNodeTLSRejectUnauthorized) {
        NODE_TLS_REJECT_UNAUTHORIZED_Attrs |= JSC::PropertyAttribute::DontEnum;
    }
    if (isEnvironmentVariableAllowed(NODE_TLS_REJECT_UNAUTHORIZED)) object->putDirectCustomAccessor(
        vm,
        Identifier::fromString(vm, NODE_TLS_REJECT_UNAUTHORIZED), JSC::CustomGetterSetter::create(vm, jsNodeTLSRejectUnauthorizedGetter, jsNodeTLSRejectUnauthorizedSetter), NODE_TLS_REJECT_UNAUTHORIZED_Attrs);

    unsigned int BUN_CONFIG_VERBOSE_FETCH_Attrs = JSC::PropertyAttribute::CustomAccessor | 0;
    if (!hasBunConfigVerboseFetch) {
        BUN_CONFIG_VERBOSE_FETCH_Attrs |= JSC::PropertyAttribute::DontEnum;
    }
    if (isEnvironmentVariableAllowed(BUN_CONFIG_VERBOSE_FETCH)) object->putDirectCustomAccessor(
        vm,
        Identifier::fromString(vm, BUN_CONFIG_VERBOSE_FETCH), JSC::CustomGetterSetter::create(vm, jsBunConfigVerboseFetchGetter, jsBunConfigVerboseFetchSetter), BUN_CONFIG_VERBOSE_FETCH_Attrs);

    for (size_t j = 0; j < proxyVarCount; j++) {
        if (!isEnvironmentVariableAllowed(String(proxyVarNames[j]))) continue;
        // Known limitation: `delete process.env.NO_PROXY` removes the accessor
        // without calling the setter, leaving the native env map stale (same as TZ).
        // Use `process.env.NO_PROXY = ""` to unset. DontDelete would throw in
        // strict mode, so we leave it deletable and document the gap.
        unsigned attrs = JSC::PropertyAttribute::CustomAccessor | 0;
        if (!hasProxyVar[j]) {
            attrs |= JSC::PropertyAttribute::DontEnum;
        }
        object->putDirectCustomAccessor(
            vm,
            Identifier::fromString(vm, proxyVarNames[j]),
            proxy_getter_setter,
            attrs);
    }

#if OS(WINDOWS)
    if (Bun__Process__environmentRestricted()) return object;
    auto editWindowsEnvVar = JSC::JSFunction::create(vm, globalObject, 0, String("editWindowsEnvVar"_s), jsEditWindowsEnvVar, ImplementationVisibility::Public);

    JSC::JSFunction* getSourceEvent = JSC::JSFunction::create(vm, globalObject, processObjectInternalsWindowsEnvCodeGenerator(vm), globalObject);
    RETURN_IF_EXCEPTION(scope, {});
    JSC::MarkedArgumentBuffer args;
    args.append(object);
    args.append(keyArray);
    args.append(editWindowsEnvVar);
    auto clientData = WebCore::clientData(vm);
    JSC::CallData callData = JSC::getCallData(getSourceEvent);
    NakedPtr<JSC::Exception> returnedException = nullptr;
    auto result = JSC::profiledCall(globalObject, JSC::ProfilingReason::API, getSourceEvent, callData, globalObject->globalThis(), args, returnedException);
    RETURN_IF_EXCEPTION(scope, {});

    if (returnedException) {
        throwException(globalObject, scope, returnedException.get());
        return jsUndefined();
    }

    RELEASE_AND_RETURN(scope, result);
#else
    return object;
#endif
}
}

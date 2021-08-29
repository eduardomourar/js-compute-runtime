#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>

#include "js-compute-builtins.h"

#include "js/Array.h"
#include "js/ArrayBuffer.h"
#include "js/Conversions.h"
#include "js/experimental/TypedData.h"
#include "js/JSON.h"
#include "js/shadow/Object.h"
#include "js/Stream.h"
#include "js/Value.h"

using JS::CallArgs;
using JS::CallArgsFromVp;
using JS::UniqueChars;

using JS::Value;

using JS::RootedValue;
using JS::RootedObject;
using JS::RootedString;

using JS::HandleValue;
using JS::HandleValueArray;
using JS::HandleObject;
using JS::HandleString;
using JS::MutableHandleValue;

using JS::PersistentRooted;

// Ensure that all the things we want to use the hostcall buffer for actually fit into the buffer.
#define HOSTCALL_BUFFER_LEN 8000


class OwnedHostCallBuffer {
  static char* hostcall_buffer;
  char* borrowed_buffer;

public:
  static bool initialize(JSContext* cx) {
    // Ensure the buffer is all zeros so it doesn't add too much to the snapshot.
    hostcall_buffer = (char*)js_calloc(HOSTCALL_BUFFER_LEN);
    return !!hostcall_buffer;
  }

  OwnedHostCallBuffer() {
    MOZ_RELEASE_ASSERT(hostcall_buffer != nullptr);
    borrowed_buffer = hostcall_buffer;
    hostcall_buffer = nullptr;
  }

  char* get() {
    return borrowed_buffer;
  }

  ~OwnedHostCallBuffer() {
    // TODO: consider adding a build config that makes this zero the buffer.
    hostcall_buffer = borrowed_buffer;
  }
};

char* OwnedHostCallBuffer::hostcall_buffer;

// TODO: introduce a version that writes into an existing buffer, and use that
// with the hostcall buffer where possible.
UniqueChars encode(JSContext* cx, HandleString str, size_t* encoded_len) {
  UniqueChars text = JS_EncodeStringToUTF8(cx, str);
  if (!text)
    return nullptr;

  // This shouldn't fail, since the encode operation ensured `str` is linear.
  JSLinearString* linear = JS_EnsureLinearString(cx, str);
  *encoded_len = JS::GetDeflatedUTF8StringLength(linear);
  return text;
}

UniqueChars encode(JSContext* cx, HandleValue val, size_t* encoded_len) {
  RootedString str(cx, JS::ToString(cx, val));
  if (!str) return nullptr;

  return encode(cx, str, encoded_len);
}

#define HANDLE_RESULT(cx, result) \
  handle_result(cx, result, __LINE__, __func__)

#define DBG(...) \
  printf("%s#%d: ", __func__, __LINE__); printf(__VA_ARGS__); fflush(stdout);

JSObject* PromiseRejectedWithPendingError(JSContext* cx) {
  RootedValue exn(cx);
  if (!JS_IsExceptionPending(cx) || !JS_GetPendingException(cx, &exn)) {
    return nullptr;
  }
  JS_ClearPendingException(cx);
  return JS::CallOriginalPromiseReject(cx, exn);
}

inline bool ReturnPromiseRejectedWithPendingError(JSContext* cx, const JS::CallArgs& args) {
  JSObject* promise = PromiseRejectedWithPendingError(cx);
  if (!promise) {
    return false;
  }

  args.rval().setObject(*promise);
  return true;
}

#define HANDLE_READ_CHUNK_SIZE 1024

template<auto op, class HandleType>
static char* read_from_handle_all(JSContext* cx, HandleType handle,
                                  size_t* nwritten, bool read_until_zero)
{
  // TODO: investigate passing a size hint in situations where we might know
  // the final size, e.g. via the `content-length` header.
  size_t buf_size = HANDLE_READ_CHUNK_SIZE;
  // TODO: make use of malloc slack.
  char* buf = static_cast<char*>(JS_malloc(cx, buf_size));
  if (!buf) {
      return nullptr;
  }

  // For realloc below.
  char* new_buf;

  size_t offset = 0;
  while (true) {
      size_t num_written = 0;
      int result = op(handle, buf + offset, HANDLE_READ_CHUNK_SIZE, &num_written);
      if (!HANDLE_RESULT(cx, result)) {
          JS_free(cx, buf);
          return nullptr;
      }

      offset += num_written;
      if (num_written == 0 ||
          (!read_until_zero && num_written < HANDLE_READ_CHUNK_SIZE))
      {
          break;
      }

      // TODO: make use of malloc slack, and use a smarter buffer growth strategy.
      size_t new_size = buf_size + HANDLE_READ_CHUNK_SIZE;
      new_buf = static_cast<char*>(JS_realloc(cx, buf, buf_size, new_size));
      if (!new_buf) {
        JS_free(cx, buf);
        return nullptr;
      }
      buf = new_buf;

      buf_size += HANDLE_READ_CHUNK_SIZE;
  }

  new_buf = static_cast<char*>(JS_realloc(cx, buf, buf_size, offset + 1));
  if (!buf) {
    JS_free(cx, buf);
    return nullptr;
  }
  buf = new_buf;

  buf[offset] = '\0';
  *nwritten = offset;

  return buf;
}

#define MULTI_VALUE_HOSTCALL(op, accum) \
    uint32_t cursor = 0; \
    int64_t ending_cursor = 0; \
    size_t nwritten; \
 \
    while (true) { \
        op \
 \
        if (nwritten == 0) { \
            break; \
        } \
 \
        accum \
 \
        if (ending_cursor < 0) { \
            break; \
        } \
 \
        cursor = (uint32_t)ending_cursor; \
    }

#define CLASS_BOILERPLATE_CUSTOM_INIT(cls) \
  const JSClass class_ = { #cls, JSCLASS_HAS_RESERVED_SLOTS(Slots::Count) | class_flags, \
                           &class_ops }; \
  static PersistentRooted<JSObject*> proto_obj; \
 \
  bool is_instance(JSObject* obj) { \
    return JS::GetClass(obj) == &class_; \
  } \
 \
  bool is_instance(JS::Value val) { \
    return val.isObject() && is_instance(&val.toObject()); \
  } \
 \
  bool check_receiver(JSContext* cx, HandleObject self, const char* method_name) { \
    if (!is_instance(self)) { \
      JS_ReportErrorUTF8(cx, "Method %s called on receiver that's not an instance of %s\n", \
                         method_name, class_.name); \
      return false; \
    } \
    return true; \
  }; \
 \
  bool init_class_impl(JSContext* cx, HandleObject global, \
                                    HandleObject parent_proto = nullptr) \
  { \
    proto_obj.init(cx, JS_InitClass(cx, global, parent_proto, &class_, constructor, ctor_length, \
                                    properties, methods, nullptr, nullptr)); \
    return proto_obj; \
  }; \

#define CLASS_BOILERPLATE(cls) \
  CLASS_BOILERPLATE_CUSTOM_INIT(cls) \
 \
  bool init_class(JSContext* cx, HandleObject global) { \
    return init_class_impl(cx, global); \
  } \

#define CLASS_BOILERPLATE_NO_CTOR(cls) \
  bool constructor(JSContext* cx, unsigned argc, Value* vp) { \
    JS_ReportErrorUTF8(cx, #cls " can't be instantiated directly"); \
    return false; \
  } \
 \
  CLASS_BOILERPLATE_CUSTOM_INIT(cls) \
 \
  bool init_class(JSContext* cx, HandleObject global) { \
    /* Right now, deleting the ctor from the global object after class \
       initialization seems to be the best we can do. Not ideal, but works. */ \
    return init_class_impl(cx, global) && \
           JS_DeleteProperty(cx, global, class_.name); \
  } \

namespace Compute {

  static bool debug_logging_enabled = false;

  bool dump(JSContext* cx, unsigned argc, Value* vp) {
    CallArgs args = CallArgsFromVp(argc, vp);
    if (!args.requireAtLeast(cx, __func__, 1))
      return false;

    dump_value(cx, args[0], stdout);

    args.rval().setUndefined();
    return true;
  }

  bool enableDebugLogging(JSContext* cx, unsigned argc, Value* vp) {
    CallArgs args = CallArgsFromVp(argc, vp);
    if (!args.requireAtLeast(cx, __func__, 1))
      return false;

    debug_logging_enabled = JS::ToBoolean(args[0]);

    args.rval().setUndefined();
    return true;
  }

  bool includeBytes(JSContext* cx, unsigned argc, Value* vp) {
    CallArgs args = CallArgsFromVp(argc, vp);
    RootedObject self(cx, &args.thisv().toObject());
    if (!args.requireAtLeast(cx, "compute.includeBytes", 1))
      return false;

    size_t path_len;
    UniqueChars path = encode(cx, args[0], &path_len);
    if (!path) return false;

    FILE* fp = fopen(path.get(), "r");
    if (!fp) {
      JS_ReportErrorUTF8(cx, "Error opening file %s", path.get());
      return false;
    }

    fseek(fp, 0L, SEEK_END);
    size_t size = ftell(fp);
    rewind(fp);
    RootedObject typed_array(cx, JS_NewUint8Array(cx, size));
    if (!typed_array) return false;

    size_t read_bytes;
    {
      JS::AutoCheckCannotGC noGC(cx);
      bool is_shared;
      void* buffer = JS_GetArrayBufferViewData(typed_array, &is_shared, noGC);
      read_bytes = fread(buffer, 1, size, fp);
    }

    if (read_bytes != size) {
      JS_ReportErrorUTF8(cx, "Failed to read contents of file %s", path.get());
      return false;
    }

    args.rval().setObject(*typed_array);
    return true;
  }

  const JSFunctionSpec methods[] = {
    JS_FN("dump", dump, 1, 0),
    JS_FN("enableDebugLogging", enableDebugLogging, 1, JSPROP_ENUMERATE),
    JS_FN("includeBytes", includeBytes, 1, JSPROP_ENUMERATE),
    JS_FS_END
  };

  static bool create(JSContext* cx, HandleObject global) {
    RootedObject compute(cx, JS_NewPlainObject(cx));
    if (!compute) return false;

    if (!JS_DefineProperty(cx, global, "compute", compute, 0)) return false;
    return JS_DefineFunctions(cx, compute, methods);
  }
}

namespace Console {
  template<const char* prefix, uint8_t prefix_len>
  static bool console_out(JSContext* cx, unsigned argc, Value* vp) {
    CallArgs args = CallArgsFromVp(argc, vp);
    size_t msg_len;
    UniqueChars msg = encode(cx, args.get(0), &msg_len);
    if (!msg) return false;

    printf("%s: %s\n", prefix, msg.get());
    fflush(stdout);

    args.rval().setUndefined();
    return true;
  }

  static constexpr char PREFIX_LOG[] = "Log";
  static constexpr char PREFIX_TRACE[] = "Trace";
  static constexpr char PREFIX_INFO[] = "Info";
  static constexpr char PREFIX_WARN[] = "Warn";
  static constexpr char PREFIX_ERROR[] = "Error";

  const JSFunctionSpec methods[] = {
    JS_FN("log", (console_out<PREFIX_LOG, 3>), 1, JSPROP_ENUMERATE),
    JS_FN("trace", (console_out<PREFIX_TRACE, 5>), 1, JSPROP_ENUMERATE),
    JS_FN("info", (console_out<PREFIX_INFO, 4>), 1, JSPROP_ENUMERATE),
    JS_FN("warn", (console_out<PREFIX_WARN, 4>), 1, JSPROP_ENUMERATE),
    JS_FN("error", (console_out<PREFIX_ERROR, 5>), 1, JSPROP_ENUMERATE),
    JS_FS_END
  };

  static bool create(JSContext* cx, HandleObject global) {
    RootedObject console(cx, JS_NewPlainObject(cx));
    if (!console) return false;
    if (!JS_DefineProperty(cx, global, "console", console, JSPROP_ENUMERATE)) return false;
    return JS_DefineFunctions(cx, console, methods);
  }
}

bool is_int_typed_array(JSObject* obj) {
  return JS_IsInt8Array(obj) ||
         JS_IsUint8Array(obj) ||
         JS_IsInt16Array(obj) ||
         JS_IsUint16Array(obj) ||
         JS_IsInt32Array(obj) ||
         JS_IsUint32Array(obj) ||
         JS_IsUint8ClampedArray(obj);
}

namespace Crypto {

  #define MAX_BYTE_LENGTH 65536

  /**
   * Implementation of https://www.w3.org/TR/WebCryptoAPI/#Crypto-method-getRandomValues
   * TODO: investigate ways to automatically wipe the buffer passed in here when it is
   * GC'd. Content can roughly approximate that using finalizers for views of the buffer,
   * but it's far from ideal.
   */
  bool get_random_values(JSContext* cx, unsigned argc, Value* vp) {
    CallArgs args = CallArgsFromVp(argc, vp);
    if (!args.requireAtLeast(cx, "crypto.getRandomValues", 1))
      return false;

    if (!args[0].isObject() || !is_int_typed_array(&args[0].toObject())) {
      JS_ReportErrorUTF8(cx, "crypto.getRandomValues: input must be an integer-typed TypedArray");
      return false;
    }

    RootedObject typed_array(cx, &args[0].toObject());
    size_t byte_length = JS_GetArrayBufferViewByteLength(typed_array);
    if (byte_length > MAX_BYTE_LENGTH) {
      JS_ReportErrorUTF8(cx, "crypto.getRandomValues: input byteLength must be at most %u, "
                              "but is %zu", MAX_BYTE_LENGTH, byte_length);
        return false;
    }

    JS::AutoCheckCannotGC noGC(cx);
    bool is_shared;
    void* buffer = JS_GetArrayBufferViewData(typed_array, &is_shared, noGC);
    arc4random_buf(buffer, byte_length);

    args.rval().setObject(*typed_array);
    return true;
  }

  const JSFunctionSpec methods[] = {
    JS_FN("getRandomValues", get_random_values, 1, JSPROP_ENUMERATE),
    JS_FS_END
  };

  static bool create(JSContext* cx, HandleObject global) {
    RootedObject crypto(cx, JS_NewPlainObject(cx));
    if (!crypto) return false;
    if (!JS_DefineProperty(cx, global, "crypto", crypto, JSPROP_ENUMERATE)) return false;
    return JS_DefineFunctions(cx, crypto, methods);
  }
}

bool define_compute_sys(JSContext* cx, HandleObject global) {
  // Allocating the reusable hostcall buffer here means it's baked into the
  // snapshot, and since it's all zeros, it won't increase the size of the snapshot.
  if (!OwnedHostCallBuffer::initialize(cx)) return false;
  if (!JS_DefineProperty(cx, global, "self", global, JSPROP_ENUMERATE)) return false;

  if (!Compute::create(cx, global)) return false;
  if (!Console::create(cx, global)) return false;
  if (!Crypto::create(cx, global)) return false;

  return true;
}

UniqueChars stringify_value(JSContext* cx, JS::HandleValue value) {
  JS::RootedString str(cx, JS_ValueToSource(cx, value));
  if (!str)
  return nullptr;

  return JS_EncodeStringToUTF8(cx, str);
}

bool debug_logging_enabled() {
  return Compute::debug_logging_enabled;
}

bool dump_value(JSContext* cx, JS::Value val, FILE* fp) {
  RootedValue value(cx, val);
  UniqueChars utf8chars = stringify_value(cx, value);
  if (!utf8chars)
    return false;
  fprintf(fp, "%s\n", utf8chars.get());
  return true;
}

bool print_stack(JSContext* cx, HandleObject stack, FILE* fp) {
  RootedString stackStr(cx);
  if (!BuildStackString(cx, nullptr, stack, &stackStr, 2)) {
    return false;
  }
  size_t stack_len;

  UniqueChars utf8chars = encode(cx, stackStr, &stack_len);
  if (!utf8chars)
    return false;
  fprintf(fp, "%s\n", utf8chars.get());
  return true;
}

bool print_stack(JSContext* cx, FILE* fp) {
  RootedObject stackp(cx);
  if (!JS::CaptureCurrentStack(cx, &stackp))
    return false;
  return print_stack(cx, stackp, fp);
}

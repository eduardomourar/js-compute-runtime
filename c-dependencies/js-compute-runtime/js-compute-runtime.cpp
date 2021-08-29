#include <cassert>
#include <cstdlib>
#include <vector>
#include <iostream>
#include <chrono>
#ifdef MEM_STATS
#include <string>
#endif

#include <wasi/libc-environ.h>

// TODO: remove these once the warnings are fixed
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winvalid-offsetof"

#include "js/CompilationAndEvaluation.h"
#include "js/ContextOptions.h"
#include "js/Conversions.h"
#include "js/Initialization.h"
#include "js/JSON.h"
#include "js/SourceText.h"
#include "js/Value.h"

#pragma clang diagnostic pop

#include "js-compute-builtins.h"
#include "wizer.h"
#ifdef MEM_STATS
#include "memory-reporting.h"
#endif

using std::chrono::duration_cast;
using std::chrono::microseconds;
using std::chrono::system_clock;

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
using JS::PersistentRootedVector;

#ifdef MEM_STATS
size_t size_of_cb(const void* ptr) {
  return ptr ? sizeof(ptr) : 0;
}

static bool dump_mem_stats(JSContext* cx) {
  SimpleJSRuntimeStats rtStats(&size_of_cb);
  if (!JS::CollectRuntimeStats(cx, &rtStats, nullptr, false))
    return false;
  std::string rtPath = "rt";
  size_t rtTotal;
  ReportJSRuntimeExplicitTreeStats(rtStats, rtPath, nullptr, false, &rtTotal);

  printf("compartment counts: %zu sys, %zu usr\n", JS::SystemCompartmentCount(cx), JS::UserCompartmentCount(cx));
  printf("GC heap total: %zu\n", size_t(JS_GetGCParameter(cx, JSGC_TOTAL_CHUNKS)) * js::gc::ChunkSize);
  printf("GC heap unused: %zu\n", size_t(JS_GetGCParameter(cx, JSGC_UNUSED_CHUNKS)) * js::gc::ChunkSize);

  return true;
}
#endif // MEM_STATS

/* The class of the global object. */
static JSClass global_class = {
    "global",
    JSCLASS_GLOBAL_FLAGS,
    &JS::DefaultGlobalClassOps
};

bool INITIALIZED = false;
JSContext* CONTEXT = nullptr;

JS::PersistentRootedObject GLOBAL;
JS::PersistentRootedObject unhandledRejectedPromises;

static JS::PersistentRootedObjectVector* EVENT_HANDLERS;

void gc_callback(JSContext* cx, JSGCStatus status, JS::GCReason reason, void* data) {
  if (debug_logging_enabled())
    printf("gc for reason %s, %s\n", JS::ExplainGCReason(reason), status ? "end" : "start");
}

static void rejection_tracker(JSContext* cx, bool mutedErrors, JS::HandleObject promise,
                              JS::PromiseRejectionHandlingState state, void* data)
{
  RootedValue promiseVal(cx, JS::ObjectValue(*promise));

  switch (state) {
    case JS::PromiseRejectionHandlingState::Unhandled: {
      if (!JS::SetAdd(cx, unhandledRejectedPromises, promiseVal)) {
        // Note: we unconditionally print these, since they almost always indicate serious bugs.
        fprintf(stderr, "Adding an unhandled rejected promise to the promise "
                        "rejection tracker failed");
      }
      return;
    }
    case JS::PromiseRejectionHandlingState::Handled: {
      bool deleted = false;
      if (!JS::SetDelete(cx, unhandledRejectedPromises, promiseVal, &deleted)) {
        // Note: we unconditionally print these, since they almost always indicate serious bugs.
        fprintf(stderr, "Removing an handled rejected promise from the promise "
                        "rejection tracker failed");
      }
    }
  }
}

bool init_js() {
  JS_Init();

  JSContext *cx = JS_NewContext(JS::DefaultHeapMaxBytes);
  if (!cx)
      return false;
  if (!js::UseInternalJobQueues(cx) || !JS::InitSelfHostedCode(cx))
      return false;

  JS::ContextOptionsRef(cx)
    .setPrivateClassFields(true)
    .setPrivateClassMethods(true)
    .setErgnomicBrandChecks(true);

  // TODO: check if we should set a different creation zone.
  JS::RealmOptions options;
  options.creationOptions()
    .setStreamsEnabled(true)
    .setReadableByteStreamsEnabled(true)
    .setBYOBStreamReadersEnabled(true)
    .setReadableStreamPipeToEnabled(true)
    .setWritableStreamsEnabled(true)
    .setIteratorHelpersEnabled(true)
    .setWeakRefsEnabled(JS::WeakRefSpecifier::EnabledWithoutCleanupSome);

  JS::DisableIncrementalGC(cx);
  // JS_SetGCParameter(cx, JSGC_MAX_EMPTY_CHUNK_COUNT, 1);

  RootedObject global(cx, JS_NewGlobalObject(cx, &global_class, nullptr, JS::FireOnNewGlobalHook,
                                             options));
  if (!global)
      return false;

  JSAutoRealm ar(cx, global);
  if (!JS::InitRealmStandardClasses(cx))
    return false;

  JS::SetPromiseRejectionTrackerCallback(cx, rejection_tracker);

  CONTEXT = cx;
  GLOBAL.init(cx, global);
  unhandledRejectedPromises.init(cx, JS::NewSetObject(cx));
  if (!unhandledRejectedPromises)
    return false;

  return true;
}

static bool report_unhandled_promise_rejections(JSContext* cx) {
  RootedValue iterable(cx);
  if (!JS::SetValues(cx, unhandledRejectedPromises, &iterable))
    return false;

  JS::ForOfIterator it(cx);
  if (!it.init(iterable))
    return false;

  RootedValue promise_val(cx);
  RootedObject promise(cx);
  while (true) {
    bool done;
    if (!it.next(&promise_val, &done))
      return false;

    if (done)
      break;

    promise = &promise_val.toObject();
    // Note: we unconditionally print these, since they almost always indicate serious bugs.
    fprintf(stderr, "Promise rejected but never handled: ");
    dump_value(cx, JS::GetPromiseResult(promise), stderr);
  }

  return true;
}

static void DumpPendingException(JSContext* cx, const char* description) {
  JS::ExceptionStack exception(cx);
  if (!JS::GetPendingExceptionStack(cx, &exception)) {
    fprintf(stderr, "Error: exception pending after %s, but got another error "
            "when trying to retrieve it. Aborting.\n", description);
  } else {
    fprintf(stderr, "Exception while %s: ", description);
    dump_value(cx, exception.exception(), stderr);
    print_stack(cx, exception.stack(), stderr);
  }
}

static void abort(JSContext* cx, const char* description) {
  // Note: we unconditionally print messages here, since they almost always indicate serious bugs.
  if (JS_IsExceptionPending(cx)) {
    DumpPendingException(cx, description);
  } else {
    fprintf(stderr, "Error while %s, but no exception is pending. "
            "Aborting, since that doesn't seem recoverable at all.\n", description);
  }

  if (JS::SetSize(cx, unhandledRejectedPromises) > 0) {
    fprintf(stderr,
            "Additionally, some promises were rejected, but the rejection never handled:\n");
    report_unhandled_promise_rejections(cx);
  }

  fflush(stderr);
  exit(1);
}

bool eval_stdin(JSContext* cx, MutableHandleValue result) {
  char* code = NULL;
  size_t len = 0;
  if (getdelim(&code, &len, EOF, stdin) < 0) {
      return false;
  }

  JS::CompileOptions opts(cx);
  opts.setForceFullParse();
  // TODO: investigate passing a filename to Wizer and using that here to improve diagnostics.
  // TODO: furthermore, investigate whether Wizer by now allows us to pass an actual path
  // and open that, instead of having to redirect `stdin` for a subprocess of `js-compute-runtime`.
  opts.setFileAndLine("<stdin>", 1);

  JS::SourceText<mozilla::Utf8Unit> srcBuf;
  if (!srcBuf.init(cx, code, strlen(code), JS::SourceOwnership::TakeOwnership)) {
      return false;
  }

  JS::RootedScript script(cx);
  {
    // Disabling GGC during compilation seems to slightly reduce the number of
    // pages touched post-deploy.
    // (Whereas disabling it during execution below meaningfully increases it,
    // which is why this is scoped to just compilation.)
    JS::AutoDisableGenerationalGC noGGC(cx);
    script = JS::Compile(cx, opts, srcBuf);
    if (!script) return false;
  }

  // TODO: verify that it's better to perform a shrinking GC here, as manual testing
  // indicates. Running a shrinking GC here causes *fewer* 4kb pages to be written to when
  // processing a request, at least for one fairly large input script.
  //
  // A hypothesis for why this is the case could be that the objects allocated by parsing
  // the script (but not evaluating it) tend to be read-only, so optimizing them for
  // compactness makes sense and doesn't fragment writes later on.
  JS::PrepareForFullGC(cx);
  JS::NonIncrementalGC(cx, JS::GCOptions::Shrink, JS::GCReason::API);

  if (!JS_ExecuteScript(cx, script, result))
    return false;

  // TODO: check if it makes sense to increase the empty chunk count *before* running GC like this.
  // The working theory is that otherwise the engine might mark chunk pages as free that then later
  // the allocator doesn't turn into chunks without further fragmentation. But that might be wrong.
  // JS_SetGCParameter(cx, JSGC_MAX_EMPTY_CHUNK_COUNT, 10);

  // TODO: verify that it's better to *not* perform a shrinking GC here, as manual testing
  // indicates. Running a shrinking GC here causes *more* 4kb pages to be written to when
  // processing a request, at least for one fairly large input script.
  //
  // A hypothesis for why this is the case could be that most writes are to object kinds that are
  // initially allocated in the same vicinity, but that the shrinking GC causes them to be
  // intermingled with other objects. I.e., writes become more fragmented due to the shrinking GC.
  JS::PrepareForFullGC(cx);
  JS::NonIncrementalGC(cx, JS::GCOptions::Normal, JS::GCReason::API);

  // Ignore the first GC, but then print all others, because ideally GCs
  // should be rare, and developers should know about them.
  // TODO: consider exposing a way to parameterize this, and/or specifying a dedicated log target
  // for telemetry messages like this.
  JS_SetGCCallback(cx, gc_callback, nullptr);

  return true;
}

void init() {
    assert(!INITIALIZED);

  if (!init_js())
    exit(1);

  JSContext* cx = CONTEXT;
  RootedObject global(cx, GLOBAL);
  JSAutoRealm ar(cx, global);
  EVENT_HANDLERS = new JS::PersistentRootedObjectVector(cx);

  define_compute_sys(cx, global);

  RootedValue result(cx);
  if (!eval_stdin(cx, &result))
    abort(cx, "evaluating JS");

  if (EVENT_HANDLERS->length() == 0) {
    RootedValue val(cx);
    if (!JS_GetProperty(cx, global, "main", &val) ||
        !val.isObject() || !JS_ObjectIsFunction(&val.toObject()))
    {
      fprintf(stderr, "Error: no `main` event handler registered during initialization.\n");
      exit(1);
    }
    if (!EVENT_HANDLERS->append(&val.toObject()))
      abort(cx, "Adding main as a event handler");
  }

  fflush(stdout);
  fflush(stderr);

  // Define this to print a simple memory usage report.
#ifdef MEM_STATS
  dump_mem_stats(cx);
#endif

  INITIALIZED = true;
}

WIZER_INIT(init);

static void dispatch_event(JSContext* cx, HandleString event, double* total_compute) {
  auto pre_handler = system_clock::now();

  RootedValue result(cx);
  RootedValue event_val(cx);
  event_val.setString(event);
  HandleValueArray argsv = HandleValueArray(event_val);
  RootedValue handler(cx);
  RootedValue rval(cx);

  if (debug_logging_enabled())
    printf("Preparing event handler (%zu)...\n", EVENT_HANDLERS->length());

  handler.setObject(*(*EVENT_HANDLERS)[0]);
  if (!JS_CallFunctionValue(cx, GLOBAL, handler, argsv, &rval)) {
    DumpPendingException(cx, "dispatching event\n");
    JS_ClearPendingException(cx);
  }

  double diff = duration_cast<microseconds>(system_clock::now() - pre_handler).count();
  *total_compute += diff;
  if (debug_logging_enabled())
    printf("Request handler took %fms\n", diff / 1000);
}

static void process_pending_jobs(JSContext* cx, double* total_compute) {
  auto pre_reactions = system_clock::now();
  if (debug_logging_enabled()) {
    printf("Running promise reactions\n");
    fflush(stdout);
  }

  while (js::HasJobsPending(cx)) {
    js::RunJobs(cx);

    if (JS_IsExceptionPending(cx))
      abort(cx, "running Promise reactions");
  }

  double diff = duration_cast<microseconds>(system_clock::now() - pre_reactions).count();
  *total_compute += diff;
  if (debug_logging_enabled())
    printf("Running promise reactions took %fms\n", diff / 1000);
}

static void wait_for_backends(JSContext* cx, double* total_compute) {
  auto pre_requests = system_clock::now();
  if (debug_logging_enabled()) {
    printf("Waiting for backends ...\n");
    fflush(stdout);
  }

  double diff = duration_cast<microseconds>(system_clock::now() - pre_requests).count();
  if (debug_logging_enabled())
    printf("Done, waited for %fms\n", diff / 1000);
}

int main(int argc, const char *argv[]) {
  if (!INITIALIZED) {
    init();
    assert(INITIALIZED);
  }

  double total_compute = 0;
  auto start = system_clock::now();

  __wasilibc_initialize_environ();

  std::vector<std::string> args(argv, argv + argc);
  std::string input = args.at(1);

  if (debug_logging_enabled()) {
    printf("Running JS handleRequest function for service\n");
    printf("[0] %s [1} %s\n", args[0].c_str(), input.c_str());
    fflush(stdout);
  }

  JSContext* cx = CONTEXT;
  JSAutoRealm ar(cx, GLOBAL);
  js::ResetMathRandomSeed(cx);

  RootedString event(cx, JS_NewStringCopyN(cx, input.c_str(), input.length()));

  dispatch_event(cx, event, &total_compute);

  // Loop until no more resolved promises or backend requests are pending.
  if (debug_logging_enabled()) {
    printf("Start processing async jobs ...\n");
    fflush(stdout);
  }

  do {
    // First, drain the promise reactions queue.
    process_pending_jobs(cx, &total_compute);

    // Process async tasks.
    wait_for_backends(cx, &total_compute);
  } while (js::HasJobsPending(cx));

  if (JS::SetSize(cx, unhandledRejectedPromises) > 0) {
    report_unhandled_promise_rejections(cx);
  }

  auto end = system_clock::now();
  double diff = duration_cast<microseconds>(end - start).count();
  if (debug_logging_enabled()) {
    printf("Done. Total request processing time: %fms. Total compute time: %fms\n",
           diff / 1000, total_compute / 1000);
  }

  // Note: we deliberately skip shutdown, because it takes quite a while,
  // and serves no purpose for us.
  // TODO: investigate also skipping the destructors deliberately run in wizer.h.
  // GLOBAL = nullptr;
  // CONTEXT = nullptr;
  // JS_DestroyContext(cx);
  // JS_ShutDown();

  return 0;
}

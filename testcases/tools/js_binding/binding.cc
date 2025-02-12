#include <node.h>
#include <v8.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>

using v8::Context;
using v8::Isolate;
using v8::Local;

#define SYS_sc_snapshot       0x1000
#define SYS_sc_print_stat     0x1001
#define SYS_sc_start_polling  0x1002
#define SYS_sc_get_stat       0x1004

static void SCSnapshot(const v8::FunctionCallbackInfo<v8::Value>& args) {
  syscall(SYS_sc_snapshot);
}

static void StatAtImportDone(const v8::FunctionCallbackInfo<v8::Value>& args) {
  syscall(SYS_sc_print_stat, "import_done");
}

static void StatAtFuncDone(const v8::FunctionCallbackInfo<v8::Value>& args) {
  syscall(SYS_sc_print_stat, "func_done");
}

static void StatGetStat(const v8::FunctionCallbackInfo<v8::Value>& args) {
  Isolate* isolate = args.GetIsolate();
  Local<Context> context = isolate->GetCurrentContext();
  double stat = args[0]->NumberValue(context).FromMaybe(0);
  args.GetReturnValue().Set((double)syscall(SYS_sc_get_stat, (int)stat));
}

static void CRIUSnapshot(const v8::FunctionCallbackInfo<v8::Value>& args) {
  int fd, ret;
  char flag;
  
  fd = open("/criu/restore_flag", O_RDONLY);
  assert(fd >= 0);

  do {
    ret = pread(fd, &flag, 1, 0);
    assert(ret == 1);
  } while (flag == '0');

  close(fd);
}

static void StartPolling(const v8::FunctionCallbackInfo<v8::Value>& args) {
  syscall(SYS_sc_start_polling);
}

// Not using the full NODE_MODULE_INIT() macro here because we want to test the
// addon loader's reaction to the FakeInit() entry point below.
extern "C" NODE_MODULE_EXPORT void
NODE_MODULE_INITIALIZER(v8::Local<v8::Object> exports,
                        v8::Local<v8::Value> module,
                        v8::Local<v8::Context> context) {
  NODE_SET_METHOD(exports, "sc_snapshot", SCSnapshot);
  NODE_SET_METHOD(exports, "stat_at_import_done", StatAtImportDone);
  NODE_SET_METHOD(exports, "stat_at_func_done", StatAtFuncDone);
  NODE_SET_METHOD(exports, "criu_snapshot", CRIUSnapshot);
  NODE_SET_METHOD(exports, "start_polling", StartPolling);
  NODE_SET_METHOD(exports, "stat_get_stat", StatGetStat);
}

static void FakeInit(v8::Local<v8::Object> exports,
                     v8::Local<v8::Value> module,
                     v8::Local<v8::Context> context) {
  auto isolate = context->GetIsolate();
  auto exception = v8::Exception::Error(v8::String::NewFromUtf8(isolate,
      "FakeInit should never run!").ToLocalChecked());
  isolate->ThrowException(exception);
}

// Define a Node.js module, but with the wrong version. Node.js should still be
// able to load this module, multiple times even, because it exposes the
// specially named initializer above.
#undef NODE_MODULE_VERSION
#define NODE_MODULE_VERSION 3
NODE_MODULE(NODE_GYP_MODULE_NAME, FakeInit)
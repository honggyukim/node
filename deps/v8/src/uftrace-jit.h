// Copyright 2018 the V8 project authors. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef V8_UFTRACE_JIT_H_
#define V8_UFTRACE_JIT_H_

#include "src/log.h"

namespace v8 {
namespace internal {

#if V8_OS_LINUX

// Linux uftrace tool logging support
class UftraceJitLogger : public CodeEventLogger {
#define NSEC_PER_SEC  1000000000
#define NSEC_PER_MSEC 1000000

#define RECORD_MAGIC_V3  0xa
#define RECORD_MAGIC_V4  0x5
#define RECORD_MAGIC     RECORD_MAGIC_V4
 public:
  explicit UftraceJitLogger(Isolate* isolate);
  virtual ~UftraceJitLogger();

  void CodeMoveEvent(AbstractCode* from, AbstractCode* to) override {}
  void CodeDisableOptEvent(AbstractCode* code,
                           SharedFunctionInfo* shared) override {}

  FILE* uftrace_data_handle() { return uftrace_data_handle_; }

  /* reduced version of mcount_ret_stack */
  struct uftrace_record {
      uint64_t time;
      uint64_t type:   2;
      uint64_t more:   1;
      uint64_t magic:  3;
      uint64_t depth:  10;
      uint64_t addr:   48; /* child ip or uftrace_event_id */
  };

  enum uftrace_record_type {
      UFTRACE_ENTRY,
      UFTRACE_EXIT,
      UFTRACE_LOST,
      UFTRACE_EVENT,
  };

  static inline uint64_t mcount_gettime(void)
  {
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      return (uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
  }

 private:
  void LogRecordedBuffer(AbstractCode* code, SharedFunctionInfo* shared,
                         const char* name, int length) override;
  void LogRecordedBuffer(const wasm::WasmCode* code, const char* name,
                         int length) override;
  void WriteLogRecordedBuffer(uintptr_t address, int size, const char* name,
                              int name_length);

  // Extension added to V8 log file name to get the low-level log name.
  static const char kSymbolFilenameFormatString[];
  static const char kDataFilenameFormatString[];
  static const int kFilenameBufferPadding;

  FILE* uftrace_symbol_handle_;
  FILE* uftrace_data_handle_;
};

#else

// UftraceJitLogger is only implemented on Linux
class UftraceJitLogger : public CodeEventLogger {
 public:
  void CodeMoveEvent(AbstractCode* from, Address to) override {
    UNIMPLEMENTED();
  }

  void CodeDisableOptEvent(AbstractCode* code,
                           SharedFunctionInfo* shared) override {
    UNIMPLEMENTED();
  }

  void LogRecordedBuffer(AbstractCode* code, SharedFunctionInfo* shared,
                         const char* name, int length) override {
    UNIMPLEMENTED();
  }

  void LogRecordedBuffer(const wasm::WasmCode* code, const char* name,
                         int length) override {
    UNIMPLEMENTED();
  }
};

#endif  // V8_OS_LINUX
}  // namespace internal
}  // namespace v8

#endif  // V8_UFTRACE_JIT_H_


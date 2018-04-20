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

#include "src/uftrace-jit.h"

#include <memory>

#include "src/assembler.h"
#include "src/eh-frame.h"
#include "src/instruction-stream.h"
#include "src/objects-inl.h"
#include "src/source-position-table.h"
#include "src/wasm/wasm-code-manager.h"

#if V8_OS_LINUX
#include <fcntl.h>
#include <sys/mman.h>
#undef MAP_TYPE  // jumbo: conflicts with v8::internal::InstanceType::MAP_TYPE
#include <unistd.h>
#endif  // V8_OS_LINUX

namespace v8 {
namespace internal {

#if V8_OS_LINUX

const char UftraceJitLogger::kSymbolFilenameFormatString[] = "%d.jit.sym";
const char UftraceJitLogger::kDataFilenameFormatString[] = "%d.jit.dat";
// Extra space for the PID in the filename
const int UftraceJitLogger::kFilenameBufferPadding = 16;

UftraceJitLogger::UftraceJitLogger(Isolate* isolate) : CodeEventLogger(isolate),
                                 uftrace_symbol_handle_(nullptr),
                                 uftrace_data_handle_(nullptr) {
  int bufferSize, size;

  // Open the uftrace symbol file for JITed function symbol.
  bufferSize = sizeof(kSymbolFilenameFormatString) + kFilenameBufferPadding;
  ScopedVector<char> uftrace_dump_symbol_name(bufferSize);
  size = SNPrintF(
      uftrace_dump_symbol_name,
      kSymbolFilenameFormatString,
      base::OS::GetCurrentProcessId());
  CHECK_NE(size, -1);
  uftrace_symbol_handle_ =
      base::OS::FOpen(uftrace_dump_symbol_name.start(), base::OS::LogFileOpenMode);
  CHECK_NOT_NULL(uftrace_symbol_handle_);
  setvbuf(uftrace_symbol_handle_, nullptr, _IOLBF, 0);

  // Open the uftrace data file for JITed function record.
  bufferSize = sizeof(kDataFilenameFormatString) + kFilenameBufferPadding;
  ScopedVector<char> uftrace_dump_data_name(bufferSize);
  size = SNPrintF(
      uftrace_dump_data_name,
      kDataFilenameFormatString,
      base::OS::GetCurrentProcessId());
  CHECK_NE(size, -1);
  uftrace_data_handle_ =
      base::OS::FOpen(uftrace_dump_data_name.start(), base::OS::LogFileOpenMode);
  CHECK_NOT_NULL(uftrace_data_handle_);
  setvbuf(uftrace_data_handle_, nullptr, _IOFBF, 0);
}


UftraceJitLogger::~UftraceJitLogger() {
  fclose(uftrace_symbol_handle_);
  uftrace_symbol_handle_ = nullptr;
  fclose(uftrace_data_handle_);
  uftrace_data_handle_ = nullptr;
}

void UftraceJitLogger::WriteLogRecordedBuffer(uintptr_t address, int size,
                                           const char* name,
                                           int name_length) {
  base::OS::FPrint(uftrace_symbol_handle_, "%" V8PRIxPTR " T %s\n", address,
                   name);
}

void UftraceJitLogger::LogRecordedBuffer(AbstractCode* code, SharedFunctionInfo*,
                                      const char* name, int length) {
  WriteLogRecordedBuffer(reinterpret_cast<uintptr_t>(code->InstructionStart()),
                         code->InstructionSize(), name, length);
}

void UftraceJitLogger::LogRecordedBuffer(const wasm::WasmCode* code, const char* name,
                                      int length) {
  WriteLogRecordedBuffer(
      reinterpret_cast<uintptr_t>(code->instructions().start()),
      code->instructions().length(), name, length);
}

#endif  // V8_OS_LINUX
}  // namespace internal
}  // namespace v8

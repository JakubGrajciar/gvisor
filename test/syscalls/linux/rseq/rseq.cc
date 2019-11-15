// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "test/syscalls/linux/rseq/critical.h"
#include "test/syscalls/linux/rseq/syscalls.h"
#include "test/syscalls/linux/rseq/test.h"
#include "test/syscalls/linux/rseq/types.h"
#include "test/syscalls/linux/rseq/uapi.h"

namespace gvisor {
namespace testing {

extern "C" int main(int argc, char** argv, char** envp);

// Standalone initialization before calling main().
extern "C" void __init(uintptr_t* sp) {
  int argc = sp[0];
  char** argv = reinterpret_cast<char**>(&sp[1]);
  char** envp = &argv[argc + 1];

  // Call main() and exit.
  sys_exit_group(main(argc, argv, envp));

  // sys_exit_group does not return
}

int strncmp(const char* s1, const char* s2, size_t n) {
  const unsigned char* p1 = reinterpret_cast<const unsigned char*>(s1);
  const unsigned char* p2 = reinterpret_cast<const unsigned char*>(s2);

  while (n--) {
    if (*p1 != *p2) {
      return static_cast<int>(*p1) - static_cast<int>(*p2);
    }
    if (!*p1) {
      return 0;
    }
    ++p1;
    ++p2;
  }
  return 0;
}

int RSeq(struct rseq* rseq, uint32_t rseq_len, int flags, uint32_t sig) {
  return syscall(kRseqSyscall, rseq, rseq_len, flags, sig);
}

// Test that rseq must be aligned.
int TestUnaligned() {
  constexpr uintptr_t kRequiredAlignment = alignof(rseq);

  char buf[2 * kRequiredAlignment] = {};
  uintptr_t ptr = reinterpret_cast<uintptr_t>(&buf[0]);
  if ((ptr & (kRequiredAlignment - 1)) == 0) {
    // buf is already aligned. Misalign it.
    ptr++;
  }

  int ret = RSeq(reinterpret_cast<rseq*>(ptr), sizeof(rseq), 0, 0);
  if (sys_errno(ret) != EINVAL) {
    return 1;
  }
  return 0;
}

// Sanity test that registration works.
int TestRegister() {
  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, 0);
  if (sys_errno(ret) != 0) {
    return 1;
  }
  return 0;
};

// Registration can't be done twice.
int TestDoubleRegister() {
  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, 0);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  ret = RSeq(&r, sizeof(r), 0, 0);
  if (sys_errno(ret) != EBUSY) {
    return 1;
  }

  return 0;
};

// Registration can be done again after unregister.
int TestRegisterUnregister() {
  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, 0);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  ret = RSeq(&r, sizeof(r), kRseqFlagUnregister, 0);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  ret = RSeq(&r, sizeof(r), 0, 0);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  return 0;
};

// The pointer to rseq must match on register/unregister.
int TestUnregisterDifferentPtr() {
  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, 0);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  struct rseq r2 = {};
  ret = RSeq(&r2, sizeof(r2), kRseqFlagUnregister, 0);
  if (sys_errno(ret) != EINVAL) {
    return 1;
  }

  return 0;
};

// The signature must match on register/unregister.
int TestUnregisterDifferentSignature() {
  constexpr int kSignature = 0;

  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, kSignature);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  ret = RSeq(&r, sizeof(r), kRseqFlagUnregister, kSignature + 1);
  if (sys_errno(ret) != EPERM) {
    return 1;
  }

  return 0;
};

// The CPU ID is initialized.
int TestCPU() {
  struct rseq r = {};
  r.cpu_id = kRseqCPUIDUninitialized;

  int ret = RSeq(&r, sizeof(r), 0, 0);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  if (__atomic_load_n(&r.cpu_id, __ATOMIC_RELAXED) < 0) {
    return 1;
  }
  if (__atomic_load_n(&r.cpu_id_start, __ATOMIC_RELAXED) < 0) {
    return 1;
  }

  return 0;
};

// Critical section is eventually aborted.
int TestAbort() {
  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, kRseqSignature);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  struct rseq_cs cs = {};
  cs.version = 0;
  cs.flags = 0;
  cs.start_ip = reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.post_commit_offset = reinterpret_cast<uint64_t>(&rseq_loop_post_commit) -
                          reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.abort_ip = reinterpret_cast<uint64_t>(&rseq_loop_abort);

  // Loops until abort. If this returns then abort occurred.
  rseq_loop(&r, &cs);

  return 0;
};

// Abort may be before the critical section.
int TestAbortBefore() {
  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, kRseqSignature);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  struct rseq_cs cs = {};
  cs.version = 0;
  cs.flags = 0;
  cs.start_ip = reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.post_commit_offset = reinterpret_cast<uint64_t>(&rseq_loop_post_commit) -
                          reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.abort_ip = reinterpret_cast<uint64_t>(&rseq_loop_early_abort);

  // Loops until abort. If this returns then abort occurred.
  rseq_loop(&r, &cs);

  return 0;
};

// Signature must match.
int TestAbortSignature() {
  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, kRseqSignature + 1);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  struct rseq_cs cs = {};
  cs.version = 0;
  cs.flags = 0;
  cs.start_ip = reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.post_commit_offset = reinterpret_cast<uint64_t>(&rseq_loop_post_commit) -
                          reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.abort_ip = reinterpret_cast<uint64_t>(&rseq_loop_abort);

  // Loops until abort. This should SIGSEGV on abort.
  rseq_loop(&r, &cs);

  return 1;
};

// Abort must not be in the critical section.
int TestAbortPreCommit() {
  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, kRseqSignature + 1);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  struct rseq_cs cs = {};
  cs.version = 0;
  cs.flags = 0;
  cs.start_ip = reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.post_commit_offset = reinterpret_cast<uint64_t>(&rseq_loop_post_commit) -
                          reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.abort_ip = reinterpret_cast<uint64_t>(&rseq_loop_pre_commit);

  // Loops until abort. This should SIGSEGV on abort.
  rseq_loop(&r, &cs);

  return 1;
};

// rseq.rseq_cs is cleared on abort.
int TestAbortClearsCS() {
  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, kRseqSignature);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  struct rseq_cs cs = {};
  cs.version = 0;
  cs.flags = 0;
  cs.start_ip = reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.post_commit_offset = reinterpret_cast<uint64_t>(&rseq_loop_post_commit) -
                          reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.abort_ip = reinterpret_cast<uint64_t>(&rseq_loop_abort);

  // Loops until abort. If this returns then abort occurred.
  rseq_loop(&r, &cs);

  if (__atomic_load_n(&r.rseq_cs, __ATOMIC_RELAXED)) {
    return 1;
  }

  return 0;
};

// rseq.rseq_cs is cleared on abort outside of critical section.
int TestInvalidAbortClearsCS() {
  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, kRseqSignature);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  struct rseq_cs cs = {};
  cs.version = 0;
  cs.flags = 0;
  cs.start_ip = reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.post_commit_offset = reinterpret_cast<uint64_t>(&rseq_loop_post_commit) -
                          reinterpret_cast<uint64_t>(&rseq_loop_start);
  cs.abort_ip = reinterpret_cast<uint64_t>(&rseq_loop_abort);

  __atomic_store_n(&r.rseq_cs, &cs, __ATOMIC_RELAXED);

  // When the next abort condition occurs, the kernel will clear cs once it
  // determines we aren't in the critical section.
  while (1) {
    if (!__atomic_load_n(&r.rseq_cs, __ATOMIC_RELAXED)) {
      break;
    }
  }

  return 0;
};

// A simple syscall inside the critical section works.
//
// This works as long as the syscall doesn't set TIF_NOTIFY_RESUME, which only
// only occurs on scheduling and signal events.
//
// Linux really doesn't want you to do this. CONFIG_DEBUG_RSEQ will detect this
// case and cause SIGSEGV, but who will enable that?
int TestSyscall() {
  struct rseq r = {};
  int ret = RSeq(&r, sizeof(r), 0, kRseqSignature);
  if (sys_errno(ret) != 0) {
    return 1;
  }

  struct rseq_cs cs = {};
  cs.version = 0;
  cs.flags = 0;
  cs.start_ip = reinterpret_cast<uint64_t>(&rseq_getpid_start);
  cs.post_commit_offset = reinterpret_cast<uint64_t>(&rseq_getpid_post_commit) -
                          reinterpret_cast<uint64_t>(&rseq_getpid_start);
  cs.abort_ip = reinterpret_cast<uint64_t>(&rseq_getpid_abort);

  // Loops until abort. If this returns then abort occurred.
  int pid = rseq_getpid(&r, &cs);

  if (pid != sys_getpid()) {
    return 1;
  }

  return 0;
};

// Exit codes:
//  0 - Pass
//  1 - Fail
//  2 - Missing argument
//  3 - Unknown test case
extern "C" int main(int argc, char** argv, char** envp) {
  if (argc != 2) {
    // Usage: rseq <test case>
    return 2;
  }

  if (strncmp(argv[1], kRseqTestUnaligned, sizeof(kRseqTestUnaligned)) == 0) {
    return TestUnaligned();
  }
  if (strncmp(argv[1], kRseqTestRegister, sizeof(kRseqTestRegister)) == 0) {
    return TestRegister();
  }
  if (strncmp(argv[1], kRseqTestDoubleRegister,
              sizeof(kRseqTestDoubleRegister)) == 0) {
    return TestDoubleRegister();
  }
  if (strncmp(argv[1], kRseqTestRegisterUnregister,
              sizeof(kRseqTestRegisterUnregister)) == 0) {
    return TestRegisterUnregister();
  }
  if (strncmp(argv[1], kRseqTestUnregisterDifferentPtr,
              sizeof(kRseqTestUnregisterDifferentPtr)) == 0) {
    return TestUnregisterDifferentPtr();
  }
  if (strncmp(argv[1], kRseqTestUnregisterDifferentSignature,
              sizeof(kRseqTestUnregisterDifferentSignature)) == 0) {
    return TestUnregisterDifferentSignature();
  }
  if (strncmp(argv[1], kRseqTestCPU, sizeof(kRseqTestCPU)) == 0) {
    return TestCPU();
  }
  if (strncmp(argv[1], kRseqTestAbort, sizeof(kRseqTestAbort)) == 0) {
    return TestAbort();
  }
  if (strncmp(argv[1], kRseqTestAbortBefore, sizeof(kRseqTestAbortBefore)) ==
      0) {
    return TestAbortBefore();
  }
  if (strncmp(argv[1], kRseqTestAbortSignature,
              sizeof(kRseqTestAbortSignature)) == 0) {
    return TestAbortSignature();
  }
  if (strncmp(argv[1], kRseqTestAbortPreCommit,
              sizeof(kRseqTestAbortPreCommit)) == 0) {
    return TestAbortPreCommit();
  }
  if (strncmp(argv[1], kRseqTestAbortClearsCS,
              sizeof(kRseqTestAbortClearsCS)) == 0) {
    return TestAbortClearsCS();
  }
  if (strncmp(argv[1], kRseqTestInvalidAbortClearsCS,
              sizeof(kRseqTestInvalidAbortClearsCS)) == 0) {
    return TestInvalidAbortClearsCS();
  }
  if (strncmp(argv[1], kRseqTestSyscall, sizeof(kRseqTestSyscall)) == 0) {
    return TestSyscall();
  }

  return 3;
}

}  // namespace testing
}  // namespace gvisor

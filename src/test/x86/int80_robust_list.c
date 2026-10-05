/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "int80_util.h"

/* Threads of an x86-64 process register robust futex lists with an i386
   set_robust_list() (int $0x80). The kernel keeps such a list besides the
   thread's x86-64 one (which glibc registers), and processes both when the
   thread exits: it marks the futexes that the thread still owns
   FUTEX_OWNER_DIED. A new thread doesn't get the i386 list of the thread
   that creates it. */

#if defined(__x86_64__)

#define I386_set_robust_list 311

/* The i386 struct robust_list_head */
struct i386_robust_list_head {
  uint32_t next;
  int32_t futex_offset;
  uint32_t list_op_pending;
};

/* An entry of the list: the i386 struct robust_list, and the futex */
struct entry {
  uint32_t next;
  uint32_t futex;
};

struct thread_data {
  struct i386_robust_list_head* head;
  struct entry* entry;
  /* Whether to create a thread that takes the futex, instead of taking it */
  int create_owner;
};

static void* take_futex_and_exit(void* p) {
  struct entry* entry = p;
  entry->futex = sys_gettid();
  return (void*)(long)entry->futex;
}

static void* register_and_exit(void* p) {
  struct thread_data* data = p;
  struct i386_robust_list_head* head = data->head;
  head->futex_offset = offsetof(struct entry, futex);
  head->list_op_pending = 0;
  if (data->entry) {
    /* A list with one entry, a futex */
    data->entry->futex = data->create_owner ? 0 : sys_gettid();
    data->entry->next = LOW(head);
    head->next = LOW(data->entry);
  } else {
    /* An empty list */
    head->next = LOW(head);
  }
  test_assert(0 == int80_2(I386_set_robust_list, LOW(head), sizeof(*head)));
  if (data->create_owner) {
    /* The new thread's exit leaves the futex alone */
    pthread_t thread;
    void* tid;
    test_assert(
        0 == pthread_create(&thread, NULL, take_futex_and_exit, data->entry));
    test_assert(0 == pthread_join(thread, &tid));
    test_assert(data->entry->futex == (uint32_t)(long)tid);
  }
  return NULL;
}

int main(void) {
  unsigned char* page;
  struct thread_data data;
  pthread_t thread;

  int80_setup();
  page = int80_low_alloc(4096);

  data.head = (struct i386_robust_list_head*)page;
  data.entry = NULL;
  data.create_owner = 0;
  test_assert(0 == pthread_create(&thread, NULL, register_and_exit, &data));
  test_assert(0 == pthread_join(thread, NULL));

  data.head = (struct i386_robust_list_head*)(page + 1024);
  data.entry = (struct entry*)(page + 2048);
  test_assert(0 == pthread_create(&thread, NULL, register_and_exit, &data));
  test_assert(0 == pthread_join(thread, NULL));
  test_assert(data.entry->futex == FUTEX_OWNER_DIED);

  data.head = (struct i386_robust_list_head*)(page + 3072);
  data.entry = (struct entry*)(page + 3584);
  data.create_owner = 1;
  test_assert(0 == pthread_create(&thread, NULL, register_and_exit, &data));
  test_assert(0 == pthread_join(thread, NULL));
  test_assert(!(data.entry->futex & FUTEX_OWNER_DIED));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#else

int main(void) {
  atomic_puts("EXIT-SUCCESS");
  return 0;
}

#endif

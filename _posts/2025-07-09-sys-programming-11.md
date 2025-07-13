---
title: "11. Thread Synchronization"
categories: [Linux, Programming]
tags: [linux, sys-programming]
---

In the previous blog, we discussed **race conditions** and how they can cause unpredictable behavior in multi-threaded programs.

To avoid such issues, it’s crucial to use proper **thread synchronization techniques** to coordinate access to shared resources safely.

### Thread Synchronization

In multithreaded applications, synchronization mechanisms are essential to manage access to shared resources. Common techniques include:

- **Mutexes** (`pthread_mutex_t`) — Lock/unlock critical sections.
- **Atomic Opreations** 
- **Semaphores** — For signaling and resource counting.

### 1. Using Mutex (Mutual Exclusion)

A **mutex** ensures that only one thread can access a shared resource at a time.

```c
#include <pthread.h>

int counter = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *increment_counter(void *arg) {
    for (int i = 0; i < 100000; i++) {
        pthread_mutex_lock(&lock); // Lock before modifying
        counter++;
        pthread_mutex_unlock(&lock); // Unlock after
    }
    return NULL;
}
```

**Key Points:**

- Always **unlock** the mutex to avoid deadlocks.
- Keep the critical section (locked region) **as short as possible** to minimize performance impact.

### 2. Using Atomic Operations

Some operations (like `++` on integers) can be made **thread-safe** using atomic instructions (available in GCC with `__atomic` built-ins or C11 `stdatomic.h`).

```c
#include <stdatomic.h>

atomic_int counter = 0; // C11 atomic variable

void *increment_counter(void *arg) {
    for (int i = 0; i < 100000; i++) {
        atomic_fetch_add(&counter, 1); // Thread-safe increment
    }
    return NULL;
}
```

But it is limited to certain operations (not suitable for complex critical sections).


### 3. Using Semaphores

Semaphores generalize mutexes by allowing **multiple threads** to access a resource up to a specified limit.

```c
#include <semaphore.h>

int counter = 0;
sem_t sem;

void *increment_counter(void *arg) {
    for (int i = 0; i < 100000; i++) {
        sem_wait(&sem); // Decrement semaphore (like lock)
        counter++;
        sem_post(&sem); // Increment semaphore (like unlock)
    }
    return NULL;
}

int main() {
    sem_init(&sem, 0, 1); // Initialize semaphore with value 1 (binary semaphore)
    // ... (rest of the code)
}
```

You can try Race Condition CTF challenges -

- [TryHackMe Race Conditions](https://vulnerable.sh/posts/thm_race_conditions/)
- [picoCTF Tic-Tac](https://brandon-t-elliott.github.io/tic-tac)


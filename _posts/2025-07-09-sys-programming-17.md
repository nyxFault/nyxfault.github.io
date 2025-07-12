---
title: "Semaphore"
categories: [Linux, Programming]
tags: [linux, sys-programming]
---

Semaphores are synchronization primitives used to control access to shared resources. We already know they are used to prevent race conditions.

### System V vs POSIX Semaphores

- **System V** (`semget`, `semop`)
- **POSIX** (`sem_open`, `sem_wait`, `sem_post`)

A **semaphore** is essentially a **counter** that controls access to a shared resource:

- It **blocks** a process if the resource isn't available.
- It **signals** when the resource becomes available.


Semaphores can be:

- **Counting Semaphores:** Counter allows more than one process to access the resource (like connection pools).
- **Binary Semaphores (Mutex):** Counter limited to 0 or 1, similar to a lock/unlock mechanism.

#### Semaphore Operation Structure (`man semop`):

```c
struct sembuf {
    unsigned short sem_num;  // Semaphore index
    short sem_op;            // Operation (+1 = signal, -1 = wait)
    short sem_flg;           // Operation flags (e.g., IPC_NOWAIT)
};

```

In the following example we will solve our race condition problem we faced in [here](https://nyxfault.github.io/posts/sys-programming-12/#race-condition)

```c
#include <pthread.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <stdlib.h>

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

int counter = 0;
int semid;

// Semaphore wait (P operation)
void sem_wait() {
    struct sembuf sb = {0, -1, 0};
    if (semop(semid, &sb, 1) == -1) {
        perror("semop - wait");
        exit(1);
    }
}

// Semaphore signal (V operation)
void sem_signal() {
    struct sembuf sb = {0, 1, 0};
    if (semop(semid, &sb, 1) == -1) {
        perror("semop - signal");
        exit(1);
    }
}

void *increment_counter(void *arg) {
    for (int i = 0; i < 100000; i++) {
        sem_wait();       // Lock
        counter++;        // Critical section
        sem_signal();     // Unlock
    }
    return NULL;
}

int main() {
    pthread_t thread1, thread2;
    key_t key = ftok("semfile", 65);

    // Create semaphore
    semid = semget(key, 1, 0666 | IPC_CREAT);
    if (semid == -1) {
        perror("semget");
        exit(1);
    }

    // Initialize semaphore to 1
    union semun arg;
    arg.val = 1;
    if (semctl(semid, 0, SETVAL, arg) == -1) {
        perror("semctl");
        exit(1);
    }

    pthread_create(&thread1, NULL, increment_counter, NULL);
    pthread_create(&thread2, NULL, increment_counter, NULL);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    printf("Final counter value: %d\n", counter);  // Correct: 200000

    // Cleanup: remove semaphore
    if (semctl(semid, 0, IPC_RMID) == -1) {
        perror("semctl - IPC_RMID");
        exit(1);
    }

    return 0;
}

```


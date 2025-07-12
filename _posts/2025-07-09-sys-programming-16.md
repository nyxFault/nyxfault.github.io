---
title: "Message Queue"
categories: [Linux, Programming]
tags: [linux, sys-programming]
---

Message queues allow processes to exchange data in the form of messages. Unlike pipes, they support multiple readers/writers and preserve message boundaries. They allow processes to **send and receive messages** in a queue-like structure, with the kernel acting as the intermediary.


- **System V Message Queues** (`msgget`, `msgsnd`, `msgrcv`)
- **POSIX Message Queues** (`mq_open`, `mq_send`, `mq_receive`)

*Example (Sys V)*

```c
#include <sys/msg.h>
#include <stdio.h>

struct msg_buffer {
    long msg_type;
    char msg_text[100];
} message;

int main() {
    key_t key = ftok("progfile", 65);
    int msgid = msgget(key, 0666 | IPC_CREAT);

    // Send a message
    message.msg_type = 1;
    sprintf(message.msg_text, "Hello from sender");
    msgsnd(msgid, &message, sizeof(message), 0);

    // Receive a message
    msgrcv(msgid, &message, sizeof(message), 1, 0);
    printf("Received: %s\n", message.msg_text);

    msgctl(msgid, IPC_RMID, NULL); // Cleanup
    return 0;
}
```
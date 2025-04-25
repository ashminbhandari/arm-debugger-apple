#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/thread_status.h>
#include <mach/thread_act.h>
#include <mach/mach_vm.h>

typedef struct
{
    pid_t pid;
    mach_port_t task;
} Debugger;

kern_return_t read_memory(mach_port_t task, mach_vm_address_t address, void *buffer, size_t size)
{
    mach_msg_type_number_t data_size = (mach_msg_type_number_t)size;
    vm_offset_t data = 0;
    kern_return_t kr = mach_vm_read(task, address, size, &data, &data_size);

    if (kr != KERN_SUCCESS)
    {
        printf("Error reading memory: %s\n", mach_error_string(kr));
        return kr;
    }

    memcpy(buffer, (void *)data, size);
    vm_deallocate(mach_task_self(), data, data_size);

    return KERN_SUCCESS;
}

uint64_t get_stack_pointer(Debugger *debugger)
{
    uint64_t rsp;

    // Get the threads for the process
    thread_act_array_t threads;
    mach_msg_type_number_t thread_count;
    kern_return_t kr = task_threads(debugger->task, &threads, &thread_count);

    if (kr != KERN_SUCCESS)
    {
        printf("Failed to get threads for the process\n");
        return 1;
    }

    // Get the current thread state
    thread_state_flavor_t flavor = x86_THREAD_STATE64; // x86_64 architecture
    thread_state_data_t state;
    mach_msg_type_number_t state_count = THREAD_STATE_MAX;

    kr = thread_get_state(threads[0], flavor, state, &state_count);
    if (kr != KERN_SUCCESS)
    {
        printf("Failed to get thread state\n");
        return 1;
    }

    uint64_t *state_array = (uint64_t *)state;
    rsp = state_array[7]; // __rsp aka stack pointer is at 7 index
    return rsp;
}

void inspect_stack(Debugger *debugger)
{
    uint64_t rsp = get_stack_pointer(debugger);

    if (rsp == 1)
    {
        printf("Error retrieving stack pointer.\n");
        return;
    }

    printf("Stack pointer (rsp): 0x%llx\n", rsp);

    // Expand the memory range to read around the stack pointer
    uint64_t start = rsp - 1024; // Read 1024 bytes before rsp
    size_t size = 2048;          // Read 2048 bytes in total

    uint8_t *buffer = malloc(size);
    if (!buffer)
    {
        perror("malloc failed");
        return;
    }

    mach_vm_size_t outsize = size;
    kern_return_t kr = mach_vm_read_overwrite(
        debugger->task,
        start,
        size,
        (mach_vm_address_t)buffer,
        &outsize);

    if (kr != KERN_SUCCESS)
    {
        printf("Failed to read memory: %s\n", mach_error_string(kr));
        free(buffer);
        return;
    }

    printf("Memory near stack pointer 0x%llx:\n", rsp);
    for (size_t i = 0; i < size; i += sizeof(uint32_t))
    {
        uint32_t value = *(uint32_t *)(buffer + i);
        printf("0x%llx: 0x%08x (%d)\n", start + i, value, value);
    }

    free(buffer);
}

int main()
{
    Debugger *debugger = malloc(sizeof(Debugger));
    pid_t child_pid = fork();

    if (child_pid == 0)
    {
        // Child process: run the target
        char *args[] = {"./program", NULL};
        ptrace(PT_TRACE_ME, 0, 0, 0);
        execv(args[0], args);
        perror("execv failed");
        exit(1);
    }

    debugger->pid = child_pid;
    printf("Spawned child with PID: %d\n", debugger->pid);

    waitpid(debugger->pid, NULL, 0);

    kern_return_t kr = task_for_pid(mach_task_self(), debugger->pid, &debugger->task);
    if (kr != KERN_SUCCESS)
    {
        printf("task_for_pid failed: %s\n", mach_error_string(kr));
    }
    else
    {
        printf("task_for_pid succeeded!\n");
    }

    printf("Debugger attached to process %d\n", debugger->pid);

    while (1)
    {
        printf("[n] step | [e] exit: ");
        char input = getchar();
        while (getchar() != '\n')
            ;

        if (input == 'e')
        {
            ptrace(PT_DETACH, debugger->pid, (caddr_t)1, 0);
            printf("Detached.\n");
            break;
        }
        else if (input == 'n')
        {
            ptrace(PT_STEP, debugger->pid, (caddr_t)1, 0);
            waitpid(debugger->pid, NULL, 0);
            printf("Stepped one instruction.\n");
            inspect_stack(debugger);
        }
    }

    waitpid(debugger->pid, NULL, 0);
    free(debugger);
    return 0;
}
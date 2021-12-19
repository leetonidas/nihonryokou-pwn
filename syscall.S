.intel_syntax noprefix

.global syscall0
.global syscall1
.global syscall2
.global syscall3
.global syscall4
.global syscall5
.global syscall6
.global print_val

syscall6:
mov eax, 0x8[rsp]
jmp 1f
syscall5:
mov eax, r9d
jmp 1f
syscall4:
mov eax, r8d
1:
mov r10, rcx
jmp 2f
syscall3:
mov eax, ecx
jmp 2f
syscall2:
mov eax, edx
jmp 2f
syscall1:
mov eax, esi
jmp 2f
syscall0:
mov eax, edi
2:
syscall
ret

print_val:
xor edx, edx
1:
mov rsi, rdi
and esi, 0xf
add esi, 0x30
cmp esi, 0x3a
jl 2f
add esi, 0x27
2:
dec rdx
mov [rsp + rdx], sil
shr rdi, 4
jnz 1b

inc edi
mov eax, edi
lea rsi, [rsp + rdx]
neg rdx
syscall
ret
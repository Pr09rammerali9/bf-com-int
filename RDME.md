
an brainfuck interpreter + brainfuck llvm compiler in C++(Both are Posix Only) 
Usage:
./bfint <file.bf>
compiler:
./bfcom <file.bf> > <file.ll>
clang <file.ll>

cmds:
>: Increment the data pointer.
<: Decrement the data pointer.
+: Increment the byte at the data pointer.
-: Decrement the byte at the data pointer.
.: Output the byte at the data pointer.
,: Input a byte and store it at the data pointer.
[: Start a loop. If the current cell is zero, jump forward to the matching ].
]: End a loop. If the current cell is non-zero, jump back to the matching [.
Extended Commands
%inc [filename]: Include a file.
%grd [filename]: Guarded include, inserting a file only if not previously included.
$: Open the file specified by the null-terminated string at the data pointer.
~: Close the currently open file.
#: Write the byte at the data pointer to the open file.
^: Read a byte from the open file into the data pointer.
{: Start a function definition.
}: End a function definition.
_: Return from a function.
@: Call the function named by the null-terminated string at the data pointer.
"cond": Start a conditional block that executes if the current cell is non-zero.
`: End a conditional block.
!: Execute a syscall using the number and arguments from the tape.

Pre proceser:
%inc <file.bf>:include a module/header
%grd <file>:include guard
Updated added:
@ for derefrence
^ for extern of C functions

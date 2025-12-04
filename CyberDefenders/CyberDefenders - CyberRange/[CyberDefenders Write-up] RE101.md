# [CyberDefenders - RE101](https://cyberdefenders.org/blueteam-ctf-challenges/re101/)
## Table of Contents

  - [Questions](#questions)
- [Example usage](#example-usage)

* * *
RE101 challenge is a binary analysis exercise - a task security blue team analysts do to understand how a specific malware works and extract possible intel.

**Category**: Malware Analysis

**Tools**:
- [IDA](https://www.hex-rays.com/products/ida/support/download_freeware/)
- [Ghidra](https://ghidra-sre.org/)
- [Cutter](https://cutter.re/)
- [HxD](https://mh-nexus.de/en/hxd/)
- [zipdetails](https://www.systutorials.com/docs/linux/man/1-zipdetails/)
* * *
## Questions
> Q1: File: MALWARE000 - I've used this new encryption I heard about online for my warez; I bet you can't extract the flag!

![ebbe490199d262aab2a1188d5945fb41.png](/resources/ebbe490199d262aab2a1188d5945fb41.png)

Its elf file compiled by GCC so we can use decomplier like Ghidra to decompile and read the code 

![ca5305e305470935dff3d5c4241f4e43.png](/resources/ca5305e305470935dff3d5c4241f4e43.png)

We can see that if we actually execute this file, it will print something and sleep for a several times before actually exit the program

![dc3f6ebafcd07daea14c3d599a85e6ad.png](/resources/dc3f6ebafcd07daea14c3d599a85e6ad.png)

But the flag can be obtained by using strings then we will have this base64 string

![5564a0a87830958a3dfa0be15ce84a5f.png](/resources/5564a0a87830958a3dfa0be15ce84a5f.png)

Decode it then we will have a flag

![7a4cf4eb017a89a6a55384fca62c9aeb.png](/resources/7a4cf4eb017a89a6a55384fca62c9aeb.png)

We can actually find base64 character here but strings would be the best to solve this one
```
0ops_i_used_1337_b64_encryption
```

> Q2: File: Just some JS - Check out what I can do!

![f172e57f9d6a60e42f983247621e5116.png](/resources/f172e57f9d6a60e42f983247621e5116.png)

After examined that code, It does look like heavily obfuscated JavaScript so I used JavaScript Deobfuscator to see if I can execute this script directly on the browser, and the output shows us that its safe to execute this JavaScript code and obtain a flag

![4434175cd84a8476fdfd73c8540a0432.png](/resources/4434175cd84a8476fdfd73c8540a0432.png)

I used [JavaScript Online Compiler](https://www.programiz.com/javascript/online-compiler/) to execute it rather than using console

```
what_a_cheeky_language!1!
```

> Q3: File: This is not JS - I'm tired of Javascript. Luckily, I found the grand-daddy of that lame last language!

![40f77cbd3a1675fc9f7cab86bad55f92.png](/resources/40f77cbd3a1675fc9f7cab86bad55f92.png)

I recognized this pattern, It is brainfuck

![baa8eed551864a2ca70019b886c2c106.png](/resources/baa8eed551864a2ca70019b886c2c106.png)

Use [Brainfuck Translator](https://md5decrypt.net/en/Brainfuck-translator/) to obtain a flag

```
Now_THIS_is_programming
```

> Q4: File: Unzip Me - I zipped flag.txt and encrypted it with the password "password", but I think the header got messed up... You can have the flag if you fix the file

We couldn't extract a file since file is corrupted so we need to fix it

![9ad196a3b7ca498aad2a4cd6fb313a82.png](/resources/9ad196a3b7ca498aad2a4cd6fb313a82.png)

Using "zipdetails" then we can see that magic number of pkzip is correct but Filename Length is a bit weird since we have that "flag.txt" length is not 5858 but 8

![4205ab460d8cf9af45345dcb50b3f6d8.png](/resources/4205ab460d8cf9af45345dcb50b3f6d8.png)

According to https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html, we need to fix this offset 

![db919f65fd450781e25861a6940bc2b0.png](/resources/db919f65fd450781e25861a6940bc2b0.png)

Used HxD (Hex Editor) to fix it to 08 00

![467cc3322677bb5e981e8699843ea747.png](/resources/467cc3322677bb5e981e8699843ea747.png)

Then we use can password provided from a question to read text file inside recovered zip file

```
R3ad_th3_spec
```

> Q5: File: MALWARE101 - Apparently, my encryption isn't so secure. I've got a new way of hiding my flags!

![0411ea942a32975136e3de764971ae59.png](/resources/0411ea942a32975136e3de764971ae59.png)

Using decomplier, we can se that many characters will be assigned to different memory location

![d4c735b4446345eae4c690d071ddc2e0.png](/resources/d4c735b4446345eae4c690d071ddc2e0.png)

Debug it then open stack memory which we will obtain a flag here

```
sTaCk_strings_LMAO
```

> Q6: File: MALWARE201 - Ugh... I guess I'll just roll my own encryption. I'm not too good at math, but it looks good to me!

![3d2becc55c279d728a1566d686e5a409.png](/resources/3d2becc55c279d728a1566d686e5a409.png)

Using decomplier, we can see it will print encrypted flag first then it shows us the sample text which will be sent to encrypt function and print it out for us 

![bc37649c1db51a35b27977bebae54fdc.png](/resources/bc37649c1db51a35b27977bebae54fdc.png)

Here it what it look like when we actually executed this file

![67f4b4871da71e64613cb8ab7c548280.png](/resources/67f4b4871da71e64613cb8ab7c548280.png)

Here is the function that created an encrypted flag but we didn't need it since we can just copy encryped flag from an image above

![56bca681d74b820539a377dc42646f7a.png](/resources/56bca681d74b820539a377dc42646f7a.png)

And here is an encryption function, we can see that it start by shifting 1 bit then OR with 1 then XOR the result with (local_28 % 0xff | 0xa0) before getting that output

```
def reverse_transformation(transformed_data):
    original_data = bytearray()
    
    for index, byte in enumerate(transformed_data):
        # XOR the byte with (index % 0xff | 0xa0)
        xor_value = (index % 0xff) | 0xa0
        byte ^= xor_value
        
        # Remove the least significant bit set by the original transformation
        byte &= 0xFE
        
        # Right shift by 1
        original_byte = byte >> 1
        
        # Append the original byte to the result
        original_data.append(original_byte)
    
    return original_data

# Example usage
transformed_data = bytearray(
    [0x6d, 0x78, 0x61, 0x6c, 0xdd, 0x7e, 0x65, 0x7e, 0x47, 0x6a, 0x4f, 0xcc, 0xf7, 0xca, 0x73, 0x68,
     0x55, 0x42, 0x53, 0xdc, 0xd7, 0xd4, 0x6b, 0xec, 0xdb, 0xd2, 0xe1, 0x1c, 0x6d, 0xde, 0xd1, 0xc2]
)
original_data = reverse_transformation(transformed_data)
print("Original data:", original_data)
print("Original data (hex):", original_data.hex())
```

I asked ChatGPT to write me this script so we can execute it and get the flag right away

![62af225da487a883e7de266de0bb3f8e.png](/resources/62af225da487a883e7de266de0bb3f8e.png)

```
malwar3-3ncryp710n-15-Sh17
```

https://cyberdefenders.org/blueteam-ctf-challenges/achievements/Chicken_0248/re101/
 
* * *

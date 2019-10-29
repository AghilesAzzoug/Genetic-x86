# Genetic memcpy

# What does it do?
* Generate X86 Assembly code for memcpy 

# How?
* Using genetic algorithm 
    * k-tournament selection
    * 2 points crossover 
    * Bit and Byte mutations

* Using Unicorn CPU emulator

# Output examples 
By default the input address is in ESI, the output address in EDI and its length in ECX.

Here are some outputs of this script
```
Format : ADDRESS CODE
```
```
30000 repne movsd dword ptr es:[edi], dword ptr [esi]
30002 jb 0x2fff7
30004 lds edi, ptr [eax]
30006 loope 0x2ffe7
...
```
```
30000 push edi
30001 movsb byte ptr es:[edi], byte ptr [esi]
30002 inc eax
30003 pop esp
30004 inc eax
30005 jmp 0x30001
...
```
```
...
3003a arpl di, dx
3003c movsd dword ptr es:[edi], dword ptr [esi]
3003d push esi
3003e jno 0x3003a
...
```

Not that beautiful, but it does a memcpy.

# Requirements

* Python >= 3
* Unicorn >= 1.0.0

Tested on both windows 10 and Ubuntu 16.04

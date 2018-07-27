"""
A python script that creates an X86 assembly code for memcpy using genetic algorithms.
@author: Azzoug Aghiles
"""

from unicorn.x86_const import *
from unicorn import *
from capstone import *
import random
import os


# Specimen class
class Spec:

    def __init__(self, code=None):
        if code is None:
            self.code = os.urandom(CODE_LEN)
        else:
            self.code = code
        self.fitness = Population.evaluate(self.code, EVALUATION_BYTES)

    def __repr__(self):
        return str(self.code)

    def __str__(self):
        return str(self.code)

    def mutatebits(self, prob=0.50):
        nbits = int(len(self.code) * 8 * prob)
        v = bytearray(self.code)
        for _ in range(nbits):
            bit = random.randint(0, len(self.code) * 8 - 1)
            byte_ind, bit_ind = divmod(bit, 8)
            v[byte_ind] ^= (1 << bit_ind)

        self.code = bytes(v)

    def mutatebytes(self, prob=0.10):
        nbytes = int(len(self.code) * prob)

        v = bytearray(self.code)

        for _ in range(nbytes):
            byte_ind = random.randint(0, len(self.code) - 1)

            v[byte_ind] = random.randint(0, 255) & 0xFF

        self.code = bytes(v)

    def mutate(self):
        if random.random() < 0.95:
            self.mutatebytes()
            return Spec(self.code)
        else:
            self.mutatebits()
            return Spec(self.code)

    def disassemble(self):
        cs = Cs(CS_ARCH_X86, CS_MODE_32)
        o = []
        for instruction in cs.disasm(self.code, MEM_CODE_ADDR):
            o.append(
                "%x %s %s" % (
                    instruction.address, instruction.mnemonic, instruction.op_str))
        return '\n'.join(o)


# Population class
class Population:
    def __init__(self, size=1024, crossover=0.8, elitism=0.1, mutation=0.03, tournamentSize=10):
        self.elitism = elitism
        self.mutation = mutation
        self.crossover = crossover
        self.tournamentSize = tournamentSize

        buf = [Spec() for _ in range(size)]

        self.population = list(sorted(buf, key=lambda x: -x.fitness))

    def _tournament_selection(self):
        best = random.choice(self.population)
        for _ in range(self.tournamentSize):
            cont = random.choice(self.population)
            if cont.fitness > best.fitness:
                best = cont

        return best

    def _selectParents(self):
        return self._tournament_selection(), self._tournament_selection()

    def evolve(self):

        size = len(self.population)
        idx = int(round(size * self.elitism))
        buf = self.population[:idx]

        while idx < size:
            if random.random() <= self.crossover:
                p1, p2 = self._selectParents()
                children = [self.mix(p1, p2), self.mix(p2, p1)]
                for c in children:
                    if random.random() <= self.mutation:
                        buf.append(c.mutate())
                    else:
                        buf.append(c)
                idx += 2
            else:
                if random.random() <= self.mutation:
                    buf.append(self.population[idx].mutate())
                else:
                    buf.append(self.population[idx])
                idx += 1

        self.population = list(sorted(buf[:size], key=lambda x: -x.fitness))

    # crossover method
    @staticmethod
    def mix(spec1, spec2):
        data = bytearray(spec1.code)

        size = random.randint(1, 8)
        loc = random.randint(0, CODE_LEN - size - 1)

        chunk = spec2.code[loc:loc + size]

        dst = random.randint(0, CODE_LEN - size - 1)
        data[dst:dst + size] = chunk

        return Spec(bytes(data))

    # outputs the fitness of a specimen given it assembly code and a test string, fitness == the number of bytes copied
    @staticmethod
    def evaluate(code, test):

        score = 0
        size = len(test)

        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        uc.mem_map(MEM_INPUT_ADDR, 0x1000, UC_PROT_READ)
        uc.mem_map(MEM_OUTPUT_ADDR, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(MEM_CODE_ADDR, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
        uc.mem_map(MEM_STACK_ADDR, 0x1000, UC_PROT_READ | UC_PROT_WRITE)

        uc.reg_write(UC_X86_REG_ESP, MEM_STACK_ADDR + 0x800)
        uc.reg_write(UC_X86_REG_EBP, 0)
        uc.reg_write(UC_X86_REG_EAX, 0)
        uc.reg_write(UC_X86_REG_EBX, 0)
        uc.reg_write(UC_X86_REG_ECX, size)
        uc.reg_write(UC_X86_REG_EDX, 0)
        uc.reg_write(UC_X86_REG_ESI, MEM_INPUT_ADDR)
        uc.reg_write(UC_X86_REG_EDI, MEM_OUTPUT_ADDR)

        uc.mem_write(MEM_INPUT_ADDR, test + ZERO_PAGE[:-size])

        uc.mem_write(MEM_OUTPUT_ADDR, ZERO_PAGE)
        uc.mem_write(MEM_STACK_ADDR, ZERO_PAGE)

        # initialize code memory with NOPs

        uc.mem_write(MEM_CODE_ADDR, b"\x90" * 0x1000)

        uc.mem_write(MEM_CODE_ADDR, code)

        try:
            uc.emu_start(MEM_CODE_ADDR, 0x41424344, count=size * 8)

        except unicorn.UcError:
            pass

        copied_bytes = uc.mem_read(MEM_OUTPUT_ADDR, len(test))
        test_bytes = uc.mem_read(MEM_INPUT_ADDR, len(test))

        for c, t in zip(copied_bytes, test_bytes):
            if c == t:
                score += 1

        return score


if __name__ == '__main__':

    ZERO_PAGE = b"\0" * 0x1000

    # code length
    CODE_LEN = 512

    # memory addresses
    MEM_INPUT_ADDR = 0x10000
    MEM_OUTPUT_ADDR = 0x20000
    MEM_CODE_ADDR = 0x30000
    MEM_STACK_ADDR = 0x40000

    MAX_GENERATIONS = 200
    EVALUATION_BYTES = b"ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ"

    pop = Population(size=200, crossover=0.8, elitism=0.1, mutation=0.3, tournamentSize=10)

    best_solution = pop.population[0]

    for i in range(0, MAX_GENERATIONS):
        print("[+] Generation %d : fitness %d \n" % (i, pop.population[0].fitness))

        if pop.population[0].fitness > best_solution.fitness:
            best_solution = pop.population[0]
            print("\t [+] Better solution found !!!\n")

        # the length of the test string
        if pop.population[0].fitness >= len(EVALUATION_BYTES):
            print("[+] Best solution found after {} generations is : \n\n{}".format(i, pop.population[0].disassemble()))
            break
        else:
            pop.evolve()
    else:
        print("[!] Maximum generations reached")
        print("[+] Best solution over {} generations is : \n{}".format(MAX_GENERATIONS, best_solution.disassemble()))

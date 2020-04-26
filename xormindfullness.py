#! /usr/bin/python3

# Code to ease analysis of Xor Madness challenge
# https://www.root-me.org/es/Challenges/Cracking/PE-x86-Xor-Madness

import r2pipe
import shutil

class XM:

    def __init__(self, in_path, out_path):
        self.in_path = in_path
        self.out_path = out_path

        self.r2_in = r2pipe.open(in_path)
        self.r2_out = r2pipe.open(out_path, flags=['-w'])

        self.checkers = [
            self.check_push,
            self.check_mov,
        ]

    def parse(self):
        
        while self.curr_offset() < 0x4014c2:

            for checker in self.checkers:
                next_opcode = checker()
                if next_opcode > 0:
                    self.r2_in.cmd(f"so {next_opcode}")
                    break
            else:
                self.r2_in.cmd("so 1")

    def curr_offset(self):
        return self.r2_in.cmdj("pdj 1")[0]["offset"]

    def get_xor_args(self, inst):
        if inst["type"] != "xor":
            print(f"This is not a xor! 0x{inst['offset']:x}")
            exit(1)

        args = inst["disasm"][4:].split(", ")

        return args

    # Function to detect same reg but different reg size
    # ecx = exc and ebx = bx and eax = ah
    def same_reg(self, d1, d2):

        return d1[-2:][0] == d2[-2:][0]

    ## Checkers ##

    # xor A, A
    # xor A, B
    # =
    # mov A, B
    def check_mov(self):
        instr_count = 0
        seems_mov = False

        [x1, x2] = self.r2_in.cmdj("pdj 2")

        # xor A, A
        if x1["type"] == "xor":
            arg_1_x1, arg_2_x1 = self.get_xor_args(x1)
            if arg_1_x1 == arg_2_x1:
                seems_mov = True
        
        # xor A, B
        if seems_mov and x2["type"] == "xor":
            arg_1_x2, arg_2_x2 = self.get_xor_args(x2)
            if arg_1_x2 != arg_2_x2 and self.same_reg(arg_1_x2, arg_1_x1):
                dst = arg_1_x2
                src = arg_2_x2
                instr_count = 2
                self.r2_out.cmd(f"s {self.curr_offset()}")
                # TODO: potential error not clearing high nibble
                self.r2_out.cmd(f"\"wa mov {dst},{src};nop;nop\"")
                print(f"[i] 0x{self.curr_offset():x} - mov {dst},{src}")

        return instr_count

    # call +0
    # xor A, A
    # xor A, [esp]
    # xor [esp], A
    # xor [esp], sth
    # =
    # push sth
    def check_push(self):

        [c1, x1, x2, x3, x4] = self.r2_in.cmdj("pdj 5")

        # call +0
        if c1["type"] == "call":
            if c1["bytes"] != "e800000000":
                return 0
        else:
            return 0
        
        # xor A, A
        if x1["type"] == "xor":
            arg_1_x1, arg_2_x1 = self.get_xor_args(x1)
            if arg_1_x1 != arg_2_x1:
                return 0
        else:
            return 0

        # xor A, [esp]
        if x2["type"] == "xor":
            arg_1_x2, arg_2_x2 = self.get_xor_args(x2)
            if arg_1_x1 != arg_1_x2 or arg_1_x2 == arg_2_x2 or arg_2_x2 != "dword [esp]":
                return 0
        else:
            return 0

        # xor [esp], A
        if x3["type"] == "xor":
            arg_1_x3, arg_2_x3 = self.get_xor_args(x3)
            if arg_1_x1 != arg_2_x3 or arg_1_x3 == arg_2_x3 or arg_1_x3 != "dword [esp]":
                return 0
        else:
            return 0

        # xor [esp], sth
        if x4["type"] == "xor":
            arg_1_x4, arg_2_x4 = self.get_xor_args(x4)
            if arg_1_x4 == "dword [esp]":
                pushed = arg_2_x4
                total_size = c1["size"] + x1["size"] + x2["size"] + x3["size"] + x4["size"]

                self.r2_out.cmd(f"s {self.curr_offset()}")
                self.r2_out.cmd(f"wa push {pushed}") # write push
                p1 = self.r2_out.cmdj("pdj 1")[0]
                print(f"[?] push info {p1}")
                new_size = p1["size"]
                print(f"[?] total {total_size} | new {new_size}")
                bytes_diff = total_size - new_size

                self.r2_out.cmd(f"so 1") # skip push
                print(f"[?] Escribo {bytes_diff} nops en {self.r2_out.cmd('s')}")
                nop_str = ";".join(["nop"] * bytes_diff)
                self.r2_out.cmd(f"\"wa {nop_str}\"") # write nops

                print(f"[i] 0x{self.curr_offset():x} - push {pushed}")
            else:
                return 0
        else:
            return 0

        return 5


if __name__ == "__main__":

    in_path = "xormadness.exe"
    out_path = "xormindfullness.exe"
    shutil.copy(in_path, out_path)

    xm = XM(in_path, out_path)
    xm.parse()

import argparse, sys

import opcodes
import devices

parser = argparse.ArgumentParser("Disassemble Uxn roms into Uxntal assembly")
parser.add_argument("rom", type=argparse.FileType("rb"), default=sys.stdin)
parser.add_argument("tal", type=argparse.FileType("w"), default=sys.stdout)

arguments = parser.parse_args()

with arguments.rom as romfile:
    rom = romfile.read()

# Zero-page
rom = bytes(256) + rom

tal = {}
comments = {}

vectors = [0x0100]

def dis_vector(pos):
    if pos in tal:
        raise Exception(f"Tried to overwrite already disassembled code at {pos:04x}")
    while pos < 0x10000:
        byte = rom[pos]
        if byte == 0:
            tal[pos] = "BRK"
            break

        cmd = opcodes.names[byte & 0x1f]

        if byte & 0x20 > 0:
            cmd = cmd + "2"
        if byte & 0x80 > 0:
            cmd = cmd + "k"
        if byte & 0x40 > 0:
            cmd = cmd + "r"

        if byte & 0x1f == 0:
            # Remove redundant "k" on LIT
            cmd = cmd.replace("k", "")

        tal[pos] = cmd
        
        if byte & 0x1f == 0:
            # Advance pointer
            pos += 1
            if byte & 0x20 > 0:
                pos += 1
        
        # Device vectors
        if cmd.startswith("DEO2"):
            device_port = rom[pos-1]
            if device_port & 0x0f == 0:
                # It's a vector write
                i = pos - 3
                while i > 0x00ff:
                    if i in tal and tal[i].startswith("LIT2"):
                        newvec = (rom[i+1] << 8) + rom[i+2]
                        vectors.append(newvec)
                        comments[newvec] = "Vector for device "+devices.names[(device_port & 0xf0) >> 4]
                        print("Found vector: {:04x}".format(newvec))
                        break
                    i -= 1

        # Subroutines
        if cmd.startswith("JSR2"):
            i = pos - 3 
            while i > 0x0ff:
                if i in tal and tal[i] == "LIT2":
                    newvec = (rom[i+1] << 8) + rom[i+2]
                    vectors.append(newvec)
                    comments[newvec] = "Subroutine"
                    print(f"Found subroutine: {newvec:04x}")
                    break
                i -= 1

        if cmd.startswith("JMP"):
            break
        pos += 1

seen = {}
while len(vectors) > 0:
    vec = vectors.pop()
    if vec in seen:
        continue
    dis_vector(vec)
    seen[vec] = True

# This could hide bugs in the disasm if stuff is pointed to out side of the rom
for pos in range(0x0100, len(rom)):
    if pos not in tal:
        tal[pos] = "{:02x}".format(rom[pos])

with arguments.tal as f:
    f.write("( Disassembly of {} )\n".format(arguments.rom.name))
    f.write("|0100\n")
    it = iter(sorted(tal))
    while True:
        try:
            pos = next(it)
        except StopIteration:
            break
        if pos in comments:
            f.write("\n( {} )\n".format(comments[pos]))
        
        cmd = tal[pos] 
        if cmd == "LIT":
            cmd = "#"+tal[pos+1]
            next(it)
        elif cmd == "LIT2":
            cmd = "#"+tal[pos+1]+tal[pos+2] 
            next(it); next(it)

        f.write("( {:04x} ) {:s}\n".format(pos, cmd))

# Refresh the current program's data types from the GhidraBoy module.
#
# Registers any new types into the program's data type manager and re-applies
# the MMIO register types (LCDC, STAT, P1, IF, IE, etc.) so existing decomps
# pick up the bitfield enum rendering without needing a full reimport.
#
# Hardware kind (DMG vs CGB) is detected from the loader-created memory
# blocks: presence of "vram1" indicates a CGB program.
#
# Safe to re-run. Ghidra's undo will reverse the changes if needed.
#
#@author kabili
#@category mgbdis
#@menupath Tools.Game Boy.Refresh data types

from fi.gekkio.ghidraboy import DataTypes, GameBoyKind, GameBoyUtils


def detect_kind(program):
    if program.getMemory().getBlock("vram1") is not None:
        return GameBoyKind.CGB
    return GameBoyKind.GB


def run():
    program = getCurrentProgram()
    if program is None:
        printerr("No program is open")
        return

    DataTypes.addAll(program.getDataTypeManager())
    print("Registered Game Boy data types in data type manager")

    kind = detect_kind(program)
    GameBoyUtils.populateHardwareBlocks(program, kind)
    print("Re-applied MMIO register types ({})".format(kind))


run()

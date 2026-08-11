# Move CGB banked RAM bank 0/1 out of an overlay and into the default address space.
#
# Programs imported before the loader change map vram bank 0 and wram bank 1 as
# overlays, so 8000-9fff and d000-dfff have no block in the default space. That is
# where absolute references (LD A,(0xd0ad)) actually resolve, so globals there can
# be labelled but never given a type or a plate comment, and annotating the overlay
# copy instead writes to an address nothing references.
#
# This re-creates those two blocks as ordinary blocks in the default space. The
# switchable banks (vram1, wram2-wram7) stay overlays. Newly imported programs
# already have the right layout and are left alone.
#
# Only the block layout changes. Nothing in the fixed banks is touched, and Ghidra's
# undo will reverse the whole run.
#
#@author kabili
#@category mgbdis
#@menupath Tools.Game Boy.Migrate banked RAM blocks

from ghidra.program.model.address import AddressSet
from ghidra.util.task import TaskMonitor

# name, offset, length, executable — mirrors GameBoyUtils.addHardwareBlocks
TARGETS = [
    ("vram0", 0x8000, 0x2000, False, "Video RAM (bank 0)"),
    ("wram1", 0xd000, 0x1000, True, "Work RAM (bank 1)"),
]

SOURCE = "Game Boy Color hardware"


def describe_contents(program, block):
    """What would be lost by removing this overlay block, as a list of strings."""
    body = AddressSet(block.getStart(), block.getEnd())
    listing = program.getListing()
    found = []

    instructions = sum(1 for _ in listing.getInstructions(body, True))
    if instructions:
        found.append("{} instruction(s)".format(instructions))

    data = sum(1 for _ in listing.getDefinedData(body, True))
    if data:
        found.append("{} defined data item(s)".format(data))

    symbols = [s.getName() for s in program.getSymbolTable().getPrimarySymbolIterator(body, True)]
    if symbols:
        preview = ", ".join(symbols[:5])
        if len(symbols) > 5:
            preview += ", ..."
        found.append("{} symbol(s): {}".format(len(symbols), preview))

    refs = sum(1 for _ in program.getReferenceManager().getReferenceDestinationIterator(body, True))
    if refs:
        found.append("{} referenced address(es)".format(refs))

    return found


def migrate(program, name, offset, length, executable, comment):
    memory = program.getMemory()
    address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    existing = memory.getBlock(address)
    if existing is not None:
        print("{}: already in the default space as '{}', nothing to do".format(name, existing.getName()))
        return False

    overlay = memory.getBlock(name)
    if overlay is None:
        print("{}: no such block, skipping".format(name))
        return False
    if not overlay.isOverlay():
        print("{}: not an overlay, skipping".format(name))
        return False

    contents = describe_contents(program, overlay)
    if contents:
        print("{}: overlay is not empty: {}".format(name, "; ".join(contents)))
        keep = askYesNo(
            "Migrate {}".format(name),
            "The {} overlay holds:\n\n{}\n\n"
            "These sit at addresses nothing in the program references, which is the bug\n"
            "this migration fixes. Removing the overlay discards them.\n\n"
            "Remove it and re-create {} in the default space?".format(
                name, "\n".join(contents), name
            ),
        )
        if not keep:
            print("{}: left alone".format(name))
            return False

    memory.removeBlock(overlay, TaskMonitor.DUMMY)
    try:
        program.removeOverlaySpace(name)
    except Exception as e:
        # Leaves a phantom space that <name>:<offset> still resolves to. Harmless for
        # the decompiler, but worth knowing about if a later write goes to the wrong place.
        print("{}: WARNING could not remove the overlay space: {}".format(name, e))

    block = memory.createUninitializedBlock(name, address, length, False)
    block.setRead(True)
    block.setWrite(True)
    block.setExecute(executable)
    block.setComment(comment)
    block.setSourceName(SOURCE)
    print("{}: moved to the default space at {}".format(name, address))
    return True


def run():
    program = getCurrentProgram()
    if program is None:
        printerr("No program is open")
        return

    if program.getMemory().getBlock("vram1") is None:
        printerr("Not a CGB program (no vram1 block); nothing to migrate")
        return

    migrated = 0
    for name, offset, length, executable, comment in TARGETS:
        if migrate(program, name, offset, length, executable, comment):
            migrated += 1

    if migrated:
        print(
            "Migrated {} block(s). Globals in these ranges can now be typed on their bare "
            "address (set_global address=\"d0ac\").".format(migrated)
        )
    else:
        print("No blocks migrated")


run()

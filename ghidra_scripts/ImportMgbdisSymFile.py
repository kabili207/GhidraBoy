# Import an mgbdis-compatible .sym file into the current program.
#
# Labels are created at the corresponding Ghidra address. Banks 1+ are resolved
# via overlay memory blocks named "rom1", "rom2", etc.; bank 0 uses the default
# address space.
#
# Block directives are applied as follows:
#   .text:LEN              -> char[LEN] data
#   .data:LEN[:rowsize]    -> byte[LEN] data (rowsize is ignored; mgbdis-only)
#   .code:LEN              -> disassemble starting at the address
#   .image:LEN             -> tile_2bpp[LEN/16] data
#   .image:LEN:1bpp[,...]  -> tile_1bpp[LEN/8] data
# For .image blocks the mgbdis-only width and palette args (e.g. w128,pe4)
# are not stored in Ghidra; they only affect mgbdis's PNG rendering.
#
# Lines that fail to parse are logged and skipped.
#
#@author kabili
#@category mgbdis
#@menupath Tools.mgbdis.Import sym file

from ghidra.program.model.data import ArrayDataType, ByteDataType, CharDataType
from ghidra.program.model.data import CategoryPath, DataUtilities
from ghidra.program.model.symbol import SourceType


GB_CATEGORY = CategoryPath(CategoryPath.ROOT, "Game Boy")


def parse_line(raw):
    """Return (bank, offset, payload) or None if the line is blank/comment/bad."""
    line = raw.split(";", 1)[0].strip()
    if not line:
        return None
    parts = line.split(None, 1)
    if len(parts) != 2:
        return None
    location, payload = parts
    if ":" not in location:
        return None
    bank_s, addr_s = location.split(":", 1)
    try:
        bank = int(bank_s, 16)
        offset = int(addr_s, 16)
    except ValueError:
        return None
    return (bank, offset, payload)


def parse_block(payload):
    """Return (type, length, args) if payload is a block directive, else None."""
    if not payload.startswith("."):
        return None
    parts = payload.split(":")
    if len(parts) < 2:
        return None
    btype = parts[0][1:].lower()
    # mgbdis treats .byt as .data, .asc as .text
    if btype == "byt":
        btype = "data"
    elif btype == "asc":
        btype = "text"
    if btype not in ("code", "data", "text", "image"):
        return None
    try:
        length = int(parts[1], 16)
    except ValueError:
        return None
    args = parts[2] if len(parts) >= 3 else None
    return (btype, length, args)


def resolve_address(program, bank, offset):
    """Map (bank, offset) to a Ghidra address. Returns None if unresolvable."""
    memory = program.getMemory()
    if bank == 0:
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
        if memory.getBlock(addr) is None:
            return None
        return addr

    block = memory.getBlock("rom{}".format(bank))
    if block is None:
        return None
    space = block.getStart().getAddressSpace()
    addr = space.getAddress(offset)
    if not block.contains(addr):
        return None
    return addr


def apply_label(program, addr, name):
    program.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED)


def apply_block(program, addr, btype, length, args, monitor):
    """Apply a block directive to the program."""
    if btype == "code":
        # Trigger disassembly across the run; Ghidra figures out instruction boundaries.
        disassemble(addr)
        return

    dtm = program.getDataTypeManager()

    if btype == "image":
        # Use the GhidraBoy tile typedefs so the bytes are semantically marked
        # as image data. mgbdis's "1bpp" arg picks the 1-bit variant.
        is_1bpp = args is not None and "1bpp" in args
        tile_name = "tile_1bpp" if is_1bpp else "tile_2bpp"
        tile_size = 8 if is_1bpp else 16
        tile_dt = dtm.getDataType(GB_CATEGORY, tile_name)
        if tile_dt is not None and length % tile_size == 0:
            count = length // tile_size
            dt = ArrayDataType(tile_dt, count, tile_dt.getLength())
        else:
            if tile_dt is None:
                printerr("  {} not found in data type manager; falling back to byte[]".format(tile_name))
            else:
                printerr("  image length {} is not a multiple of {}; falling back to byte[]".format(length, tile_size))
            elem = ByteDataType.dataType
            dt = ArrayDataType(elem, length, elem.getLength())
    elif btype == "text":
        elem = CharDataType.dataType
        dt = ArrayDataType(elem, length, elem.getLength())
    else:
        # .data -> raw bytes
        elem = ByteDataType.dataType
        dt = ArrayDataType(elem, length, elem.getLength())

    DataUtilities.createData(
        program, addr, dt, length, False,
        DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA,
    )


def run():
    program = getCurrentProgram()
    if program is None:
        printerr("No program is open")
        return

    in_file = askFile("Import mgbdis sym file", "Open")
    if in_file is None:
        return

    labels = 0
    blocks = 0
    skipped = 0

    f = open(in_file.getAbsolutePath(), "r")
    try:
        line_no = 0
        for raw in f:
            line_no += 1
            parsed = parse_line(raw)
            if parsed is None:
                continue
            bank, offset, payload = parsed
            addr = resolve_address(program, bank, offset)
            if addr is None:
                printerr("Line {}: no memory at {:02x}:{:04x} (bank {} not loaded?)".format(
                    line_no, bank, offset, bank))
                skipped += 1
                continue

            block_def = parse_block(payload)
            if block_def is None:
                try:
                    apply_label(program, addr, payload)
                    labels += 1
                except Exception as e:
                    printerr("Line {}: failed to set label '{}' at {}: {}".format(line_no, payload, addr, e))
                    skipped += 1
                continue

            btype, length, args = block_def
            try:
                apply_block(program, addr, btype, length, args, monitor)
                blocks += 1
            except Exception as e:
                printerr("Line {}: failed to apply {} block at {}: {}".format(line_no, btype, addr, e))
                skipped += 1
    finally:
        f.close()

    print("Imported {} labels, {} blocks ({} skipped) from {}".format(
        labels, blocks, skipped, in_file.getAbsolutePath()))


run()

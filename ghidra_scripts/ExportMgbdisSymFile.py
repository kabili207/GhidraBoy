# Export labels and data blocks from the current program to an mgbdis-compatible
# .sym file. Banks are derived from memory block names: the overlay blocks
# created by GhidraBoy's loader are named "rom1", "rom2", etc. Anything in the
# default address space maps to bank 0.
#
# Data blocks are emitted when the address has a defined Data item that maps
# cleanly onto mgbdis's block model:
#   - char arrays / TerminatedCString  -> .text:LEN
#   - byte/word/dword arrays           -> .data:LEN
# Other data types fall through with just a label.
#
#@author kabili
#@category mgbdis
#@menupath Tools.mgbdis.Export sym file

import re

from ghidra.program.model.symbol import SymbolType, SourceType


BANK_BLOCK_RE = re.compile(r"^rom(\d+)$")


def block_bank(block):
    """Return the bank number for a memory block, or 0 if non-banked."""
    if block is None:
        return 0
    m = BANK_BLOCK_RE.match(block.getName())
    if m:
        return int(m.group(1))
    return 0


def classify_data(data):
    """Map a Ghidra Data item to (block_type, length_bytes) or None."""
    if data is None or not data.isDefined():
        return None
    dt = data.getDataType()
    length = data.getLength()
    if length <= 0:
        return None

    name = dt.getName().lower()
    # Strings (any string-y type) -> .text
    if "string" in name or name in ("char", "wchar_t"):
        return ("text", length)

    # Arrays: inspect element type
    if hasattr(dt, "getDataType") and hasattr(dt, "getNumElements"):
        elem = dt.getDataType()
        elem_name = elem.getName().lower()
        if elem_name in ("char", "wchar_t") or "string" in elem_name:
            return ("text", length)
        if elem_name in ("byte", "undefined1", "undefined", "word", "dword", "ushort", "uint", "short", "int"):
            return ("data", length)
        # Fall through: emit as data anyway
        return ("data", length)

    # Single primitive byte/word at a labelled address: emit as 1- or 2-byte data
    if name in ("byte", "undefined1", "undefined"):
        return ("data", length)
    if name in ("word", "ushort", "short"):
        return ("data", length)
    if name in ("dword", "uint", "int"):
        return ("data", length)

    return None


def is_user_label(symbol):
    """Skip default labels (LAB_xxxx, FUN_xxxx, etc.) and non-code symbols."""
    if symbol.getSource() == SourceType.DEFAULT:
        return False
    st = symbol.getSymbolType()
    if st != SymbolType.LABEL and st != SymbolType.FUNCTION:
        return False
    return True


def collect_entries(program):
    """Walk the program and return a list of (bank, addr, label, block_or_None)."""
    listing = program.getListing()
    memory = program.getMemory()
    out = []
    seen = set()  # (bank, addr, label) for dedup

    symbol_table = program.getSymbolTable()
    for symbol in symbol_table.getSymbolIterator(True):
        if not is_user_label(symbol):
            continue
        addr = symbol.getAddress()
        if addr is None or not addr.isMemoryAddress():
            continue
        block = memory.getBlock(addr)
        bank = block_bank(block)
        offset = addr.getOffset() & 0xFFFF
        label = symbol.getName()  # unqualified; RGBDS local labels use "." not "::"

        key = (bank, offset, label)
        if key in seen:
            continue
        seen.add(key)

        data = listing.getDataAt(addr)
        block_info = classify_data(data)
        out.append((bank, offset, label, block_info))

    out.sort(key=lambda e: (e[0], e[1], e[2]))
    return out


def format_entries(entries):
    """Turn the entry list into the mgbdis sym file body."""
    lines = []
    last_bank = None
    for bank, offset, label, block_info in entries:
        if last_bank is not None and bank != last_bank:
            lines.append("")  # blank line between banks for readability
        last_bank = bank

        loc = "{:02x}:{:04x}".format(bank, offset)
        lines.append("{} {}".format(loc, label))
        if block_info is not None:
            btype, blen = block_info
            lines.append("{} .{}:{:x}".format(loc, btype, blen))
    return "\n".join(lines) + "\n"


def run():
    program = getCurrentProgram()
    if program is None:
        printerr("No program is open")
        return

    out_file = askFile("Export mgbdis sym file", "Save")
    if out_file is None:
        return

    entries = collect_entries(program)
    body = format_entries(entries)

    header = "; mgbdis sym file exported from Ghidra\n; Program: {}\n\n".format(program.getName())

    f = open(out_file.getAbsolutePath(), "w")
    try:
        f.write(header)
        f.write(body)
    finally:
        f.close()

    print("Wrote {} entries to {}".format(len(entries), out_file.getAbsolutePath()))


run()

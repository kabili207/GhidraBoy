// Copyright 2019-2020 Joonas Javanainen <joonas.javanainen@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package fi.gekkio.ghidraboy;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;

import java.util.Arrays;

public final class DataTypes {
    private DataTypes() {
    }

    private static final CategoryPath PATH = new CategoryPath(CategoryPath.ROOT, "Game Boy");

    public static final ByteDataType u8 = ByteDataType.dataType;
    public static final WordDataType u16 = WordDataType.dataType;
    public static final CharDataType ch = CharDataType.dataType;

    public static final TypeDef LOGO;
    public static final TypeDef TILE_2BPP;
    public static final TypeDef TILE_1BPP;
    public static final TypeDef CGB_PALETTE_COLOR;
    public static final Enum CGB_FLAG;
    public static final Structure TITLE_BLOCK_OLD;
    public static final Structure TITLE_BLOCK_NEW;
    public static final Union TITLE_BLOCK;
    public static final Enum SGB_FLAG;
    public static final Enum CART_TYPE;
    public static final Enum ROM_SIZE;
    public static final Enum RAM_SIZE;
    public static final Enum REGION;
    public static final Structure HEADER;
    public static final Enum LCDC;
    public static final Enum STAT;
    public static final Enum INTR_FLAGS;
    public static final Enum JOYPAD;
    public static final Enum OAM_ATTRIBUTES;
    public static final Structure OAM_ENTRY;

    static {
        LOGO = new TypedefDataType(PATH, "logo", array(u8, 0x30));
        TILE_2BPP = new TypedefDataType(PATH, "tile_2bpp", array(u8, 16));
        TILE_1BPP = new TypedefDataType(PATH, "tile_1bpp", array(u8, 8));

        CGB_FLAG = new EnumDataType(PATH, "cgb_flag", 1);
        CGB_FLAG.add("NONE", 0x00);
        CGB_FLAG.add("SUPPORT", 0x80);
        CGB_FLAG.add("ONLY", 0xc0);

        TITLE_BLOCK_OLD = new StructureDataType(PATH, "title_block_old", 0);
        TITLE_BLOCK_OLD.add(array(ch, 15), "title", null);
        TITLE_BLOCK_OLD.add(CGB_FLAG, "cgb_flag", null);

        TITLE_BLOCK_NEW = new StructureDataType(PATH, "title_block_new", 0);
        TITLE_BLOCK_NEW.add(array(ch, 11), "title", null);
        TITLE_BLOCK_NEW.add(array(ch, 4), "manufacturer_code", null);
        TITLE_BLOCK_NEW.add(CGB_FLAG, "cgb_flag", null);

        TITLE_BLOCK = new UnionDataType(PATH, "title_block");
        TITLE_BLOCK.add(array(ch, 16), "title_only", null);
        TITLE_BLOCK.add(TITLE_BLOCK_OLD, "old_format", null);
        TITLE_BLOCK.add(TITLE_BLOCK_NEW, "new_format", null);

        SGB_FLAG = new EnumDataType(PATH, "sgb_flag", 1);
        SGB_FLAG.add("NONE", 0x00);
        SGB_FLAG.add("SUPPORT", 0x03);

        CART_TYPE = new EnumDataType(PATH, "cart_type", 1);
        CART_TYPE.add("ROM_ONLY", 0x00);
        CART_TYPE.add("MBC1", 0x01);
        CART_TYPE.add("MBC1_RAM", 0x02);
        CART_TYPE.add("MBC1_RAM_BATT", 0x03);
        CART_TYPE.add("MBC2", 0x05);
        CART_TYPE.add("MBC2_BATT", 0x06);
        CART_TYPE.add("RAM", 0x08);
        CART_TYPE.add("RAM_BATT", 0x09);
        CART_TYPE.add("MMM01", 0x0b);
        CART_TYPE.add("MMM01_RAM", 0x0c);
        CART_TYPE.add("MMM01_RAM_BATT", 0x0d);
        CART_TYPE.add("MBC3_RTC_BATT", 0x0f);
        CART_TYPE.add("MBC3_RAM_RTC_BATT", 0x10);
        CART_TYPE.add("MBC3", 0x11);
        CART_TYPE.add("MBC3_RAM", 0x12);
        CART_TYPE.add("MBC3_RAM_BATT", 0x13);
        CART_TYPE.add("MBC5", 0x19);
        CART_TYPE.add("MBC5_RAM", 0x1a);
        CART_TYPE.add("MBC5_RAM_BATT", 0x1b);
        CART_TYPE.add("MBC5_RUMBLE", 0x1c);
        CART_TYPE.add("MBC5_RAM_RUMBLE", 0x1d);
        CART_TYPE.add("MBC5_RAM_BATT_RUMBLE", 0x1e);
        CART_TYPE.add("MBC6", 0x20);
        CART_TYPE.add("MBC7", 0x22);
        CART_TYPE.add("POCKET_CAMERA", 0xfc);
        CART_TYPE.add("TAMA5", 0xfd);
        CART_TYPE.add("HUC3", 0xfe);
        CART_TYPE.add("HUC1", 0xff);

        ROM_SIZE = new EnumDataType(PATH, "rom_size", 1);
        ROM_SIZE.add("32K", 0x00);
        ROM_SIZE.add("64K", 0x01);
        ROM_SIZE.add("128K", 0x02);
        ROM_SIZE.add("256K", 0x03);
        ROM_SIZE.add("512K", 0x04);
        ROM_SIZE.add("1MB", 0x05);
        ROM_SIZE.add("2MB", 0x06);
        ROM_SIZE.add("4MB", 0x07);
        ROM_SIZE.add("8MB", 0x08);

        RAM_SIZE = new EnumDataType(PATH, "ram_size", 1);
        RAM_SIZE.add("NONE", 0x00);
        RAM_SIZE.add("2KB", 0x01);
        RAM_SIZE.add("8KB", 0x02);
        RAM_SIZE.add("32KB", 0x03);
        RAM_SIZE.add("128KB", 0x04);
        RAM_SIZE.add("64KB", 0x05);

        REGION = new EnumDataType(PATH, "region", 1);
        REGION.add("JAPAN", 0x00);
        REGION.add("WORLD", 0x01);

        HEADER = new StructureDataType(PATH, "header", 0);
        HEADER.add(TITLE_BLOCK, "title_block", null);
        HEADER.add(array(ch, 2), "new_licensee_code", null);
        HEADER.add(SGB_FLAG, "sgb_flag", null);
        HEADER.add(CART_TYPE, "cartridge_type", null);
        HEADER.add(ROM_SIZE, "rom_size", null);
        HEADER.add(RAM_SIZE, "ram_size", null);
        HEADER.add(REGION, "region", null);
        HEADER.add(u8, "old_licensee_code", null);
        HEADER.add(u8, "mask_rom_version", null);
        HEADER.add(u8, "header_checksum", null);
        HEADER.add(u16, "global_checksum", null);

        // 5x 16-bit RGB555 little-endian colors form a CGB palette.
        CGB_PALETTE_COLOR = new TypedefDataType(PATH, "cgb_palette_color", u16);

        LCDC = new EnumDataType(PATH, "lcdc", 1);
        LCDC.add("BG_WIN_ENABLE", 0x01);
        LCDC.add("OBJ_ENABLE", 0x02);
        LCDC.add("OBJ_SIZE_8X16", 0x04);
        LCDC.add("BG_TILEMAP_9C00", 0x08);
        LCDC.add("TILEDATA_8000", 0x10);
        LCDC.add("WIN_ENABLE", 0x20);
        LCDC.add("WIN_TILEMAP_9C00", 0x40);
        LCDC.add("LCD_ENABLE", 0x80);

        // STAT bits 0-1 (PPU mode) are read-only and not enumerated.
        STAT = new EnumDataType(PATH, "stat", 1);
        STAT.add("LYC_EQ_LY", 0x04);
        STAT.add("MODE0_INTR", 0x08);
        STAT.add("MODE1_INTR", 0x10);
        STAT.add("MODE2_INTR", 0x20);
        STAT.add("LYC_INTR", 0x40);

        INTR_FLAGS = new EnumDataType(PATH, "intr_flags", 1);
        INTR_FLAGS.add("VBLANK", 0x01);
        INTR_FLAGS.add("STAT", 0x02);
        INTR_FLAGS.add("TIMER", 0x04);
        INTR_FLAGS.add("SERIAL", 0x08);
        INTR_FLAGS.add("JOYPAD", 0x10);

        // Hardware reports 0 for pressed; the bit names describe each line's identity.
        JOYPAD = new EnumDataType(PATH, "joypad", 1);
        JOYPAD.add("RIGHT_OR_A", 0x01);
        JOYPAD.add("LEFT_OR_B", 0x02);
        JOYPAD.add("UP_OR_SELECT", 0x04);
        JOYPAD.add("DOWN_OR_START", 0x08);
        JOYPAD.add("SELECT_DIR", 0x10);
        JOYPAD.add("SELECT_ACTION", 0x20);

        // CGB palette index lives in bits 0-2 (values 0-7); not enumerated.
        OAM_ATTRIBUTES = new EnumDataType(PATH, "oam_attributes", 1);
        OAM_ATTRIBUTES.add("CGB_VRAM_BANK", 0x08);
        OAM_ATTRIBUTES.add("DMG_PALETTE_OBP1", 0x10);
        OAM_ATTRIBUTES.add("X_FLIP", 0x20);
        OAM_ATTRIBUTES.add("Y_FLIP", 0x40);
        OAM_ATTRIBUTES.add("BG_OVER_OBJ", 0x80);

        OAM_ENTRY = new StructureDataType(PATH, "oam_entry", 0);
        OAM_ENTRY.add(u8, "y", null);
        OAM_ENTRY.add(u8, "x", null);
        OAM_ENTRY.add(u8, "tile", null);
        OAM_ENTRY.add(OAM_ATTRIBUTES, "attrs", null);
    }

    public static void addAll(DataTypeManager m) {
        var types = new DataType[]{
                LOGO, TILE_2BPP, TILE_1BPP, CGB_PALETTE_COLOR,
                CGB_FLAG, TITLE_BLOCK_OLD, TITLE_BLOCK_NEW, TITLE_BLOCK,
                SGB_FLAG, CART_TYPE, ROM_SIZE, RAM_SIZE, REGION, HEADER,
                LCDC, STAT, INTR_FLAGS, JOYPAD, OAM_ATTRIBUTES, OAM_ENTRY,
        };
        var c = m.createCategory(PATH);
        Arrays.stream(types).forEach(d -> c.addDataType(d, DataTypeConflictHandler.DEFAULT_HANDLER));
    }

    static Array array(DataType d, int size) {
        return new ArrayDataType(d, size, -1);
    }
}

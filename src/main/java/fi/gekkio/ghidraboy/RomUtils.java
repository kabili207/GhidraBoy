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

import ghidra.app.util.bin.ByteProvider;

import java.io.IOException;
import java.util.Optional;

public final class RomUtils {
    private RomUtils() {
    }

    private static final Sha256 LOGO_HASH = Sha256.parse("daf4cabdc852baa0291849203f0b41fd0b4ecd58e0d7aff4a509f5de4d7f9a2e");

    public static Optional<GameBoyKind> detectRom(ByteProvider provider) throws IOException {
        if (provider.length() >= 0x150) {
            var logo = provider.readBytes(0x0104, 0x30);
            if (LOGO_HASH.equals(Sha256.of(logo))) {
                var cgbFlag = (short) provider.readByte(0x0143);
                return Optional.of((cgbFlag & 0x80) == 0 ? GameBoyKind.GB : GameBoyKind.CGB);
            }
        }
        return Optional.empty();
    }

    /**
     * Memory bank controller family, derived from the cartridge type byte at
     * header offset 0x0147. The bank-switching analyzer uses this to decide
     * whether a ROM has switchable banks at all. The actual ROM bank-select
     * register sits at 0x2000-0x3fff for every banked family here (MBC5 splits
     * the low 8 bits and bit 8 across 0x2000-0x2fff / 0x3000-0x3fff, but both
     * fall in that window), so the analyzer treats 0x2000-0x3fff uniformly.
     */
    public enum Mbc {
        NONE,
        MBC1,
        MBC2,
        MBC3,
        MBC5,
        OTHER;

        public boolean hasRomBanking() {
            return this != NONE;
        }
    }

    public static Mbc detectMbc(ByteProvider provider) throws IOException {
        if (provider.length() < 0x148) {
            return Mbc.NONE;
        }
        var type = provider.readByte(0x0147) & 0xff;
        return switch (type) {
            case 0x00, 0x08, 0x09 -> Mbc.NONE; // ROM only (+RAM / +battery)
            case 0x01, 0x02, 0x03 -> Mbc.MBC1;
            case 0x05, 0x06 -> Mbc.MBC2;
            case 0x0f, 0x10, 0x11, 0x12, 0x13 -> Mbc.MBC3;
            case 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e -> Mbc.MBC5;
            default -> Mbc.OTHER; // MBC6/7, MMM01, HuC1/3, etc. (bank reg still ~0x2000-0x3fff)
        };
    }
}

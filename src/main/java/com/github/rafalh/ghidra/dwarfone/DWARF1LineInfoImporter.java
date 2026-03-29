package com.github.rafalh.ghidra.dwarfone;

import java.io.IOException;

import com.github.rafalh.ghidra.dwarfone.model.AddrAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.AttributeName;
import com.github.rafalh.ghidra.dwarfone.model.ConstAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.DebugInfoEntry;
import com.github.rafalh.ghidra.dwarfone.model.RefAttributeValue;
import com.github.rafalh.ghidra.dwarfone.model.StringAttributeValue;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.util.task.TaskMonitor;

/**
 * Parses the DWARF1 .line section (MWCC PS2 format) and attaches source
 * file/line EOL comments to instruction addresses in the Ghidra listing.
 *
 * MWCC PS2 .line section layout:
 *
 *   Block header (8 bytes):
 *     uint32  blockLength   total block size including this field
 *     uint32  baseAddr      absolute base address for all entries in this block
 *
 *   Entries (10 bytes each), starting at offset 8:
 *     uint16  line_number
 *     uint16  zero          (always 0x0000)
 *     uint16  0xFFFF        sentinel
 *     uint16  delta_lo      byte offset from baseAddr (low 16 bits)
 *     uint16  delta_hi      byte offset from baseAddr (high 16 bits, always 0)
 *
 *   Blocks are contiguous in the section.
 *   An entry with line_number == 0 marks the end of the block's entries.
 */
public class DWARF1LineInfoImporter {

    private static final int BLOCK_HEADER_SIZE = 8;  // blockLength(4) + baseAddr(4)
    private static final int ENTRY_SIZE        = 10; // line(2) + zero(2) + ffff(2) + delta(4)

    private final DWARF1Program dwarfProgram;
    private final MessageLog log;
    private final TaskMonitor monitor;

    DWARF1LineInfoImporter(DWARF1Program dwarfProgram, MessageLog log, TaskMonitor monitor) {
        this.dwarfProgram = dwarfProgram;
        this.log = log;
        this.monitor = monitor;
    }

    /**
     * Processes a single COMPILE_UNIT DIE: reads its AT_stmt_list offset,
     * then parses the corresponding block in the .line section.
     */
    void processCompileUnit(DebugInfoEntry cuDie, ByteProvider lineBp) throws IOException {
        // AT_stmt_list can be encoded as DATA4 (Const), REF, or ADDR depending on compiler
        long blockOffset;
        var asConst = cuDie.<ConstAttributeValue>getAttribute(AttributeName.STMT_LIST);
        if (asConst.isPresent()) {
            blockOffset = asConst.get().get().longValue();
        } else {
            var asRef = cuDie.<RefAttributeValue>getAttribute(AttributeName.STMT_LIST);
            if (asRef.isPresent()) {
                blockOffset = asRef.get().get();
            } else {
                var asAddr = cuDie.<AddrAttributeValue>getAttribute(AttributeName.STMT_LIST);
                if (asAddr.isPresent()) {
                    blockOffset = asAddr.get().get();
                } else {
                    return;
                }
            }
        }

        String cuName = cuDie.<StringAttributeValue>getAttribute(AttributeName.NAME)
                .map(StringAttributeValue::get)
                .orElse(null);

        parseLineBlock(lineBp, blockOffset, cuName);
    }

    private void parseLineBlock(ByteProvider bp, long blockOffset, String cuName) throws IOException {
        long fileLen = bp.length();
        if (blockOffset + BLOCK_HEADER_SIZE > fileLen) {
            log.appendMsg(String.format("[DWARF1 .line] Block offset 0x%X out of bounds.", blockOffset));
            return;
        }

        BinaryReader br = new BinaryReader(bp, dwarfProgram.isLittleEndian());
        br.setPointerIndex(blockOffset);

        long blockLength = br.readNextUnsignedInt();
        if (blockLength < BLOCK_HEADER_SIZE + ENTRY_SIZE) {
            return;
        }

        long baseAddr = br.readNextUnsignedInt();
        if (baseAddr == 0 || baseAddr > 0xFFFFFFFFL) {
            return;
        }

        long blockEnd = blockOffset + blockLength;
        if (blockEnd > fileLen) {
            blockEnd = fileLen;
        }

        String fileName = buildFileName(cuName);
        Listing listing = dwarfProgram.getProgram().getListing();

        while (br.getPointerIndex() + ENTRY_SIZE <= blockEnd) {
            if (monitor.isCancelled()) {
                break;
            }

            int  line    = br.readNextUnsignedShort(); // line number
            br.readNextUnsignedShort();                // zero
            br.readNextUnsignedShort();                // 0xFFFF sentinel
            long deltaLo = br.readNextUnsignedShort(); // delta low 16 bits
            long deltaHi = br.readNextUnsignedShort(); // delta high 16 bits
            long delta   = deltaLo | (deltaHi << 16);

            if (line == 0 || line == 0xFFFF) {
                continue;
            }

            long resolvedAddr = baseAddr + delta;
            if (resolvedAddr > 0xFFFFFFFFL) {
                continue;
            }

            Address addr = dwarfProgram.toAddr(resolvedAddr);
            setEolComment(listing, addr, buildComment(fileName, line));
        }
    }

    private static String buildFileName(String cuName) {
        if (cuName == null) return null;
        int slash = Math.max(cuName.lastIndexOf('/'), cuName.lastIndexOf('\\'));
        return (slash >= 0) ? cuName.substring(slash + 1) : cuName;
    }

    private static String buildComment(String fileName, int lineNum) {
        return (fileName != null ? fileName : "line") + ":" + lineNum;
    }

    private void setEolComment(Listing listing, Address addr, String comment) {
        String existing = listing.getComment(CommentType.EOL, addr);
        if (existing != null) {
            if (existing.contains(comment)) {
                return;
            }
            comment = existing + " | " + comment;
        }
        listing.setComment(addr, CommentType.EOL, comment);
    }
}

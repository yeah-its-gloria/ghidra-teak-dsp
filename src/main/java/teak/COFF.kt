package teak

import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.InvalidDataException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.MalformedInputException
import java.nio.charset.StandardCharsets
import java.util.IllegalFormatFlagsException

class COFF {
  // FOffset -> file offset. all absolute

  data class FileHeader (
    val magic: UShort, // varies by implementation
    val sectionCount: UShort,
    val timestamp: UInt,
    val symbolFOffset: UInt,
    val symbolCount: UInt,
    val optionalHeaderSize: UShort,
    val flags: UShort
  )

  data class OptionalHeader (
    val magic: UShort,
    val versionStamp: UShort,
    val textSize: UInt,
    val dataSize: UInt,
    val bssSize: UInt,
    val entryPoint: UInt,
    val textStart: UInt,
    val dataStart: UInt
  )

  @JvmInline
  value class SectionFlags(val raw: UInt) {
    // Matches teakra: https://github.com/wwylele/teakra/blob/3d697a18df504f4677b65129d9ab14c7c597e3eb/src/coff_reader/coff.h#L75
    companion object {
      val Exec = SectionFlags(0x0001u)
      val Unk2 = SectionFlags(0x0002u)
      val Prog = SectionFlags(0x0008u)
      val Data = SectionFlags(0x0010u)
      val Moni = SectionFlags(0x0020u)
      val Un40 = SectionFlags(0x0040u)
      val Dupl = SectionFlags(0x0080u)
      val U200 = SectionFlags(0x0200u)

      val RegionMask = Prog or Data
    }

    constructor(data: BinaryReader) : this(data.getUInt())

    infix fun and(other: SectionFlags): SectionFlags = SectionFlags(this.raw and other.raw)
    infix fun or(other: SectionFlags): SectionFlags = SectionFlags(this.raw or other.raw)

    fun has(flag: SectionFlags): Boolean = (this.raw and flag.raw) == flag.raw

    override fun toString(): String {
      var flag = ""

      if (has(Exec)) { flag += "Exec," }
      if (has(Prog)) { flag += "Prog," }
      if (has(Unk2)) { flag += "Unk2," }
      if (has(Data)) { flag += "Data," }
      if (has(Moni)) { flag += "Moni," }
      if (has(Un40)) { flag += "Un40," }
      if (has(Dupl)) { flag += "Dupl," }
      if (has(U200)) { flag += "U200," }


      return flag.trimEnd { it == ',' }
    }
  }

  private data class SectionHeader (
    val name: String, // 8 bytes
    val progAddress: UInt,
    val dataAddress: UInt,
    val size: UInt,
    val sectionDataFOffset: UInt,
    val relocationTableFOffset: UInt,
    val lineNumberFOffset: UInt,
    val relocationTableEntries: UShort,
    val lineNumberTableEntries: UShort,
    val flags: SectionFlags
  )

  data class Relocation (
    val virtualAddress: UInt,
    val symbolIndex: UInt,
    val type: UShort
  )

  sealed interface LineNumberData {
    data class AsSymbolIndex(val index: UInt): LineNumberData
    data class AsPhysicalAddress(val address: UInt): LineNumberData
  }

  data class LineNumber (
    val symbolIndexOrPhysicalAddress: LineNumberData,
    val lineNumber: UShort
  )

  @JvmInline
  value class SymbolType(val raw: UShort) {
    companion object {
      val UNDEFINED = SymbolType(0U)
      val ABSOLUTE = SymbolType(1U)
      val DEBUG = SymbolType(2U)
    }
  }

  @JvmInline
  value class SymbolStorageClass(val raw: Byte) {
    constructor(data: BinaryReader) : this(data.readNextByte())

    // matches teakra: https://github.com/wwylele/teakra/blob/3d697a18df504f4677b65129d9ab14c7c597e3eb/src/coff_reader/coff.h#L98
    override fun toString(): String { // TODO: expose this like flags
      return when (raw.toInt()) {
        0 -> "label" 1 -> "auto" 2 -> "external" 3 -> "static" 4 -> "register"
        8 -> "struct" 9 -> "arg" 10 -> "struct-tag" 11 -> "union" 12 -> "union-tag"
        13 -> "typedef" 15 -> "enum-tag" 16 -> "enum" 18 -> "bitfield"
        19 -> "auto-arg" 98 -> "start" 99 -> "end" 100 -> "block"
        101 -> "func" 102 -> "struct-size" 103 -> "file" 255 -> "physical-function-end"
        107, 108, 109, 110, 111, 112 -> "ar"

        else -> raw.toInt().toString()
      }
    }
  }

  data class Symbol (
    val name: String, // 8 bytes
    val value: UInt,
    val sectionNumber: Short,
    val type: SymbolType,
    val storageClass: SymbolStorageClass,
    val auxCount: Byte
  )

  @Suppress("ArrayInDataClass")
  data class Section (
      val name: String,
      val progAddress: UInt,
      val dataAddress: UInt,
      val data: ByteArray,
      val flags: SectionFlags,
      val relocations: List<Relocation>,
      val lineNumbers: List<LineNumber>
  )

  val header: FileHeader
  val optionalHeader: OptionalHeader?

  val symbols: List<Symbol>
  val sections: List<Section>

  constructor (data: BinaryReader) {
    this.header = parseFileHeader(data)

    val stringList = getStringTable(data, header)
    if (header.optionalHeaderSize > 0u) {
      if (header.optionalHeaderSize != 28.toUShort()) {
        throw InvalidDataException("Unimplemented optional header size ${header.optionalHeaderSize}")
      }

      this.optionalHeader = parseOptionalHeader(data)
    } else {
      this.optionalHeader = null
    }

    var sectionHeaders = emptyArray<SectionHeader>()
    for (i in 0 ..< header.sectionCount.toInt()) {
      sectionHeaders += parseSectionHeader(data, stringList)
    }

    data.setPointerIndex(header.symbolFOffset.toInt())
    var symbols = emptyArray<Symbol>()
    for (i in 0 ..< header.symbolCount.toInt()) {
      symbols += parseSymbol(data, stringList)
    }

    var sections = emptyArray<Section>()

    @Suppress("DestructuringDeclaration")
    for (header in sectionHeaders) {
      if (header.flags.has(SectionFlags.Dupl)) {
        continue // TODO: do proper deduplication
      }

      if (header.size.toInt() == 0) {
        continue // TODO: figure out why there's empty sections
      }

      // check matches teakra
      val type = header.flags and SectionFlags.RegionMask
      if (type == SectionFlags.Prog && header.dataAddress != 0u) { throw IllegalFormatFlagsException("prog section has data addr") }
      else if (type == SectionFlags.Data && header.progAddress != 0u) { throw IllegalFormatFlagsException("data section has prog addr") }

      val bytes = data.getBytes(header.size.toInt(), header.sectionDataFOffset.toLong())

      var relocations = emptyArray<Relocation>()
      var lineNumbers = emptyArray<LineNumber>()

      if (header.relocationTableEntries.toInt() > 0) {
        data.setPointerIndex(header.relocationTableFOffset.toInt())
        for (i in 0 ..< header.relocationTableEntries.toInt()) {
          relocations += parseRelocation(data)
        }
      }

      if (header.lineNumberTableEntries.toInt() > 0) {
        data.setPointerIndex(header.lineNumberFOffset.toInt())
        for (i in 0 ..< header.lineNumberTableEntries.toInt()) {
          lineNumbers += parseLineNumber(data)
        }
      }

      sections += Section(header.name, header.progAddress, header.dataAddress, bytes, header.flags, relocations.toList(), lineNumbers.toList())
    }

    this.sections = sections.toList()
    this.symbols = symbols.toList()
  }

  companion object {
    private val nameDecoder = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.IGNORE) // this gets really upset otherwise and I dunno how to handle it. teakra just doesn't care but also gets the correct symbol names?

    private fun bytesToString(bytes: ByteArray): String {
      return nameDecoder.decode(ByteBuffer.wrap(bytes)).toString().trimEnd { it == 0.toChar() }
    }

    private fun getName(data: BinaryReader, stringList: List<String>): String {
      val bytes = data.getBytes(8)

      val head = bytes.getUInt()
      if (head == 0x00u) {
        val index = bytes.getUInt(4).toInt().coerceIn(0, stringList.size - 1)
        return stringList[index]
      }

      return bytesToString(bytes)
    }

    // TODO: verify header contents

    private fun parseFileHeader(data: BinaryReader): FileHeader {
      return FileHeader(data.getUShort(), data.getUShort(), data.getUInt(), data.getUInt(), data.getUInt(), data.getUShort(), data.getUShort())
    }

    private fun getStringTable(data: BinaryReader, header: FileHeader): List<String> {
      data.setPointerIndex((header.symbolFOffset + (header.symbolCount * 18u)).toInt())

      val count = data.getUInt() - 4u // count includes itself
      val block = data.getBytes(count.toInt())

      var strings = emptyArray<String>()
      var current = emptyArray<Byte>()
      for (byte in block) {
        if (byte.toInt() == 0x00) {
          strings += bytesToString(current.toByteArray())
          current = emptyArray()
          continue
        }

        current += byte
      }

      data.setPointerIndex(20) // reset buffer to after the file list
      return strings.toList()
    }

    private fun parseOptionalHeader(data: BinaryReader): OptionalHeader {
      return OptionalHeader(data.getUShort(), data.getUShort(), data.getUInt(), data.getUInt(), data.getUInt(), data.getUInt(), data.getUInt(), data.getUInt())
    }

    private fun parseSectionHeader(data: BinaryReader, stringList: List<String>): SectionHeader {
      return SectionHeader(getName(data, stringList), data.getUInt(), data.getUInt(), data.getUInt(), data.getUInt(), data.getUInt(), data.getUInt(), data.getUShort(), data.getUShort(), SectionFlags(data))
    }

    private fun parseRelocation(data: BinaryReader): Relocation {
      return Relocation(data.getUInt(), data.getUInt(), data.getUShort())
    }

    private fun parseLineNumber(data: BinaryReader): LineNumber {
      val indexOrAddress = data.getUInt()
      val number = data.getUShort()

      val inner = if (number == 0.toUShort()) { LineNumberData.AsSymbolIndex(indexOrAddress) } else { LineNumberData.AsPhysicalAddress(indexOrAddress) }

      return LineNumber(inner, number)
    }

    private fun parseSymbol(data: BinaryReader, stringList: List<String>): Symbol {
      return Symbol(getName(data, stringList), data.readNextUnsignedInt().toUInt(), data.readNextShort(), SymbolType(data.getUShort()), SymbolStorageClass(data), data.readNextByte())
    }
  }
}

// Utility functions

private fun BinaryReader.getUShort(): UShort { return this.readNextUnsignedShort().toUShort() }
private fun BinaryReader.getUInt(): UInt { return this.readNextUnsignedInt().toUInt() }
private fun BinaryReader.getBytes(size: Int, position: Long? = null): ByteArray { return if (position != null) { readByteArray(position, size) } else { readNextByteArray(size) } }

private fun ByteArray.getUInt(offset: Int = 0): UInt {
  return (this[offset].toUInt() and 0xFFu) or ((this[offset + 1].toUInt() and 0xFFu) shl 8) or ((this[offset + 2].toUInt() and 0xFFu) shl 16) or ((this[offset + 3].toUInt() and 0xFFu) shl 24)
}

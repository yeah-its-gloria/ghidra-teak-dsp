package teak

import ghidra.app.util.MemoryBlockUtils
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.opinion.AbstractProgramWrapperLoader
import ghidra.app.util.opinion.LoadSpec
import ghidra.app.util.opinion.Loader
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSpace
import ghidra.program.model.lang.LanguageCompilerSpecPair
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType

class CoffLoader : AbstractProgramWrapperLoader() {
  private val languageId = "Teak:LE:16:default"
  private val compilerId = "default"

  companion object {
    private fun wordAddress(space: AddressSpace, wordOffset: UInt): Address {
		  return space.getAddress(wordOffset.toLong(), true)
	  }
  }

  override fun getName(): String {
    return "COFF (Teak)"
  }

  override fun findSupportedLoadSpecs(provider: ByteProvider): Collection<LoadSpec?> {
    var loadSpecs = emptyArray<LoadSpec>()
		if (isSupportedCoff(provider)) {
			loadSpecs += LoadSpec(this, 0, LanguageCompilerSpecPair(languageId, compilerId), true)
		}

		return loadSpecs.toList()
  }

	override fun load(program: Program, settings: Loader.ImporterSettings) {
		val log = settings.log()
		val monitor = settings.monitor()
    val provider = settings.provider()

    val codeSpace = program.addressFactory.getAddressSpace("code")
		val dataSpace = program.addressFactory.getAddressSpace("data")
		if (codeSpace == null || dataSpace == null) {
			log.appendMsg("Teak language is missing the 'code' or 'data' address space")
			return
		}

    val reader = BinaryReader(provider, true)
    val coff = COFF(reader)

    log.appendMsg("File specifies ${coff.header.sectionCount} sections, of which ${coff.sections.size} are usable")

		var codeStarts = emptyArray<Address>()

		@Suppress("DestructuringDeclaration")
		for (section in coff.sections) {
			monitor.checkCancelled()
			if (section.flags.has(COFF.SectionFlags.Prog)) {
				val block = MemoryBlockUtils.createInitializedBlock(program, false, "code_${section.name}", wordAddress(codeSpace, section.progAddress), section.data.inputStream(), section.data.size.toLong(), "COFF section ${section.name}, type code", "COFF (Teak)", true, true, true, log, monitor)
				codeStarts += block.start
			}

			if (section.flags.has(COFF.SectionFlags.Data)) {
				val block = MemoryBlockUtils.createInitializedBlock(program, false, "data_${section.name}", wordAddress(dataSpace, section.dataAddress), section.data.inputStream(), section.data.size.toLong(), "COFF section ${section.name}, type data", "COFF (Teak)", true, true, false, log, monitor)
				codeStarts += block.start
			}
		}

		log.appendMsg("File specifies ${coff.header.symbolCount} symbols")

		// this code is very broken and upsets Ghidra
		/*for (symbol in coff.symbols) {
			val address = program.addressFactory.defaultAddressSpace.getAddress(symbol.value.toLong())
			program.symbolTable.createLabel(address, symbol.name, SourceType.IMPORTED)

			// TODO: give symbols proper types
		}*/
	}

  private fun isSupportedCoff(provider: ByteProvider): Boolean {
    val magic = provider.readBytes(0, 2)
    return (magic[0] == 0xa4.toByte() && magic[1] == 0x00.toByte())
  }
}

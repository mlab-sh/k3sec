rule packed_elf_dropper : dropper elf packed
{
    meta:
        description = "ELF binary packed with UPX, common for dropped payloads"
        author = "k3sec"
        severity = "high"
    strings:
        $upx_sig  = "UPX!"
        $upx_note = "This file is packed with the UPX"
    condition:
        // ELF magic (\x7fELF) at offset 0, plus a UPX signature.
        uint32(0) == 0x464c457f and any of ($upx*)
}

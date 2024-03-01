private rule Macho
{
    meta:
        description = "private rule to match Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca

}
rule macos_toydrop_a_obfuscation_code
{
    strings:
        $codeA = {
            48 63 85 ?? ?? ?? ??
            8B 84 85 ?? ?? ?? ??
            88 85 ?? ?? ?? ??
            8A 85 ?? ?? ?? ??
            48 63 8D ?? ?? ?? ??
            88 84 0D ?? ?? ?? ??
            8B 85 ?? ?? ?? ??
            83 C0 01
            89 85 ?? ?? ?? ??
        }
        $codeB = {
            66 ( 41 0f | 0F ) ( 6F | 6f 44 ) ( 04 | 05 ) 0?
            66 0F 38 00 C1
            ( 66 41 0F 7E 45 ?? | 66 0F 7e 03 )
            ( 48 | 49 ) 83 C? 10
            ( 48 | 49 ) 83 C? 04
            ( 4? 81 F? | 48 3D ??) [3-4]
            75 ??
        }
    condition:
        Macho and any of them
}

rule macos_toydrop_a_agent_strings
{
    strings:
        $stringA = "_GoKnuckles"
        $stringB = "_HearthI"
        $stringC = "_getNLS"
        $stringD = "_rrStr"
    condition:
        Macho and (2 of them)
}
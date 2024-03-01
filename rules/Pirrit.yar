import "macho"
rule macos_pirrit_obfuscated_installer
{
    strings:
        $xor_imm = {
            80 35 ?? ?? ?? 00 ??
            80 35 ?? ?? ?? 00 ??
            80 35 ?? ?? ?? 00 ??
        }

        $symbolA = "_AuthorizationExecuteWithPrivileges"
        $symbolB = "_NSApp"
        $symbolC = "_CC_MD5"
        $symbolD = "_arc4random_uniform"
        $symbolE = "_dyld_register_func_for_add_image"
        $symbolF = "_IOServiceMatching"

        $dlopen = "_dlopen"

    condition:
        $dlopen and
        3 of ($symbol*) and #xor_imm > 5 and
        for any segment_index in (0 .. macho.number_of_segments - 1):
        (
            for any section_index in (0 .. macho.segments[segment_index].nsects - 1):
            (
                macho.segments[segment_index].sections[section_index].segname == "__TEXT"
                and
                macho.segments[segment_index].sections[section_index].sectname == "__text"
                and
                $xor_imm in (
                        // We make sure we're actually in code, and not in bytes at the
                        // end of a binary which was causing a ton of unwanted hits on
                        // legit binaries from XCode.
                        //
                        // We use offset and not address here because address will
                        // apparently only work if YARA is scanning a process, not
                        // a binary
                        macho.segments[segment_index].sections[section_index].offset..
                        macho.segments[segment_index].sections[section_index].offset +
                        macho.segments[segment_index].sections[section_index].size
                )
            )
        )
}

rule macos_pirrit_common_assembly
{
    strings:
        // 31ff               xor     edi, edi  {0x0}
        // be0a000000         mov     esi, 0xa
        // e83b2e2300         call    _dlopen
        // 488d35dda62600     lea     rsi, [rel data_10026e4e8]
        // 4889c7             mov     rdi, rax
        // e8322e2300         call    _dlsym
        $asm0 = {
            31 ff
            be 0a 00 00 00
            e8 ?? ?? ?? ??
            48 8d 35 ?? ?? ?? ??
            48 89 c7
            e8 ?? ?? ?? ??
            48 89 (c7 | 45 a8)
        }

        // 55                 push    rbp {var_8}
        // 4889e5             mov     rbp, rsp {var_8}
        // 488b05bdaa1100     mov     rax, qword [rel data_1002a91e8] ; sub_10018e72d()
        // ffe0               jmp     rax

        //                    int64_t sub_10018e72d()
        // ff25cdaa1100       jmp     qword [rel data_1002a9200]
        $asm1 = {55 48 89 e5 48 8b 05 [3] 00 ff e0 ff 25 [3] 00}

        $dlopen = "_dlopen"
        $dlsym = "_dlsym"

    condition:
        2 of ($dl*) and 1 of ($asm*)
}
    

rule macos_pirrit_plist
{
    strings:
        $fuzzy_copyright = /NSHumanReadableCopyright.{0,100}\.iup/
    condition:
        filesize < 10KB and
        any of ($fuzzy_*)
}
    

rule macos_pirrit_shell_script
{
    strings:
        $shebang = "#!"
        $magic1 = { 50 4b 03 04 }
        $password = /funzip.*?>/
    condition:
        $shebang at 0 and $magic1 and $password
}


rule hunt_pirrit_variants
{
    strings:
        $x0 = {008BD5DF3DD38F3E30D6552639A7E6FE16EA5F6614C272B30DF61CC901A56B6896C29F454E7D622BE872DDEA99CF96667C541F88C71CE6D39D67D311C7E05D445EF24BB7F007D764CFB41B2D532288D93C168A1A}
        // {PUvP_
        $x1 = {7b505576505f}
        // processInfo.arguments.firstObject.lastPathComponent.environment.processIdentifier.numberWithInt:.hostName.globallyUniqueString.stringWithFormat:
        $x2 = {70726F63657373496E666F00617267756D656E74730066697273744F626A656374006C61737450617468436F6D706F6E656E7400656E7669726F6E6D656E740070726F636573734964656E746966696572006E756D62657257697468496E743A00686F73744E616D6500676C6F62616C6C79556E69717565537472696E6700737472696E6757697468466F726D61743A}
        
        $x3 = "@_IORegistryEntryCreateCFProperty"

        $x4 = "UDRGp0SARARARARARA`EIRBRCp"

        $x5 = {00654B39B42ECAF00FD402B66D691086D24FE7CF288C1D780CC3226FA7140A1011436E8ADEC866C7C4ABC1492CEAD175887366FDE50BD2678B95C9BD41965EAA92E1CAF0}
        
        $x6 = "LicenseInstaller.build"

        $x7 = "@_IOServiceMatching"

        $x8 = "RBSCSCSCSCSCRBRBSCRBRBRBRBRBp"

        $x9 = "RBSCRBSCSCRBRBSCSCSCSCRBRBp"
    condition:
        3 of ($x*)
}


rule hunt_macos_ptrace_deny
{
    strings:
        /*
            48c7c71f000000     mov     rdi, 0x1f PT_DENY_ATTACH 31 (0x1f)
            48c7c01a000002     mov     rax, 0x200001a ptrace 26 (0x1a)
            0f05               syscall
        */
        $ = {48 c7 c7 1f 00 00 00 48 c7 c0 1a 00 00 02 0f 05}

    condition:
        any of them
}
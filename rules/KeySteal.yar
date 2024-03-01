private rule _fat
{
    condition:
        (
            uint32be(0) == 0xcafebabe or uint32(0) == 0xcafebabe or
            uint32be(0) == 0xcafebabf or uint32(0) == 0xcafebabf
        ) and uint32be(4) >= 1 and uint32be(4) < 25
}

private rule _macho
{
    condition:
        (
            uint32be(0) == 0xfeedface or uint32(0) == 0xfeedface or
            uint32be(0) == 0xfeedfacf or uint32(0) == 0xfeedfacf
        ) or _fat
}

rule XProtect_MACOS_KEYSTEAL_A
{
    strings:
        // data:application/x-apple-aspen-mobileprovision;base64,%@
        $ = { 64 61 74 61 3A 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 2D 61 70 70 6C 65 2D 61 73 70 65 6E 2D 6D 6F 62 69 6C 65 70 72 6F 76 69 73 69 6F 6E 3B 62 61 73 65 36 34 2C 25 40 }
        // newdev newid gogogo
        $ = { 00 6E 65 77 64 65 76 00 6E 65 77 69 64 00 67 6F 67 6F 67 6F 00 }
        // {"data":"%@"}
        $ = { 7B 22 64 61 74 61 22 3A 22 25 40 22 7D }
    condition:
        _macho and all of them and filesize < 1MB
}
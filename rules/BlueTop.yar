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

rule macos_bluetop {
    strings:
        $ = { 47 45 54 20 25 73 20 48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 25 73 3A 25 75 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 55 70 67 72 61 64 65 0D 0A 55 70 67 72 61 64 65 3A 20 77 65 62 73 6F 63 6B 65 74 0D 0A 53 65 63 2D 57 65 62 53 6F 63 6B 65 74 2D 56 65 72 73 69 6F 6E 3A 20 [2] 0D 0A 53 65 63 2D 57 65 62 53 6F 63 6B 65 74 2D 4B 65 79 3A 20 25 73 0D 0A 0D 0A }
        $ = { 66 61 69 6C 72 65 73 74 61 72 74 00 66 6C 6F 63 6B 00 6C 6F 67 2E 74 78 74 00 }
    condition:
        _macho and all of them and filesize < 1MB
}

rule macos_bluego {
    strings:
        $ = { 5f 47 6f 55 72 62 61 6e 44 6c 6c 5f 53 74 61 72 56 50 4e 53 74 61 72 74 50 72 6f 78 79 43 6c 69 65 6e 74 }
        $ = { 5f 47 6f 55 72 62 61 6e 44 6c 6c 5f 53 74 61 72 56 50 4e 43 6c 69 65 6e 74 53 53 48 45 72 72 6f 72 }
        $ = { 54 68 65 72 65 20 69 73 20 6E 6F 20 69 6E 66 6F 72 6D 61 74 69 6F 6E 20 6F 6E 20 63 75 72 72 65 6E 74 6C 79 20 63 6F 6E 6E 65 63 74 65 64 20 53 53 48 20 73 65 72 76 65 72 }
    condition:
        _macho and all of them and filesize < 20MB
}

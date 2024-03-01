private rule _fat
{
    strings:
        $a = { CA FE BA BE }

    condition:
        $a at 0 and uint32(4) < 0x14000000
}

private rule _macho
{
    strings:
        $ = { CE FA ED FE }
        $ = { CF FA ED FE }
        $ = { FE ED FA CE }
        $ = { FE ED FA CF }

    condition:
        for any of them: ($ at 0) or _fat
}

private rule _osa
{
    strings:
        $a = "FasdUAS"

    condition:
        $a at 0
}

rule macos_shc
{
    strings:
        $ = { 78256C78 00 3D256C75202564 00 256C752025642563 00 }
        $ = { 2573257325733A2025730A 00 }
        $ = "_execvp"
        $ = "_putenv"
        $ = "_stat"

    condition:
        _macho and filesize < 1MB and all of them
}

rule macos_dubrobber_browser_agent_a
{
    strings:
        $ = "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f"
        $ = "plutil -replace CFBundleExecutable -string"
        $ = "codesign --remove-signature"
        $ = "mdfind kMDItemCFBundleIdentifier"
        $ = "security delete-generic-password"
        $ = "security add-generic-password"
        $ = "agentd.php"

    condition:
        _macho and 5 of them and filesize < 2MB
}

rule macos_dubrobber_browser_agent_b
{
    strings:
        $ = "No apps with bundle id of "
        $ = "?cors&"
        $ = " -ks "
        $ = "HaC80bwXscjqZ7KM6VOxULOB534"
        $ = "appleid"

    condition:
        _macho and all of them and filesize < 2MB
}

rule macos_dubrobber_browser_agent_c
{
    strings:
        $ = "com.vluxe.starscream.websocket"
        $ = "cypher suites"
        $ = "_$sSS10describingSSx_tclufC"
        $ = { 00 ( 44756d6d79 | 42756e6e79 ) 00 }
        $ = "bypassCSPEnabled"
        $ = { 666f72636564 0000 }

    condition:
        _macho and 4 of them and filesize < 3MB
}

rule macos_dubrobber_browser_script {
    strings:
        $a = "#!/usr/bin/env bash"
        $b = "/Contents/MacOS/"
        $c1 = "--remote-debugging-port"
        $c2 = "--start-debugger-server"

    condition:
        $a at 0 and $b and any of ($c*) and filesize < 200
}

rule macos_dubrobber_launchagent_a
{
    strings:
        $ = { 18 2E 73 79 73 6F 65 78 65 63 54 45 58 54 FF FF 80 }
        $ = { 00 63 00 75 00 72 00 6C }
        $ = { 00 20 00 3E 00 20 00 2F 00 64 00 65 00 76 00 2F 00 6E 00 75 00 6C 00 6C 00 20 00 32 00 3E 00 26 00 31 }
        $ = { 00 27 00 20 00 68 00 74 00 74 00 70 00 73 00 3A 00 2F 00 2F }
        $ = { 00 6D 00 6B 00 64 00 69 00 72 00 20 00 2D 00 70 00 20 }
        $ = { 00 04 5F 73 74 72 00 }

    condition:
        _osa and all of them and filesize < 100KB
}

rule macos_dubrobber_launchagent_b
{
    strings:
        $ = { 18 2E 73 79 73 6F 65 78 65 63 54 45 58 54 FF FF 80 }
        $ = { 00 6F 00 73 00 61 00 73 00 63 00 72 00 69 00 70 00 74 }
        $ = { 00 2F 00 43 00 6F 00 6E 00 74 00 65 00 6E 00 74 00 73 00 2F 00 52 00 65 00 73 00 6F 00 75 00 72 00 63 00 65 00 73 00 2F 00 53 00 63 00 72 00 69 00 70 00 74 00 73 00 2F }

    condition:
        _osa and all of them and filesize < 100KB
}

rule macos_dubrobber_open {
    strings:
        $ = { 00 2F62696E2F62617368 00 2D63 00 }
        $ = { 00 77616974 00 }
        $ = "ps aux | grep"
        $ = "/Contents/MacOS/applet"
        $ = "2>&1 &>/dev/null"

    condition:
        _macho and all of them and filesize < 500KB
}

rule macos_dubrobber_payload
{
    strings:
        $a1 = { 00 2F 00 63 00 6F 00 6D 00 2E 00 70 00 68 00 70 }
        $a2 = { 00 2F 00 6C 00 6F 00 67 00 2E 00 70 00 68 00 70 }
        $b1 = { 18 2E 73 79 73 6F 65 78 65 63 54 45 58 54 FF FF 80 }
        $b2 = { 00 63 00 75 00 72 00 6C }
        $c1 = { 08 75 73 65 72 6E 61 6D 65 00 08 75 73 65 72 4E 61 6D 65 }
        $c2 = { 07 64 66 6F 6C 64 65 72 00 07 64 46 6F 6C 64 65 72 }
        $c3 = { 0A 6D 6F 64 75 6C 65 6E 61 6D 65 00 0A 6D 6F 64 75 6C 65 4E 61 6D 65 }
        $c4 = { 07 6D 6F 64 6E 61 6D 65 00 07 6D 6F 64 4E 61 6D 65 }

    condition:
        _osa and filesize < 100KB and any of ($a*) and all of ($b*) and any of ($c*)
}

rule macos_dubrobber_payload_log
{
    strings:
        $ = { 18 2E 73 79 73 6F 65 78 65 63 54 45 58 54 FF FF 80 }
        $ = { 00 63 00 75 00 72 00 6C 00 }
        $ = { 00 2D 00 2D 00 63 00 6F 00 6E 00 6E 00 65 00 63 00 74 00 2D 00 74 00 69 00 6D 00 65 00 6F 00 75 00 74 00 }
        $ = { 00 58 00 2D 00 55 00 73 00 }
        $ = { 00 58 00 2D 00 4D 00 6F 00 64 00 }
        $ = { 00 2F 00 6C 00 6F 00 67 00 2E 00 70 00 68 00 70 }

    condition:
        _osa and all of them and filesize < 100KB
}

rule macos_dubrobber_payload_safari {
    strings:
        $ = { 00 70 00 79 00 74 00 68 00 6F 00 6E }
        $ = { 00 2F 00 43 00 6F 00 6E 00 74 00 65 00 6E 00 74 00 73 00 2F 00 4D 00 61 00 63 00 4F 00 53 00 2F }
        $ = { 00 3E 00 20 00 2F 00 64 00 65 00 76 00 2F 00 6E 00 75 00 6C 00 6C 00 20 00 32 00 3E 00 26 00 31 00 20 00 26 }
        $ = { 18 2E 73 79 73 6F 65 78 65 63 54 45 58 54 FF FF 80 }

    condition:
        _osa and all of them and filesize < 10KB
}

rule macos_dubrobber_xcode_project {
    strings:
        $a = "// !$*UTF8*$!"
        $b1 = /162E3FD122D63A22006D90..|167012E12301506800C38AA3|3F708E50247A0EB6004066FD|1D60589F0D05DD5A006BFC54|1D3623260D0F684500981D51|.{18}(AAC43A|6D902C|FFA81D|6A102C|6D904C|530871)/ nocase
        $b2 = "6375726c" nocase
        $b3 = "xxd" nocase

    condition:
        $a at 0 and all of ($b*) and filesize < 10MB
}
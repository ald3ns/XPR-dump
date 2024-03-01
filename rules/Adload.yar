rule adload_a_mrt {
    strings:
        $a = "@_inflateInit2_\x00"
        $b = "_uuid_unparse\x00"
        $c = "_IOServiceGetMatchingService\x00"
        $d = "regex_error"
        $e = "IOMACAddress"
        $f = "IOPlatformSerialNumber"
        $g = "IOEthernetInterface"
    condition:
        all of them and filesize > 300KB and filesize < 15MB
}



rule adload_b_mrt {
    strings:
        $a = "_uuid_generate_random\x00"
        $b = "_system\x00"
        $c = "_syslog\x00"
        $d = "_SecKeyGenerateSymmetric\x00"
        $e = "application/x-www-form-urlencoded"
        $f = "berContents"
        $g = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $i = "BerTaggedData"
        $j = "getSystemVer"
    condition:
        all of them and filesize < 500KB
}



rule adload_c_mrt {
    strings:
            $a = "main.copyFile"
            $b = "main.createPlist"
            $c = "syscall.Recvmsg"
            $d = "syscall.SendmsgN"
            $e = "_sysctl"
            $f = "_ioctl"
            $g = "_execve"
            $h = "_getuid"
            $i = "_recvmsg"
            $j = "_sendmsg"
            $k = "_getgrgid_"
            $l = "_getgrnam_r"
            $m = "_getpwnam_"
            $n = "_getpwuid_r"
            $o = "can't scan type: chrome-extension_corrupt"
            $p = "ExtensionInstallForcelist"
            $q = "cfprefsd"
            $r = "killallpanic"
    condition:
        all of them and filesize < 5MB
}



rule adload_d_mrt {
    strings:
            $a = "net.isDomainName"
            $b = "net.absDomainName"
            $c = "_ioctl"
            $d = "_getnameinfo"
            $e = "_getaddrinfo"
            $f = "_getattrlist"
            $g = "net.equalASCIIName"
            $h = "github.com/denisbrodbeck/machineid"
            $i = "ioreglstatmkdirmonthpanic"
            $j = "runtime.panicSliceB"
            $k = "_getnameinfo"
            $l = "cpuid"
            $m = "url.UserPassword"
            $n = "127.0.0.1:53"
            $o = "syscall.Getsockname"
            $p = "main.DownloadURL"
            $q = "/etc/hosts"
            $r = "/Library/LaunchDaemons/%s.plist"
            $s = "/tmp0x%x"
    condition:
        all of them and filesize < 10MB
}



rule adload_e_mrt {
    strings:
            $a = "_uuid_generate_random"
            $b = "_uuid_unparse"
            $c = "_sysctl"
            $d = "_syslog"
            $e = "_getxattr"
            $f = "_getgrgid"
            $g = "_getpwuid"
            $h = "_SecTransformExecute"
            $i = "_IOServiceMatching"
            $j = "_IOServiceGetMatchingServices"
            $k = "BerTagged"
            $l = "berContent"
            $m = "berLengthBytes"
            $n = "IOPlatformUUID"
            $o = "IOEthernetInterface"
            $p = "IOPlatformSerialNumber"

    condition:
        all of them and filesize < 10MB
}



    rule macos_adload_gardna_c
    {
        strings:
            $x1 = "/bin/bash"
            $x2 = "/bin/cat"
            $x3 = "_swift"
            $x4 = "guardian"
        condition:
            filesize < 100KB and all of them
    }



    rule macos_adload_daemon_obfuscation
    {
        strings:
            $symbolA = "_CFHTTPMessageCreateRequest"
            $symbolB = "_CFHTTPMessageSetHeaderFieldValue"
            $symbolC = "_IOServiceGetMatchingService"
            $symbolD = "inflateInit2"
            $symbolE = "basic_string"

            $codeA = { 8a 44 19 ff 8b 0c 19 44 01 e9 28 c8 88 45 d7 48 8b 4d a8 48 3b 4d b0 }
            $codeB = { 8a 51 ff
                        8a 18
                        88 59 ff
                        88 10
                        48 ff c8
                        48 39 c1
                        48 8d 49 01
                        72 ea }

        condition:
            (#codeA + #codeB) > 150 and all of ($symbol*)
    }



rule adload_a_mrt {
    strings:
        $a = "@_inflateInit2_\x00"
        $b = "_uuid_unparse\x00"
        $c = "_IOServiceGetMatchingService\x00"
        $d = "regex_error"
        $e = "IOMACAddress"
        $f = "IOPlatformSerialNumber"
        $g = "IOEthernetInterface"
    condition:
        all of them and filesize > 300KB and filesize < 15MB
}

rule adload_b_mrt {
    strings:
        $a = "_uuid_generate_random\x00"
        $b = "_system\x00"
        $c = "_syslog\x00"
        $d = "_SecKeyGenerateSymmetric\x00"
        $e = "application/x-www-form-urlencoded"
        $f = "berContents"
        $g = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $i = "BerTaggedData"
        $j = "getSystemVer"
    condition:
        all of them and filesize < 500KB
}

rule adload_c_mrt {
    strings:
            $a = "main.copyFile"
            $b = "main.createPlist"
            $c = "syscall.Recvmsg"
            $d = "syscall.SendmsgN"
            $e = "_sysctl"
            $f = "_ioctl"
            $g = "_execve"
            $h = "_getuid"
            $i = "_recvmsg"
            $j = "_sendmsg"
            $k = "_getgrgid_"
            $l = "_getgrnam_r"
            $m = "_getpwnam_"
            $n = "_getpwuid_r"
            $o = "can't scan type: chrome-extension_corrupt"
            $p = "ExtensionInstallForcelist"
            $q = "cfprefsd"
            $r = "killallpanic"
    condition:
        all of them and filesize < 5MB
}

rule adload_d_mrt {
    strings:
            $a = "net.isDomainName"
            $b = "net.absDomainName"
            $c = "_ioctl"
            $d = "_getnameinfo"
            $e = "_getaddrinfo"
            $f = "_getattrlist"
            $g = "net.equalASCIIName"
            $h = "github.com/denisbrodbeck/machineid"
            $i = "ioreglstatmkdirmonthpanic"
            $j = "runtime.panicSliceB"
            $k = "_getnameinfo"
            $l = "cpuid"
            $m = "url.UserPassword"
            $n = "127.0.0.1:53"
            $o = "syscall.Getsockname"
            $p = "main.DownloadURL"
            $q = "/etc/hosts"
            $r = "/Library/LaunchDaemons/%s.plist"
            $s = "/tmp0x%x"
    condition:
        all of them and filesize < 5MB
}

rule adload_e_mrt {
    strings:
            $a = "_uuid_generate_random"
            $b = "_uuid_unparse"
            $c = "_sysctl"
            $d = "_syslog"
            $e = "_getxattr"
            $f = "_getgrgid"
            $g = "_getpwuid"
            $h = "_SecTransformExecute"
            $i = "_IOServiceMatching"
            $j = "_IOServiceGetMatchingServices"
            $k = "BerTagged"
            $l = "berContent"
            $m = "berLengthBytes"
            $n = "IOPlatformUUID"
            $o = "IOEthernetInterface"
            $p = "IOPlatformSerialNumber"
    condition:
        all of them and filesize < 10MB
}

rule hunt_macos_adload_url_patterns {
    strings:
        $x1 = { 68 74 74 70 3a 2f 2f 6d 2e [1-25] 2e 63 6f 6d 2f 67 2f 75 70 3f 6c 66 3d }
        $x2 = { 68 74 74 70 3a 2f 2f 6d 2e [1-25] 2e 63 6f 6d 2f 6b 74 6c 2f 75 62 61 3f 72 61 6c 3d }
        $x3 = ".com/g/up?lf=" wide
        $x4 = ".com/ktl/uba?ral=" wide
    condition:
        any of them
}

rule macos_adload_kotlin_agent
{
    strings:
        $x1 = "ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformUUID/ { split($0, line, \"\\\"\"); printf(\"%s\", line[4]); }'" wide
        $x2 = "_kfun:#main()"
    condition:
        all of them
}

rule macos_adload_gardna_c
{
    strings:
        $x1 = "/bin/bash"
        $x2 = "/bin/cat"
        $x3 = "_swift"
        $x4 = "guardian"
    condition:
        filesize < 100KB and all of them
}

rule hunt_macos_adload_gardna
{
    strings:
        $swift = "libswift"
        $x1 = "guardian"
        $x2 = "getHostUuid"
        $x3 = "createProcess"
        $x4 = "runTask"
        $x5 = "makeRequest"
        $x6 = "Utils.swift"
        $x7 = "/bin/bash"
        $x8 = "/bin/cat"
        $x9 = "Error:\n"
        $x10 = "error creating process"
        $x11 = "_gethostuuid"
    condition:
        filesize < 100KB and $swift and (2 of ($x*)) and not macos_adload_gardna_c
}

rule macos_adload_daemon_obfuscation
{
    strings:
        $symbolA = "_CFHTTPMessageCreateRequest"
        $symbolB = "_CFHTTPMessageSetHeaderFieldValue"
        $symbolC = "_IOServiceGetMatchingService"
        $symbolD = "inflateInit2"
        $symbolE = "basic_string"

        $codeA = { 8a 44 19 ff 8b 0c 19 44 01 e9 28 c8 88 45 d7 48 8b 4d a8 48 3b 4d b0 }
        $codeB = { 8a 51 ff
                    8a 18
                    88 59 ff
                    88 10
                    48 ff c8
                    48 39 c1
                    48 8d 49 01
                    72 ea }

    condition:
        (#codeA + #codeB) > 150 and all of ($symbol*)
}

rule adload_search_agent_qls {
    strings:
        $code = {
            b8 ?? ?? ?? ?? 49 89 45
            28 49 83 65 50 00 49 83
            65 48 00 49 83 65 40 00
            49 83 65 38 00 49 83 65
            30 00 49 89 45 58 49 83
            a5 80 00 00 00 00 49 83
            65 78 00 49 83 65 70 00
            49 83 65 68 00 49 83 65
            60 00 b9 ?? ?? ?? ??
        }
        // "raiseUnimplemented"
        $s_unique = { 72 61 69 73 65 55 6e 69 6d 70 6c 65 6d 65 6e 74 65 64 }

    condition:
        all of them and filesize < 500KB
}

rule adload_search_daemon_qls {
    strings:
        $code = {
            b9 ?? ?? ?? ?? 49 89 4d
            28 49 89 45 50 49 89 45
            48 49 89 45 40 49 89 45
            38 49 89 45 30 49 89 4d
            58 49 89 85 80 00 00 00
            49 89 45 78 49 89 45 70
            49 89 45 68 49 89 45 60
            ba ?? ?? ?? ??
        }
        // "raiseUnimplemented"
        $s_unique = { 72 61 69 73 65 55 6e 69 6d 70 6c 65 6d 65 6e 74 65 64 }

    condition:
        filesize < 2MB and all of them
}

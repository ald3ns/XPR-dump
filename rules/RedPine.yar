rule macos_redpine_implant {
    strings:
        $classA = "CRConfig"
        $classD = "CRPwrInfo"
        $classE = "CRGetFile"
        $classF = "CRXDump"
    condition:
        all of them
}
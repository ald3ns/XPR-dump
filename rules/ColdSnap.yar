private rule mach_magic
{
    condition:
        uint32(0) == 0xfeedface
        or uint32(0) == 0xcefaedfe
}

private rule mach64_magic
{
    condition:
        uint32(0) == 0xfeedfacf
        or uint32(0) == 0xcffaedfe
}

private rule fat_mach_magic
{
    condition:
        uint32(0) == 0xcafebabe
        or uint32(0) == 0xbebafeca
}

private rule fat_mach64_magic
{
    condition:
        uint32(0) == 0xcafebabf
        or uint32(0) == 0xbfbafeca
}

private rule _fat
{
    condition:
        // file-94/file/magic/Magdir/cafebabe:
        // 0    belong      0xcafebabe
        // >4   ubelong     >30     compiled Java class data,
        // >4   belong      1       Mach-O universal binary with 1 architecture:
        // >4   ubelong     >1
        // >>4  ubelong     <25     Mach-O universal binary with %d architectures:
        (fat_mach_magic or fat_mach64_magic) and uint32be(4) >= 1 and uint32be(4) < 25
}

private rule _macho
{
    condition:
        mach_magic or mach64_magic or _fat
}

rule macos_coldsnap_c {
    strings:
       $user_agent = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36"
       $configuration_path = "%s/Library/WebKit/xpdf.conf"
       $system_version_check = "/System/Library/CoreServices/SystemVersion.plist"
       $fake_content_disposition = {
        2e 70 6e 67 22 0d 0a 43
        6f 6e 74 65 6e 74 2d 54
        79 70 65 3a 20 61 70 70
        6c 69 63 61 74 69 6f 6e
        2f 6f 63 74 65 74 2d 73
        74 72 65 61 6d 0d 0a 0d
        0a
       }
       $encryption_routine = "8A5Stream"
    condition:
        _macho and 2 of them
}

rule macos_coldsnap_c_xor_config {
    strings:
        $xor_instructions = { 80 34 ?? 5e 4? ff c1 4? 81 f9 2e 05 00 00 75 ??  }
    condition:
        all of them
}

rule macos_coldsnap_c_symbols {
    strings:
        $ = "_m_ComInfo"
        $ = "_m_Config"
        $ = "_m_ConnectReason"
        $ = "_m_CurrentStatus"
        $ = "_m_MsgStackCS"
        $ = "_m_MsgStackHead"
        $ = "_m_MsgStackIterBegin"
        $ = "_m_MsgStackIterEnd"
        $ = "_m_ProxyIndex"
        $ = "_m_ProxyUrl"
        $ = "_m_Session"
        $ = "__isPlatformOrVariantPlatformVersionAtLeast"
        $ = "__Z10msg_systemP11_MSG_STRUCT"
        $ = "__Z11get_os_infoP15_COMINFO_STRUCT"
        $ = "__Z12custom_sleepj"
        $ = "__Z12get_com_infoP15_COMINFO_STRUCT"
        $ = "__Z12msg_keep_conP11_MSG_STRUCT"
        $ = "__Z12msg_set_pathP11_MSG_STRUCT"
        $ = "__Z13get_file_timePcS_"
        $ = "__Z13msg_hibernateP11_MSG_STRUCTa"
        $ = "__Z14msg_secure_delP11_MSG_STRUCT"
        $ = "__Z15get_internal_ipP15_COMINFO_STRUCT"
        $ = "__Z15msg_read_configP11_MSG_STRUCT"
        $ = "__Z15reset_msg_stackv"
        $ = "__Z16connect_to_proxyP11_MSG_STRUCT"
        $ = "__Z16msg_write_configP11_MSG_STRUCT"
        $ = "__Z22generate_random_stringm"
        $ = "__Z6msg_upP11_MSG_STRUCT"
        $ = "__Z7msg_cmdP11_MSG_STRUCT"
        $ = "__Z7msg_dirP11_MSG_STRUCT"
        $ = "__Z7msg_runP11_MSG_STRUCT"
        $ = "__Z7pop_msgP11_MSG_STRUCT"
        $ = "__Z8msg_downP11_MSG_STRUCT"
        $ = "__Z8msg_exitP11_MSG_STRUCT"
        $ = "__Z8msg_testP11_MSG_STRUCT"
        $ = "__Z8push_msgP11_MSG_STRUCT"
        $ = "__Z9msg_sleepP11_MSG_STRUCTa"
        $ = "__ZN11TransCenter13m_LastMsgTimeE"
        $ = "__ZN11TransCenter18recv_at_first_connEP11_MSG_STRUCTP20_PROXY_NOTIFY_STRUCT"
        $ = "__ZN11TransCenter8recv_msgEP11_MSG_STRUCTja"
        $ = "__ZN11TransCenter8send_msgEjjPhjj"
        $ = "__ZN8A5Stream12GetKeyStreamEv"
        $ = "__ZN8A5Stream13CalcThresholdEv"
        $ = "__ZN9WebStream11set_payloadEPhj"
        $ = "__ZN9WebStream4postEPhPj"
        $ = "__ZN9WebStream9make_bodyEPhPm"
    condition:
        _macho and 4 of them
}

rule macos_coldsnap_config {
    strings:
        $beacon_url = "http"
    condition:
        $beacon_url at 0
}

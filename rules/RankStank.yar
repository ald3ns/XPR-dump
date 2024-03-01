rule macos_rankstank
{
    strings:
        $injected_func = "_run_avcodec"
        $xor_decrypt = { 80 b4 04 ?? ?? 00 00 7a }
        $stringA = "%s/.main_storage"
        $stringB = ".session-lock"
        $stringC = "%s/UpdateAgent"
    condition:
        2 of them
}
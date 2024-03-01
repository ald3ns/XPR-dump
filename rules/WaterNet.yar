private rule Macho
{
    meta:
        description = "private rule to match Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca

}
rule macos_waternet
{
    strings:
        $stringA = "connectToProxyManager"
        $stringB = "connectToDestination"
        $stringC = "heartbeatSender"
        $stringD = "connectToCnc"
        $stringE = "proxit.com/peer"
        $stringF = "_client.com/utils/hostinfo."
        $stringG = "proxit_traffic"
        $stringH = /config.Build[A-Za-z]{3}Address/

    condition:
        Macho and 2 of them
}

rule macos_waternet_b
{
    strings:
        $stringA = "cnc.HeartbeatRequest"
        $stringB = "TrafficZsetName"
        $stringC = "proxit_traffic"
        $stringD = "_client/config.ProxyManagerTLS"
        $stringE = "github.com/wille/osutil.kernelVersion"

    condition:
        Macho and 2 of them
}
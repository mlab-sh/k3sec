rule cryptominer_indicators : miner
{
    meta:
        description = "Cryptocurrency miners (XMRig and its forks, cpuminer, stratum clients)"
        author = "k3sec"
        severity = "critical"
    strings:
        $stratum_tcp = "stratum+tcp://"
        $stratum_ssl = "stratum+ssl://"
        $donate      = "--donate-level"
        $xmrig       = "XMRig" nocase
        $randomx     = "RandomX"
        $cryptonight = "cryptonight" nocase
        $pool_pass   = "\"pass\": \"x\""
    condition:
        any of ($stratum_*) or 2 of them
}

rule meterpreter_payload : malware c2
{
    meta:
        description = "Strings associated with Metasploit Meterpreter payloads"
        author = "k3sec"
        severity = "critical"
    strings:
        $s1 = "metsrv" nocase
        $s2 = "meterpreter" nocase
        $s3 = "stdapi_"
        $s4 = "core_channel_open"
    condition:
        any of them
}

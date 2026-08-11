rule k3sec_test_marker : test
{
    meta:
        description = "k3sec self-test marker, proves the exec/file scan pipeline end to end"
        author = "k3sec"
        severity = "high"
    strings:
        $marker = "K3SEC_YARA_TEST"
    condition:
        $marker
}

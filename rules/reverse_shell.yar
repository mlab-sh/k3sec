rule reverse_shell_indicators : shell reverse_shell
{
    meta:
        description = "Common interactive/reverse-shell primitives (bash, python pty, nc)"
        author = "k3sec"
        severity = "critical"
    strings:
        $bash_i    = "bash -i"
        $dev_tcp   = "/dev/tcp/"
        $py_pty    = "pty.spawn"
        $py_socket = "import socket"
        $nc_e      = "nc -e"
        $mkfifo    = "mkfifo /tmp/"
    condition:
        any of them
}

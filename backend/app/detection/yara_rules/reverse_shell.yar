/*
 * Matches against the `message` field of normalized events, not files —
 * a deliberate scope decision (see Phase 4 notes): YARA's classic use case
 * is scanning file/binary content, but this project doesn't collect file
 * artifacts yet. String/pattern matching against logged command text is a
 * legitimate, real technique in its own right — some EDR pipelines use
 * YARA this way specifically because Sigma's field-based matching can't
 * express "does this string look like a known malicious command", only
 * "does this field equal this value".
 */

rule Reverse_Shell_Command_Pattern
{
    meta:
        description = "Detects common reverse shell command patterns in logged command text"
        mitre_technique = "T1059"
        severity = "high"

    strings:
        $bash_tcp = "/dev/tcp/" nocase
        $nc_exec = "nc -e" nocase
        $nc_exec_alt = "nc.exe -e" nocase
        $python_pty = "pty.spawn" nocase
        $powershell_encoded = "-EncodedCommand" nocase

    condition:
        any of them
}

/*
 * NXS Base Signatures — bundled with NXS, no network required.
 *
 * Covers common PHP/ASP webshells, dropper patterns, and malware indicators
 * found on shared Linux/cPanel hosting. Rules are intentionally conservative
 * (high-confidence patterns only) to minimise false positives.
 *
 * License: MIT  |  Source: github.com/chrismfz/nxs
 */

// ─── Test ─────────────────────────────────────────────────────────────────────

rule EICAR_Test_File {
    meta:
        description = "EICAR antivirus test file"
        severity    = "info"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

// ─── PHP webshells ────────────────────────────────────────────────────────────

rule PHP_Webshell_Eval_Base64 {
    meta:
        description = "PHP webshell: eval(base64_decode(...))"
        severity    = "high"
    strings:
        $a = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $b = /eval\s*\(\s*str_rot13\s*\(\s*base64_decode/ nocase
    condition:
        any of them
}

rule PHP_Webshell_Eval_GzInflate {
    meta:
        description = "PHP webshell: eval(gzinflate/gzdecode chain)"
        severity    = "high"
    strings:
        $a = /eval\s*\(\s*gzinflate\s*\(/ nocase
        $b = /eval\s*\(\s*gzdecode\s*\(/ nocase
        $c = /eval\s*\(\s*gzuncompress\s*\(/ nocase
    condition:
        any of them
}

rule PHP_Webshell_PassThru_Input {
    meta:
        description = "PHP webshell: system/passthru/exec from HTTP input"
        severity    = "critical"
    strings:
        $cmd1 = /passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $cmd2 = /system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $cmd3 = /exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $cmd4 = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $cmd5 = /popen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        any of them
}

rule PHP_Webshell_Assert_Input {
    meta:
        description = "PHP webshell: assert() with HTTP input"
        severity    = "critical"
    strings:
        $a = /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /assert\s*\(\s*base64_decode\s*\(/ nocase
        $c = /assert\s*\(\s*str_rot13/ nocase
    condition:
        any of them
}

rule PHP_Webshell_Preg_Replace_e {
    meta:
        description = "PHP webshell: preg_replace with /e modifier for code execution"
        severity    = "high"
    strings:
        $a = /preg_replace\s*\(\s*['"].*\/e['"]/ nocase
    condition:
        $a
}

rule PHP_Webshell_Create_Function {
    meta:
        description = "PHP webshell: create_function for dynamic code execution"
        severity    = "high"
    strings:
        $a = /create_function\s*\(\s*['"][^'"]*['"]\s*,\s*\$/ nocase
        $b = /create_function\s*\(\s*['"][^'"]*['"]\s*,\s*base64_decode/ nocase
    condition:
        any of them
}

rule PHP_Webshell_Generic_Obfuscated {
    meta:
        description = "PHP webshell: heavily obfuscated execution chain"
        severity    = "high"
    strings:
        $chain1 = /base64_decode\s*\(\s*str_rot13/ nocase
        $chain2 = /str_rot13\s*\(\s*base64_decode/ nocase
        $chain3 = /gzinflate\s*\(\s*base64_decode/ nocase
        $chain4 = /base64_decode\s*\(\s*gzdeflate/ nocase
        $chain5 = /gzdecode\s*\(\s*base64_decode/ nocase
        $chain6 = /gzuncompress\s*\(\s*base64_decode/ nocase
        $eval   = /eval\s*\(/ nocase
    condition:
        $eval and any of ($chain*)
}

rule PHP_Webshell_FilesMan {
    meta:
        description = "PHP webshell: FilesMan / B374K / c99 / r57 marker strings"
        severity    = "high"
    strings:
        $s1 = "FilesMan" fullword
        $s2 = "b374k"    fullword nocase
        $s3 = "c99shell"
        $s4 = "r57shell"
        $s5 = "wso shell" nocase
        $s6 = "WSO 2."
        $s7 = "indoXploit" nocase
        $s8 = "b374k shell" nocase
    condition:
        any of them
}

rule PHP_Webshell_Terminal_Emulator {
    meta:
        description = "PHP webshell: browser-based terminal / file manager UI"
        severity    = "high"
    strings:
        $ui1 = "uname -a" fullword
        $ui2 = "proc/version"
        $ui3 = "cmd_history"
        $php  = "<?php"
        $sh   = /\$_(GET|POST|REQUEST)\s*\[.*(cmd|command|exec|run|shell)/i
    condition:
        $php and ($sh or (2 of ($ui*)))
}

// ─── Dropper / loader patterns ────────────────────────────────────────────────

rule PHP_Dropper_Write_To_File {
    meta:
        description = "PHP dropper writing decoded payload to disk"
        severity    = "high"
    strings:
        $fwrite  = "fwrite"
        $fputs   = "fputs"
        $b64     = "base64_decode"
        $gzip    = "gzinflate"
        $php     = "<?php"
    condition:
        $php and $b64 and ($fwrite or $fputs) and $gzip
}

rule PHP_Dropper_Remote_Fetch {
    meta:
        description = "PHP dropper fetching remote payload via HTTP"
        severity    = "high"
    strings:
        $curl1   = "curl_exec"
        $curl2   = "file_get_contents"
        $curl3   = "fsockopen"
        $write1  = "file_put_contents"
        $write2  = "fwrite"
        $exec1   = "eval"
        $exec2   = "system"
        $php     = "<?php"
    condition:
        $php and (1 of ($curl*)) and (1 of ($write*)) and (1 of ($exec*))
}

rule PHP_Dropper_Write_Execute_Delete {
    meta:
        description = "PHP dropper: write POST payload to temp file, include, then unlink (in-memory dropper)"
        severity    = "critical"
    strings:
        $write1  = "file_put_contents"
        $write2  = "fwrite"
        $incl1   = "include_once"
        $incl2   = "include("
        $incl3   = "include ("
        $del     = "unlink"
        $php     = "<?php"
    condition:
        $php and (1 of ($write*)) and (1 of ($incl*)) and $del
}

rule PHP_Dropper_TempDir_Selection {
    meta:
        description = "PHP dropper: selecting writable temp dir (shm/tmp) for payload drop"
        severity    = "critical"
    strings:
        $shm     = "/dev/shm"
        $tmp1    = "/var/tmp"
        $tmp2    = "/tmp"
        $getcwd  = /[Gg]et[Cc]wd\s*\(\s*\)/
        $write1  = "file_put_contents"
        $write2  = "fwrite"
        $del     = "unlink"
        $php     = "<?php"
    condition:
        $php and (1 of ($write*)) and $del and $getcwd and (1 of ($shm, $tmp1, $tmp2))
}

rule PHP_Dropper_POST_Decode_Drop {
    meta:
        description = "PHP dropper: decodes POST data (hex2bin/XOR/base64) then writes to file and includes"
        severity    = "critical"
    strings:
        $decode1 = "hex2bin"
        $decode2 = /base64_decode\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/
        $decode3 = /str_rot13\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/
        $write1  = "file_put_contents"
        $write2  = "fwrite"
        $incl1   = "include"
        $del     = "unlink"
        $php     = "<?php"
    condition:
        $php and (1 of ($decode*)) and (1 of ($write*)) and $incl1 and $del
}

rule PHP_Dropper_XOR_Decode_Exec {
    meta:
        description = "PHP dropper: XOR key decode of POST payload for execution"
        severity    = "critical"
    strings:
        $post    = /\$_(POST|GET|REQUEST|COOKIE)\s*\[/
        $xor     = /\^\s*\$[a-zA-Z_]\w{0,20}\[/
        $hex     = "hex2bin"
        $write1  = "file_put_contents"
        $write2  = "fwrite"
        $del     = "unlink"
        $php     = "<?php"
    condition:
        $php and $post and ($hex or $xor) and (1 of ($write*)) and $del
}

// ─── Credential harvester patterns ───────────────────────────────────────────

rule PHP_Credential_Harvester {
    meta:
        description = "PHP credential harvester sending POST data off-site"
        severity    = "high"
    strings:
        $pass1   = /\$_(POST|GET)\s*\[.*(pass|password|passwd|pwd)/i
        $pass2   = "mail("
        $pass3   = "curl_setopt"
        $php     = "<?php"
    condition:
        $php and $pass1 and ($pass2 or $pass3)
}

// ─── Cryptocurrency miner indicators ─────────────────────────────────────────

rule Miner_Stratum_Protocol {
    meta:
        description = "Stratum mining protocol endpoint string"
        severity    = "high"
    strings:
        $a = "stratum+tcp://"
        $b = "stratum+ssl://"
    condition:
        any of them
}

rule Miner_XMRig_Strings {
    meta:
        description = "XMRig or compatible miner embedded strings"
        severity    = "high"
    strings:
        $a = "xmrig"       fullword nocase
        $b = "moneropool"  fullword nocase
        $c = "donate.v2.xmrig.com"
        $d = "--donate-level"
    condition:
        any of them
}

// ─── Linux rootkit / post-exploitation indicators ────────────────────────────

rule Linux_LD_Preload_Injection {
    meta:
        description = "LD_PRELOAD set in environment or script to hook libc"
        severity    = "high"
    strings:
        $a = "LD_PRELOAD="
        $b = /putenv\s*\(\s*["']LD_PRELOAD=/
    condition:
        any of them
}

rule Linux_Reverse_Shell_Bash {
    meta:
        description = "Classic bash /dev/tcp reverse shell one-liner"
        severity    = "critical"
    strings:
        $a = /bash\s+-[il]+\s*>&\s*\/dev\/tcp\//
        $b = "/dev/tcp/"
        $c = "0>&1"
    condition:
        ($a) or ($b and $c)
}

rule Linux_Base64_Decoded_Exec {
    meta:
        description = "Shell script decoding base64 and piping to bash/sh"
        severity    = "high"
    strings:
        $a = /echo\s+[A-Za-z0-9+\/]{40,}={0,2}\s*\|\s*(base64\s+-d|openssl\s+base64)\s*\|\s*(ba)?sh/
        $b = /base64\s+(-d|--decode)\s+.*\|\s*(ba)?sh/
    condition:
        any of them
}

/*
   Visionary built-in rules. A small, conservative starter set: the point of
   the product is imported definitions and channels, these only guarantee a
   sane floor on a fresh install. Scores: >=80 convicts, 40-79 is "suspicious"
   and gets escalated to Defender / reputation / AI.
*/

rule EICAR_Test_File {
    meta:
        description = "EICAR antivirus test file"
        score = 100
    strings:
        $a = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        // The standard requires the string at the very start of a tiny file
        // (27 bytes of prefix precede this part of it).
        $a at 27 and filesize < 256
}

rule Ransomware_Recovery_Sabotage {
    meta:
        description = "Deletes shadow copies / disables recovery (ransomware staging)"
        score = 85
    strings:
        $a = "vssadmin delete shadows" nocase ascii wide
        $b = "wbadmin delete catalog" nocase ascii wide
        $c = "recoveryenabled no" nocase ascii wide
        $d = "shadowcopy delete" nocase ascii wide
        $e = "bootstatuspolicy ignoreallfailures" nocase ascii wide
    condition:
        2 of them
}

rule Defender_Tamper_Script {
    meta:
        description = "Script turns off Microsoft Defender protections"
        score = 70
    strings:
        $a = "DisableRealtimeMonitoring" nocase ascii wide
        $b = "DisableBehaviorMonitoring" nocase ascii wide
        $c = "DisableIOAVProtection" nocase ascii wide
        $d = "Set-MpPreference" nocase ascii wide
        $e = "DisableAntiSpyware" nocase ascii wide
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and ($d and 1 of ($a, $b, $c) or $e and 1 of ($a, $b, $c))
}

rule AMSI_Bypass {
    meta:
        description = "Known AMSI bypass technique"
        score = 85
    strings:
        $a = "amsiInitFailed" nocase ascii wide
        $b = "AmsiScanBuffer" ascii wide
        $c = "System.Management.Automation.AmsiUtils" nocase ascii wide
        $patch = { B8 57 00 07 80 C3 }
    condition:
        filesize < 4MB and ($a or $c or ($b and $patch))
}

rule PowerShell_Download_Cradle {
    meta:
        description = "PowerShell download-and-execute one-liner"
        score = 60
    strings:
        $dl1 = "DownloadString(" nocase ascii wide
        $dl2 = "DownloadFile(" nocase ascii wide
        $dl3 = "DownloadData(" nocase ascii wide
        $iex1 = "IEX" fullword ascii wide
        $iex2 = "Invoke-Expression" nocase ascii wide
        $hid = /-w(indowstyle)?\s+hidden/ nocase
        $enc = /-e(nc(odedcommand)?)?\s+[A-Za-z0-9+\/=]{80,}/ nocase
    condition:
        filesize < 2MB and uint16(0) != 0x5A4D and (1 of ($dl*) and 1 of ($iex*) and ($hid or $enc) or ($hid and $enc))
}

rule Mimikatz_Strings {
    meta:
        description = "Mimikatz credential dumper"
        score = 90
    strings:
        $a = "sekurlsa::logonpasswords" nocase ascii wide
        $b = "gentilkiwi" ascii wide
        $c = "lsadump::sam" nocase ascii wide
        $d = "kerberos::golden" nocase ascii wide
    condition:
        2 of them
}

rule Discord_Token_Stealer {
    meta:
        description = "Collects Discord/browser tokens and posts them to a webhook"
        score = 80
    strings:
        $hook1 = "discord.com/api/webhooks/" ascii wide
        $hook2 = "discordapp.com/api/webhooks/" ascii wide
        $hook3 = "api.telegram.org/bot" ascii wide
        $t1 = "Local Storage" ascii wide
        $t2 = "leveldb" ascii wide
        $t3 = "Login Data" ascii wide
        $t4 = "dQw4w9WgXcQ" ascii wide
        $t5 = "Local State" ascii wide
    condition:
        1 of ($hook*) and 2 of ($t*)
}

rule Game_Account_Stealer {
    meta:
        description = "Reads game-launcher credential files and exfiltrates them"
        score = 70
    strings:
        $s1 = "loginusers.vdf" nocase ascii wide
        $s2 = "ssfn" fullword ascii wide
        $s3 = "\\.minecraft\\launcher_profiles.json" nocase ascii wide
        $s4 = "Riot Games\\Riot Client\\Data" nocase ascii wide
        $s5 = "EpicGamesLauncher\\Saved\\Config" nocase ascii wide
        $x1 = "discord.com/api/webhooks/" ascii wide
        $x2 = "api.telegram.org/bot" ascii wide
        $x3 = "anonfiles" nocase ascii wide
        $x4 = "gofile.io" nocase ascii wide
    condition:
        2 of ($s*) and 1 of ($x*)
}

rule Crypto_Miner {
    meta:
        description = "Cryptocurrency miner configuration"
        score = 65
    strings:
        $a = "stratum+tcp://" ascii wide
        $b = "stratum+ssl://" ascii wide
        $c = "xmrig" nocase ascii wide
        $d = "--donate-level" ascii wide
        $e = "randomx" nocase ascii wide
    condition:
        1 of ($a, $b) and 1 of ($c, $d, $e)
}

rule Package_Install_Script_Dropper {
    meta:
        description = "Package install hook downloads and runs remote code (supply-chain pattern)"
        score = 65
    strings:
        $hook = /"(pre|post)?install"\s*:\s*"[^"]*(curl |wget |powershell|Invoke-WebRequest|node -e|python -c|bash -c)[^"]*"/
        $net = /https?:\/\/|\\x68\\x74\\x74\\x70|base64/
    condition:
        filesize < 1MB and $hook and $net
}

rule Python_Exec_Encoded_Payload {
    meta:
        description = "Python executes a decoded/decompressed blob"
        score = 60
    strings:
        $a = /exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads|bytes\.fromhex|__import__\(['"](base64|zlib|marshal)['"]\))/
        $b = /eval\s*\(\s*compile\s*\(\s*base64/
    condition:
        filesize < 4MB and uint16(0) != 0x5A4D and 1 of them
}

rule Reverse_Shell_OneLiner {
    meta:
        description = "Reverse shell one-liner"
        score = 75
    strings:
        $a = "New-Object System.Net.Sockets.TCPClient(" nocase ascii wide
        $a2 = "GetStream()" nocase ascii wide
        $a3 = "iex" nocase fullword ascii wide
        $b = /bash\s+-i\s+>&\s*\/dev\/tcp\//
        $c = /nc(\.exe)?\s+(-\w+\s+)*-e\s+(cmd|powershell|\/bin\/(ba)?sh)/ nocase
    condition:
        filesize < 2MB and (all of ($a*) or $b or $c)
}

rule LOLBin_Remote_Scriptlet {
    meta:
        description = "Living-off-the-land remote script execution (regsvr32/mshta/rundll32)"
        score = 70
    strings:
        $a = /regsvr32(\.exe)?\s+[^\r\n]{0,60}\/i:https?:\/\// nocase
        $b = /mshta(\.exe)?\s+["']?(https?:\/\/|javascript:|vbscript:)/ nocase
        $c = /rundll32(\.exe)?\s+javascript:/ nocase
        $d = /certutil(\.exe)?\s+[^\r\n]{0,40}-urlcache\s+[^\r\n]{0,40}https?:\/\// nocase
    condition:
        filesize < 2MB and 1 of them
}

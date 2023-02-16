rule onenote_maldoc_hta
{
    meta:
        name = "Malicious OneNote Documents"
        description = "Zero2Automated - January 2023 Z2A Challenge 1"
        techniques = "T1003, T1556.002"
        weaponisation = "OneNote documents containing weaponised HTAs, which call out to domains and pull down multiple files - one to masquerade legitimate activity to the victim, and another to retrieve the second stage of the campaign."
        reference = "https://blog.didierstevens.com/2023/01/22/analyzing-malicious-onenote-documents/"
        report = "https://www.malwareguy.tech/Hunts/jan-2023-zero2automated-challenge-1.html"
        author = "Malware Guy"
        version = "1.1"

    strings:
        $url = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/=]*)/i

        $header1 = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
        $header2 = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC }

        $hta1 = "<HTA:APPLICATION"
        $hta2 = "<script type=\"text/vbscript\">"
        $hta3 = "GetObject"
        $hta4 = ".Get"
        $hta5 = "Win32_ProcessStartup"
        $hta6 = ".SpawnInstance_"
        $hta7 = ".ShowWindow"
        $hta8 = "GetObject"
        $hta9 = "winmgmts:\\\\.\root\\cimv2"
        $hta10 = ".Create"
        $hta11 = "AutoOpen"
        $hta12 = "cmd /c"
        $hta13 = "powershell"
        $hta14 = "Invoke-WebRequest"
        $hta15 = "-Uri"
        $hta16 = "-OutFile $env:"
        $hta17 = ".one"
        $hta18 = "Start-Process -Filepath"
        $hta19 = "CreateObject"
        $hta20 = "WScript.Shell"
        $hta21 = ".Run"    
        $hta22 = "winmgmts:\\\\.\\root\\cimv2"
        $hta23 =  /&H[A-Za-z0-9]+:[A-Za-z0-9]+=[A-Za-z0-9]+/i
        $hta24 = ":Win32_Process"
        $hta25 = "ChrW"
        $hta26 =  /a[0-9]+/i

    condition:
        2 of ($header*) and (any of ($hta*) and $url)
}

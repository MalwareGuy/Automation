
__description__ = 'Automate configuration extraction for AsyncRAT strains utilising embedded batch scripts within OneNote documents'
__author__ = 'Malware Guy (@themalwareguy) - https://www.malwareguy.tech/'
__version__ = '1.0.0'
__date__ = '2023/02/14'

import base64
import dotnetfile
import gzip
from malduck import aes
import malduck
import os
import re
import subprocess
import tempfile

try:
    from onedump import *
except ImportError:
    print("Add onedump.py (https://github.com/DidierStevens/Beta/blob/master/onedump.py) to the same directory as this script!")

class ConfigExtractor:
    def __init__(self):
        pass

    def ProcessOneNoteFile(self, filename: str):
        '''Process OneNote files and retrieve embedded Batch Scripts within the data streams'''
        f = open(filename, "rb")
        data = f.read()

        # https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-onestore/8806fd18-6735-4874-b111-227b83eaac26
        guidHeader_FileDataStoreObject = b'\xE7\x16\xE3\xBD\x65\x26\x11\x45\xA4\xC4\x8D\x4D\x0B\x7A\x9E\xAC'
        format_FileDataStoreObject = '<16sQLQ' # guidHeader cbLength unused reserved

        for position in cEnumeration(FindAll(data, guidHeader_FileDataStoreObject)):
            oStruct = cStruct(data[position.item:])
            nFileDataStoreObject = oStruct.UnpackNamedtuple(format_FileDataStoreObject, 'FileDataStoreObject', 'guidHeader cbLength unused reserved')
            filedata = oStruct.GetBytes(nFileDataStoreObject.cbLength)

            if "@ech" in cMagicValue(filedata).both:
                return filedata.decode('ascii')

    def ReplaceBatchFunctions(self, data):
        BatchScript = data
        BatchScript = BatchScript.replace('\"\r\n', '\n') # Replace \"\r\n with \n
        BatchScript = BatchScript.replace('@echo off',  '')  # Remove basic Batch functionality and replace executable functions with a printed version
        BatchScript = BatchScript.replace('cls',  '')
        BatchScript = BatchScript.replace('exit /b', '')
        BatchScript = re.sub('\%[A-Za-z0-9]{4}\%\"', 'set ', BatchScript) #  Replace all %var%" with set e.g %Kfoc%"rqxyiLaszA=bN.T"
        BatchScript = re.sub('\n\%', r"\necho %", BatchScript) # Append all 'echo ' to all lines beginning with %var% e.g. %TINiUKVbqZ%%
        return BatchScript

    def RunBatchScript(self, data: str):
        '''At this point, the Batch script would only contain code that prints a series of PowerShell commands to the console.'''
        f = open(tempfile.gettempdir() + "\\batch.bat", mode="w+")
        f.write(data)
        output = subprocess.run([(f.name)], capture_output=True, shell=True, text=True).stdout
        f.close()
        os.remove(f.name)
        return output

    def ExtractKeyIVPWSH(self, data: str):
        '''The extracted PowerShell code can then be probed for the AES key and initialisation vector.'''
        lines = data.split(';')
        for line in lines:
            if re.search(".Key", line, re.IGNORECASE):
                key = base64.b64decode(re.search('(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)', line)[0])
            elif re.search(".IV", line, re.IGNORECASE):
                iv = base64.b64decode(re.search('(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)', line)[0])
        return key, iv

    def ObtainInitialPE(self, data: str):
        '''Retrieve the .NET payload situated behind ":: "'''
        BatchScript = data.split("\n")
        for line in BatchScript:
            if ((":: " in line) and (not "set" in line)):
                EncodedFile = line[3:]
                return EncodedFile

    def DecompressAndDecryptNETPE(self, key: bytes, iv: bytes, data: bytes):
        '''Decrypt and decompress PE files'''
        return gzip.decompress(malduck.unpad(aes.cbc.decrypt(key, iv, data)))

    def ExtractKeyIVNET(self, data):
        '''Retrieve the key and initialisation vector from the initial .NET file. Each run through the Base64 strings will check their lengths - 32 bits for the key, 16 bits for the IV'''
        pe = dotnetfile.DotNetPE(data)
        strings = pe.get_user_stream_strings()
        #for s in strings:
            #x = base64.b64decode(s + '==')
            #if len(x) == 32:
                #key = x
            #elif len(x) == 16:
                #iv = x
        return base64.b64decode(strings[2]), base64.b64decode(strings[3])

    def ObtainPayloadFromResources(self, data: bytes):
        '''Retrieve the final payload the resource section of the initial .NET PE file'''
        pe = dotnetfile.DotNetPE(data)

        payloadexe = None
        runpedll = None

        resource_data = pe.get_resources()
        for data in resource_data:
            if data["Name"] == "payload.exe":
                payloadexe = data
                break
            elif data["Name"] == "runpe.dll":
                runpedll = data
                break

        if not payloadexe == None:
            return payloadexe['Data']
        elif not runpedll == None:
            return runpedll['Data']

    def ObtainC2Info(self, data: bytes):
        '''Retrieve the IP address and port from the final payload'''
        pe = dotnetfile.DotNetPE(data)
        strings = pe.get_user_stream_strings()
        c2_regex = '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-9]+'
        for s in strings:
            if re.search(c2_regex, s) !=  None:
                return re.search(c2_regex, s)[0]

def Main():
    cfg_extractor = ConfigExtractor()
    batch_path = input("OneNote file: ")
    batchfile = cfg_extractor.ProcessOneNoteFile(batch_path)

    # Extract PowerShell commands from the Batch stage
    modified_batchfile = cfg_extractor.ReplaceBatchFunctions(batchfile)
    batchfile_output = cfg_extractor.RunBatchScript(modified_batchfile)

    # Extract the key, IV and initial payload from the PowerShell stage
    key, iv = cfg_extractor.ExtractKeyIVPWSH(batchfile_output)
    pe1 = base64.b64decode(cfg_extractor.ObtainInitialPE(modified_batchfile))
    pe1_decrypted = cfg_extractor.DecompressAndDecryptNETPE(key, iv, pe1)

    # Extract the second key, IV and payload from the previous PE file then retrieve the C2 config
    key, iv = cfg_extractor.ExtractKeyIVNET(pe1_decrypted)
    pe2 = cfg_extractor.ObtainPayloadFromResources(pe1_decrypted)
    pe2_decrypted = cfg_extractor.DecompressAndDecryptNETPE(key, iv, pe2)

    print(cfg_extractor.ObtainC2Info(pe2_decrypted))

Main()

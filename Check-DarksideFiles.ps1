param($path,$extension,[switch]$showValid,[switch]$showInvalid,[switch]$recurse,[switch]$showCount)
 
if ($path.length -lt 2 -or !(test-path $path)) {
    write-host ""
    write-host "CyberGuard Technologies - Darkside Ransomware File Checker" -ForegroundColor Cyan
    write-host "=========================================================="
    write-host "Validates whether files encrpyted by the Windows version of Darkside Ransomware will be good candidates for decryption."
    write-host ""
    write-host "Reads the RSA encrypted version of the decryption key from within the file, generates a hashed checksum and validates against checksum stored in file."
    write-host ""
    write-host "If checksum hashes match the file will be a good candidate for a decryption attempt should a valid Darkside decryptor be obtained."
    write-host "If the checksums do not match then the data required to decrypt the file has been lost and the Darkside decyptor will fail to recognise the file as being encrypted."
    write-host ""
    write-host "Usage:"
    write-host "Check-Darkside.ps1"
    write-host "-path        (required) Path to scan e.g d:\data  , place quotes around paths containing spaces"
    write-host "-recurse     (optional) Scan sub folders"
    write-host "-extension   (optional) Darkside file extension added to encrypted files e.g f435bda1, by default all files are scanned."
    write-host "-showvalid   (optional) Show files found with VALID decryption signatures"
    write-host "-showinvalid (optional) Show files found with INVALID decryption signatures"
    write-host "-showcount   (optional) Show summary count of scan results (default if -showvalid or -showinvalid not selected)"
    write-host ""
    write-host "Example:  .\Check-Darkside.ps1 -path d:\data -recurse -extension f435bda1 -showvalid -showinvalid -showcount"
    write-host
    exit 1
}

if ($extension -eq $null -or $extension -eq "") {
    $extension = "*"
}

###################################################################################################################
# Wrapper function for generating CRC32 hash values from byte stream  - credit to https://github.com/FuzzySecurity#
function Get-CRC32 {
<#
.SYNOPSIS
	Simple wrapper for undocumented RtlComputeCrc32 function.

.DESCRIPTION
	Author: Ruben Boonen (@FuzzySec)
	License: BSD 3-Clause
	Required Dependencies: None
	Optional Dependencies: None

.PARAMETER InitialCRC
	Optional initial CRC value to start with. Supply 0 initially.

.PARAMETER Buffer
	Byte array to compute the CRC32 of.

.EXAMPLE
	# Example from string
	C:\PS> $String = [System.Text.Encoding]::ASCII.GetBytes("Testing!")
	C:\PS> Get-CRC32 -Buffer $String
	C:\PS> 2392247274
#>

	param(
		[Parameter(Mandatory = $False)]
		[Int64]$InitialCRC = 0,
		[Parameter(Mandatory = $True)]
		[Byte[]]$Buffer
    )

	Add-Type -TypeDefinition @"
		using System;
		using System.Diagnostics;
		using System.Runtime.InteropServices;
		using System.Security.Principal;
	
		public static class CRC32
		{
			[DllImport("ntdll.dll")]
			public static extern UInt32 RtlComputeCrc32(
				UInt64 InitialCrc,
				Byte[] Buffer,
				Int32 Length);
		}
"@
	
	
	[CRC32]::RtlComputeCrc32($InitialCRC, $Buffer, $Buffer.Length)
}

#####################################################################################

# Initial value for CRC function (0xDEADBEEF)
$initialCRC = 3735928559

# Get list of files to check
if ($recurse) {
    $filesToCheck = Get-ChildItem -Path $path -Filter ("*.$extension") -file -recurse
} else {
    $filesToCheck = Get-ChildItem -Path $path -Filter ("*.$extension") -file
}

$validCount = 0
$invalidCount = 0

foreach ($file in ($filesToCheck | where-object{$_.length -ge 144})) {

       
    $encFile = $file.FullName

    #  Get last 144 bytes of files containing 128 byte RSA encrypted Salsa decryption key and 16 byte hash checksum
    $lastBytes = Get-Content -LiteralPath ("$encFile") -Encoding Byte -tail 144

    $RSAsalsaKey = $lastBytes[0..127]
    $checksumHash = $lastBytes[128..143]
    
    # 1st CRC32 round using initial CRC value of 3735928559 (0xDEADBEEF)
    $CRC32_1 = Get-CRC32 -InitialCRC $initialCRC -Buffer $RSAsalsaKey

    # 2nd CRC32 round using CRC32 from 1st round as initial value, convert to byte array for first 4 bytes of checksum hash
    $CRC32_2 = Get-CRC32 -InitialCRC $CRC32_1 -Buffer $RSAsalsaKey
    $hash_1 = [System.BitConverter]::GetBytes($CRC32_2)

    # 3rd CRC32 round using CRC32 from 2nd round as initial value, convert to byte array for second 4 bytes of checksum hash
    $CRC32_3 = Get-CRC32 -InitialCRC $CRC32_2 -Buffer $RSAsalsaKey
    $hash_2 = [System.BitConverter]::GetBytes($CRC32_3)

    # 4th CRC32 round using CRC32 from 3rd round as initial value, convert to byte array for third 4 bytes of checksum hash
    $CRC32_4 = Get-CRC32 -InitialCRC $CRC32_3 -Buffer $RSAsalsaKey
    $hash_3 = [System.BitConverter]::GetBytes($CRC32_4)

    # 5th CRC32 round using CRC32 from 4th round as initial value, convert to byte array for third 4 bytes of checksum hash
    $CRC32_5 = Get-CRC32 -InitialCRC $CRC32_4 -Buffer $RSAsalsaKey
    $hash_4 = [System.BitConverter]::GetBytes($CRC32_5)

    # join together 16 byte checksun hash and convert to an easy to read hex string
    $calculatedHashBytes = $hash_1 + $hash_2 + $hash_3 + $hash_4
    $calculatedHashHex = [System.BitConverter]::ToString($calculatedHashBytes)

    # Get Salsa key hash stored in file
    $actualHashHex = [System.BitConverter]::ToString($checksumHash)

    # check if calculated hash matches hash stored in file
    if ($calculatedHashHex -eq $actualHashHex) {
        $validCount++
        if ($showValid) {
            write-host "$encFile | Valid decryption signature" -ForegroundColor Green
        }
    } else {
        $invalidCount++
        if ($showInvalid) {
            write-host "$encFile | Invalid decryption signature" -ForegroundColor red
        }
    }
}

# show sumaary count of files scanned
if ($showCount -or (!($showValid) -and !($showInvalid))) {
    write-host "----------------------------------------------------------------"
    write-host "Total files found with VALID decryption signature:    $validCount" -ForegroundColor Yellow
    Write-Host "Total files found with INVALID decryption signature:  $invalidCount" -ForegroundColor Yellow
    write-host "----------------------------------------------------------------"
}

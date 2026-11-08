# Decodes text captured from powershell.exe.
# The Windows resolve diagnostic showed code unit 14915 (hex 3A43), which is the
# ASCII bytes 43 3A ("C:") read as one UTF-16LE unit. That stream is single-byte.
# A BOM or a UTF-16LE stream whose high bytes are zero is still recognized.
function Set-ChildStreamEncoding {
  param($StartInfo)
  $latin1 = [System.Text.Encoding]::GetEncoding(28591)
  $StartInfo.StandardOutputEncoding = $latin1
  $StartInfo.StandardErrorEncoding = $latin1
}

function ConvertFrom-ChildText {
  param([string]$Text)
  if ([string]::IsNullOrEmpty($Text)) { return "" }
  $latin1 = [System.Text.Encoding]::GetEncoding(28591)
  $bytes = $latin1.GetBytes($Text)
  if ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) {
    return [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
  }
  if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) {
    return [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
  }
  $highBytesAreZero = (($bytes.Length -ge 2) -and (($bytes.Length % 2) -eq 0))
  if ($highBytesAreZero) {
    for ($i = 1; $i -lt $bytes.Length; $i += 2) {
      if ($bytes[$i] -ne 0) { $highBytesAreZero = $false; break }
    }
  }
  if ($highBytesAreZero) { return [System.Text.Encoding]::Unicode.GetString($bytes) }
  return $Text
}

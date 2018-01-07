Func _FO_FileSearch($sPath, $sMask = '*', $fInclude = True, $iDepth = 125, $iFull = 1, $iArray = 1, $iTypeMask = 1, $sLocale = 0, $vExcludeFolders = '', $iExcludeDepth = -1)
	Local $vFileList
	If $sMask = '|' Then Return SetError(2, 0, '')
	; If Not StringRegExp($sPath, '(?i)^[a-z]:[^/:*?"<>|]*$') Or StringInStr($sPath, '\\') Then Return SetError(1, 0, '')
	If Not FileExists($sPath) Then Return SetError(1, 0, '')
	If StringRight($sPath, 1) <> '\' Then $sPath &= '\'

	If $vExcludeFolders Then
		$vExcludeFolders = StringSplit($vExcludeFolders, '|')
	Else
		Dim $vExcludeFolders[1] = [0]
	EndIf

	If $sMask = '*' Or $sMask = '' Then
		__FO_FileSearchAll($vFileList, $sPath, $iDepth, $vExcludeFolders, $iExcludeDepth)
	Else
		Switch $iTypeMask
			Case 0
				If StringInStr($sMask, '*') Or StringInStr($sMask, '?') Or StringInStr($sMask, '.') Then
					__FO_GetListMask($sPath, $sMask, $fInclude, $iDepth, $vFileList, $sLocale, $vExcludeFolders, $iExcludeDepth)
				Else
					__FO_FileSearchType($vFileList, $sPath, '|' & $sMask & '|', $fInclude, $iDepth, $vExcludeFolders, $iExcludeDepth)
				EndIf
			Case 1
				__FO_GetListMask($sPath, $sMask, $fInclude, $iDepth, $vFileList, $sLocale, $vExcludeFolders, $iExcludeDepth)
			Case Else
				If StringInStr($sMask, '*') Or StringInStr($sMask, '?') Or StringInStr($sMask, '.') Then Return SetError(2, 0, '')
				__FO_FileSearchType($vFileList, $sPath, '|' & $sMask & '|', $fInclude, $iDepth, $vExcludeFolders, $iExcludeDepth)
		EndSwitch
	EndIf

	If Not $vFileList Then Return SetError(3, 0, '')
	Switch $iFull
		Case 0
			$vFileList = StringRegExpReplace($vFileList, '(?m)^[^\v]{' & StringLen($sPath) & '}', '')
		Case 2
			$vFileList = StringRegExpReplace($vFileList, '(?m)^.*\\', '')
		Case 3
			$vFileList = StringRegExpReplace($vFileList, '(?m)^[^\v]+\\', '')
			$vFileList = StringRegExpReplace($vFileList, '(?m)\.[^./:*?"<>|\\\v]+\r?$', @CR)
	EndSwitch
	$vFileList = StringTrimRight($vFileList, 2)
	Switch $iArray
		Case 1
			$vFileList = StringSplit($vFileList, @CRLF, 1)
		Case 2
			$vFileList = StringSplit($vFileList, @CRLF, 3)
	EndSwitch
	Return $vFileList
EndFunc   ;==>_FO_FileSearch

Func _FO_FolderSearch($sPath, $sMask = '*', $fInclude = True, $iDepth = 0, $iFull = 1, $iArray = 1, $sLocale = 0)
	Local $vFolderList, $aFolderList, $rgex
	If $sMask = '|' Then Return SetError(2, 0, '')
	; If Not StringRegExp($sPath, '(?i)^[a-z]:[^/:*?"<>|]*$') Or StringInStr($sPath, '\\') Then Return SetError(1, 0, '')
	If Not FileExists($sPath) Then Return SetError(1, 0, '')
	If StringRight($sPath, 1) <> '\' Then $sPath &= '\'

	If $sMask = '*' Or $sMask = '' Then
		__FO_FolderSearch($vFolderList, $sPath, $iDepth)
		$vFolderList = StringTrimRight($vFolderList, 2)
	Else
		__FO_FolderSearchMask($vFolderList, $sPath, $iDepth)
		$vFolderList = StringTrimRight($vFolderList, 2)
		$sMask = StringReplace(StringReplace(StringRegExpReplace($sMask, '[][$^.{}()+]', '\\$0'), '?', '.'), '*', '.*?')

		Switch $sLocale
			Case -1
				$rgex = 'i'
			Case 1
			Case 0
				$sLocale = '\x{80}-\x{ffff}'
				ContinueCase
			Case Else
				$rgex = 'i'
				$sMask = __FO_UserLocale($sMask, $sLocale)
		EndSwitch

		If $fInclude Then
			$aFolderList = StringRegExp($vFolderList, '(?m' & $rgex & ')^(.+\|(?:' & $sMask & '))(?:\r|\z)', 3)
			$vFolderList = ''
			For $i = 0 To UBound($aFolderList) - 1
				$vFolderList &= $aFolderList[$i] & @CRLF
			Next
		Else
			$vFolderList = StringRegExpReplace($vFolderList & @CRLF, '(?m' & $rgex & ')^.+\|(' & $sMask & ')\r\n', '')
		EndIf
		$vFolderList = StringReplace(StringTrimRight($vFolderList, 2), '|', '')
	EndIf
	If Not $vFolderList Then Return SetError(3, 0, '')

	If $iFull = 0 Then $vFolderList = StringRegExpReplace($vFolderList, '(?m)^[^\v]{' & StringLen($sPath) & '}', '')

	Switch $iArray
		Case 1
			$vFolderList = StringSplit($vFolderList, @CRLF, 1)
		Case 2
			$vFolderList = StringSplit($vFolderList, @CRLF, 3)
	EndSwitch
	Return $vFolderList
EndFunc   ;==>_FO_FolderSearch

Func __FO_FolderSearchMask(ByRef $sFolderList, $sPath, $iDepth, $iCurD = 0)
	Local $sFile, $s = FileFindFirstFile($sPath & '*')
	If $s = -1 Then Return
	While 1
		$sFile = FileFindNextFile($s)
		If @error Then ExitLoop
		If @extended Then
			If $iCurD < $iDepth Then
				$sFolderList &= $sPath & '|' & $sFile & @CRLF
				__FO_FolderSearchMask($sFolderList, $sPath & $sFile & '\', $iDepth, $iCurD + 1)
			ElseIf $iCurD = $iDepth Then
				$sFolderList &= $sPath & '|' & $sFile & @CRLF
			EndIf
		EndIf
	WEnd
	FileClose($s)
EndFunc   ;==>__FO_FolderSearchMask

Func __FO_FolderSearch(ByRef $sFolderList, $sPath, $iDepth, $iCurD = 0)
	Local $sFile, $s = FileFindFirstFile($sPath & '*')
	If $s = -1 Then Return
	While 1
		$sFile = FileFindNextFile($s)
		If @error Then ExitLoop
		If @extended Then
			If $iCurD < $iDepth Then
				$sFolderList &= $sPath & $sFile & @CRLF
				__FO_FolderSearch($sFolderList, $sPath & $sFile & '\', $iDepth, $iCurD + 1)
			ElseIf $iCurD = $iDepth Then
				$sFolderList &= $sPath & $sFile & @CRLF
			EndIf
		EndIf
	WEnd
	FileClose($s)
EndFunc   ;==>__FO_FolderSearch

Func __FO_FileSearchAll(ByRef $sFileList, $sPath, ByRef $iDepth, ByRef $aExcludeFolders, ByRef $iExcludeDepth, $iCurD = 0)
	Local $sFile, $s = FileFindFirstFile($sPath & '*')
	If $s = -1 Then Return
	While 1
		$sFile = FileFindNextFile($s)
		If @error Then ExitLoop
		If @extended Then
			If $iCurD >= $iDepth Or ($iCurD <= $iExcludeDepth And __ChExcludeFolders($sFile, $aExcludeFolders)) Then ContinueLoop
			__FO_FileSearchAll($sFileList, $sPath & $sFile & '\', $iDepth, $aExcludeFolders, $iExcludeDepth, $iCurD + 1)
		Else
			$sFileList &= $sPath & $sFile & @CRLF
		EndIf
	WEnd
	FileClose($s)
EndFunc   ;==>__FO_FileSearchAll

Func __ChExcludeFolders(ByRef $sFile, ByRef $aExcludeFolders)
	For $i = 1 To $aExcludeFolders[0]
		If $sFile = $aExcludeFolders[$i] Then Return True
	Next
	Return False
EndFunc   ;==>__ChExcludeFolders

Func __FO_GetListMask($sPath, $sMask, $fInclude, $iDepth, ByRef $sFileList, $sLocale, ByRef $aExcludeFolders, ByRef $iExcludeDepth)
	Local $aFileList, $rgex
	__FO_FileSearchMask($sFileList, $sPath, $iDepth, $aExcludeFolders, $iExcludeDepth)
	$sFileList = StringTrimRight($sFileList, 2)
	$sMask = StringReplace(StringReplace(StringRegExpReplace($sMask, '[][$^.{}()+]', '\\$0'), '?', '.'), '*', '.*?')

	Switch $sLocale
		Case -1
			$rgex = 'i'
		Case 1
		Case 0
			$sLocale = '\x{80}-\x{ffff}'
			ContinueCase
		Case Else
			$rgex = 'i'
			$sMask = __FO_UserLocale($sMask, $sLocale)
	EndSwitch

	If $fInclude Then
		$aFileList = StringRegExp($sFileList, '(?m' & $rgex & ')^([^|]+\|(?:' & $sMask & '))(?:\r|\z)', 3)
		$sFileList = ''
		For $i = 0 To UBound($aFileList) - 1
			$sFileList &= $aFileList[$i] & @CRLF
		Next
	Else
		$sFileList = StringRegExpReplace($sFileList & @CRLF, '(?m' & $rgex & ')^[^|]+\|(' & $sMask & ')\r\n', '')
	EndIf
	$sFileList = StringReplace($sFileList, '|', '')
EndFunc   ;==>__FO_GetListMask

Func __FO_FileSearchType(ByRef $sFileList, $sPath, $sMask, ByRef $fInclude, ByRef $iDepth, ByRef $aExcludeFolders, ByRef $iExcludeDepth, $iCurD = 0)
	Local $iPos, $sFile, $s = FileFindFirstFile($sPath & '*')
	If $s = -1 Then Return
	While 1
		$sFile = FileFindNextFile($s)
		If @error Then ExitLoop
		If @extended Then
			If $iCurD >= $iDepth Or ($iCurD <= $iExcludeDepth And __ChExcludeFolders($sFile, $aExcludeFolders)) Then ContinueLoop
			__FO_FileSearchType($sFileList, $sPath & $sFile & '\', $sMask, $fInclude, $iDepth, $aExcludeFolders, $iExcludeDepth, $iCurD + 1)
		Else
			$iPos = StringInStr($sFile, ".", 0, -1)
			If $iPos And StringInStr($sMask, '|' & StringTrimLeft($sFile, $iPos) & '|') = $fInclude Then
				$sFileList &= $sPath & $sFile & @CRLF
			ElseIf Not $iPos And Not $fInclude Then
				$sFileList &= $sPath & $sFile & @CRLF
			EndIf
		EndIf
	WEnd
	FileClose($s)
EndFunc   ;==>__FO_FileSearchType

Func __FO_FileSearchMask(ByRef $sFileList, $sPath, ByRef $iDepth, ByRef $aExcludeFolders, ByRef $iExcludeDepth, $iCurD = 0)
	Local $sFile, $s = FileFindFirstFile($sPath & '*')
	If $s = -1 Then Return
	While 1
		$sFile = FileFindNextFile($s)
		If @error Then ExitLoop
		If @extended Then
			If $iCurD >= $iDepth Or ($iCurD <= $iExcludeDepth And __ChExcludeFolders($sFile, $aExcludeFolders)) Then ContinueLoop
			__FO_FileSearchMask($sFileList, $sPath & $sFile & '\', $iDepth, $aExcludeFolders, $iExcludeDepth, $iCurD + 1)
		Else
			$sFileList &= $sPath & '|' & $sFile & @CRLF
		EndIf
	WEnd
	FileClose($s)
EndFunc   ;==>__FO_FileSearchMask

Func __FO_UserLocale($sMask, $sLocale)
	Local $s, $tmp
	$sLocale = StringRegExpReplace($sMask, '[^' & $sLocale & ']', '')
	$tmp = StringLen($sLocale)
	For $i = 1 To $tmp
		$s = StringMid($sLocale, $i, 1)
		If $s Then
			If StringInStr($sLocale, $s, 0, 2, $i) Then
				$sLocale = $s & StringReplace($sLocale, $s, '')
			EndIf
		Else
			ExitLoop
		EndIf
	Next
	If $sLocale Then
		Local $Upper, $Lower
		$tmp = StringSplit($sLocale, '')
		For $i = 1 To $tmp[0]
			$Upper = StringUpper($tmp[$i])
			$Lower = StringLower($tmp[$i])
			If Not ($Upper == $Lower) Then $sMask = StringReplace($sMask, $tmp[$i], '[' & $Upper & $Lower & ']')
		Next
	EndIf
	Return $sMask
EndFunc   ;==>__FO_UserLocale


;-----------------------------------------------------------------------------------------------------------------------------------------------------

;FROM WINAPI

Global Const $GENERIC_ALL = 0x10000000
Global Const $GENERIC_EXECUTE = 0x20000000
Global Const $GENERIC_WRITE = 0x40000000
Global Const $GENERIC_READ = 0x80000000
Global Const $GENERIC_READWRITE = BitOR($GENERIC_READ, $GENERIC_WRITE)

Global Const $FILE_SHARE_READ = 0x00000001
Global Const $FILE_SHARE_WRITE = 0x00000002
Global Const $FILE_SHARE_DELETE = 0x00000004
Global Const $FILE_SHARE_READWRITE = BitOR($FILE_SHARE_READ, $FILE_SHARE_WRITE)
Global Const $FILE_SHARE_ANY = BitOR($FILE_SHARE_READ, $FILE_SHARE_WRITE, $FILE_SHARE_DELETE)

Global Const $CREATE_NEW = 1
Global Const $CREATE_ALWAYS = 2
Global Const $OPEN_EXISTING = 3
Global Const $OPEN_ALWAYS = 4
Global Const $TRUNCATE_EXISTING = 5

Global Const $FILE_ATTRIBUTE_READONLY = 0x00000001
Global Const $FILE_ATTRIBUTE_HIDDEN = 0x00000002
Global Const $FILE_ATTRIBUTE_SYSTEM = 0x00000004
Global Const $FILE_ATTRIBUTE_DIRECTORY = 0x00000010
Global Const $FILE_ATTRIBUTE_ARCHIVE = 0x00000020
Global Const $FILE_ATTRIBUTE_DEVICE = 0x00000040
Global Const $FILE_ATTRIBUTE_NORMAL = 0x00000080
Global Const $FILE_ATTRIBUTE_TEMPORARY = 0x00000100
Global Const $FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
Global Const $FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
Global Const $FILE_ATTRIBUTE_COMPRESSED = 0x00000800
Global Const $FILE_ATTRIBUTE_OFFLINE = 0x00001000
Global Const $FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000
Global Const $FILE_ATTRIBUTE_ENCRYPTED = 0x00004000
Global Const $INVALID_HANDLE_VALUE = Ptr(-1)
Global Const $STR_ENDISSTART = 0 ; End acts as next start when end = start
Global Const $STR_REGEXPARRAYGLOBALMATCH = 3 ; Return array of global matches.
Global Const $tagSECURITY_ATTRIBUTES = "dword Length;ptr Descriptor;bool InheritHandle"
Global Const $STR_STRIPTRAILING = 2 ; Strip trailing whitespace
Global Const $STR_ENDNOTSTART = 1 ; End does not act as new start when end = start

Func _WinAPI_CreateFile($sFileName, $iCreation, $iAccess = 4, $iShare = 0, $iAttributes = 0, $tSecurity = 0)
	Local $iDA = 0, $iSM = 0, $iCD = 0, $iFA = 0

	If BitAND($iAccess, 1) <> 0 Then $iDA = BitOR($iDA, $GENERIC_EXECUTE)
	If BitAND($iAccess, 2) <> 0 Then $iDA = BitOR($iDA, $GENERIC_READ)
	If BitAND($iAccess, 4) <> 0 Then $iDA = BitOR($iDA, $GENERIC_WRITE)

	If BitAND($iShare, 1) <> 0 Then $iSM = BitOR($iSM, $FILE_SHARE_DELETE)
	If BitAND($iShare, 2) <> 0 Then $iSM = BitOR($iSM, $FILE_SHARE_READ)
	If BitAND($iShare, 4) <> 0 Then $iSM = BitOR($iSM, $FILE_SHARE_WRITE)

	Switch $iCreation
		Case 0
			$iCD = $CREATE_NEW
		Case 1
			$iCD = $CREATE_ALWAYS
		Case 2
			$iCD = $OPEN_EXISTING
		Case 3
			$iCD = $OPEN_ALWAYS
		Case 4
			$iCD = $TRUNCATE_EXISTING
	EndSwitch

	If BitAND($iAttributes, 1) <> 0 Then $iFA = BitOR($iFA, $FILE_ATTRIBUTE_ARCHIVE)
	If BitAND($iAttributes, 2) <> 0 Then $iFA = BitOR($iFA, $FILE_ATTRIBUTE_HIDDEN)
	If BitAND($iAttributes, 4) <> 0 Then $iFA = BitOR($iFA, $FILE_ATTRIBUTE_READONLY)
	If BitAND($iAttributes, 8) <> 0 Then $iFA = BitOR($iFA, $FILE_ATTRIBUTE_SYSTEM)

	Local $aResult = DllCall("kernel32.dll", "handle", "CreateFileW", "wstr", $sFileName, "dword", $iDA, "dword", $iSM, _
			"struct*", $tSecurity, "dword", $iCD, "dword", $iFA, "ptr", 0)
	If @error Or ($aResult[0] = $INVALID_HANDLE_VALUE) Then Return SetError(@error, @extended, 0)

	Return $aResult[0]
EndFunc   ;==>_WinAPI_CreateFile

Func _WinAPI_WriteFile($hFile, $pBuffer, $iToWrite, ByRef $iWritten, $tOverlapped = 0)
	Local $aResult = DllCall("kernel32.dll", "bool", "WriteFile", "handle", $hFile, "struct*", $pBuffer, "dword", $iToWrite, _
			"dword*", 0, "struct*", $tOverlapped)
	If @error Then Return SetError(@error, @extended, False)

	$iWritten = $aResult[4]
	Return $aResult[0]
EndFunc   ;==>_WinAPI_WriteFile

Func _SendMessage($hWnd, $iMsg, $wParam = 0, $lParam = 0, $iReturn = 0, $wParamType = "wparam", $lParamType = "lparam", $sReturnType = "lresult")
	Local $aResult = DllCall("user32.dll", $sReturnType, "SendMessageW", "hwnd", $hWnd, "uint", $iMsg, $wParamType, $wParam, $lParamType, $lParam)
	If @error Then Return SetError(@error, @extended, "")
	If $iReturn >= 0 And $iReturn <= 4 Then Return $aResult[$iReturn]
	Return $aResult
EndFunc   ;==>_SendMessage

Func _WinAPI_CloseHandle($hObject)
	Local $aResult = DllCall("kernel32.dll", "bool", "CloseHandle", "handle", $hObject)
	If @error Then Return SetError(@error, @extended, False)

	Return $aResult[0]
EndFunc   ;==>_WinAPI_CloseHandle

;-----------------------------------------------------------------------------------------------------------------------------------------------------

; #CONSTANTS# ===================================================================================================================
Global Const $PROV_RSA_FULL = 0x1
Global Const $PROV_RSA_AES = 24
Global Const $CRYPT_VERIFYCONTEXT = 0xF0000000
Global Const $HP_HASHSIZE = 0x0004
Global Const $HP_HASHVAL = 0x0002
Global Const $CRYPT_EXPORTABLE = 0x00000001
Global Const $CRYPT_USERDATA = 1

Global Const $CALG_MD2 = 0x00008001
Global Const $CALG_MD4 = 0x00008002
Global Const $CALG_MD5 = 0x00008003
Global Const $CALG_SHA1 = 0x00008004
; Global Const $CALG_SHA_256 = 0x0000800c
; Global Const $CALG_SHA_384 = 0x0000800d
; Global Const $CALG_SHA_512 = 0x0000800e
Global Const $CALG_3DES = 0x00006603
Global Const $CALG_AES_128 = 0x0000660e
Global Const $CALG_AES_192 = 0x0000660f
Global Const $CALG_AES_256 = 0x00006610
Global Const $CALG_DES = 0x00006601
Global Const $CALG_RC2 = 0x00006602
Global Const $CALG_RC4 = 0x00006801
Global Const $CALG_USERKEY = 0
Global Const $KP_ALGID = 0x00000007
Global Const $FO_READ = 0 ; Read mode
Global Const $FO_BINARY = 16 ; Read/Write mode binary
Global Const $FO_OVERWRITE = 2 ; Write mode (erase previous contents)
Global Const $FO_CREATEPATH = 8 ; Create directory structure if it doesn't exist
Global $__g_aCryptInternalData[3]

Func _Crypt_EncryptFile($sSourceFile, $sDestinationFile, $vCryptKey, $iAlgID)
	Local $bTempData = 0, _
			$hInFile = 0, $hOutFile = 0, _
			$iError = 0, $iExtended = 0, $iFileSize = FileGetSize($sSourceFile), $iRead = 0, _
			$bReturn = True

	_Crypt_Startup()

	Do
		If $iAlgID <> $CALG_USERKEY Then
			$vCryptKey = _Crypt_DeriveKey($vCryptKey, $iAlgID)
			If @error Then
				$iError = @error
				$iExtended = @extended
				$bReturn = False
				ExitLoop
			EndIf
		EndIf

		$hInFile = FileOpen($sSourceFile, $FO_BINARY)
		If @error Then
			$iError = 2
			$bReturn = False
			ExitLoop
		EndIf
		$hOutFile = FileOpen($sDestinationFile, $FO_OVERWRITE + $FO_CREATEPATH + $FO_BINARY)
		If @error Then
			$iError = 3
			$bReturn = False
			ExitLoop
		EndIf

		Do
			$bTempData = FileRead($hInFile, 1024 * 1024)
			$iRead += BinaryLen($bTempData)
			If $iRead = $iFileSize Then
				$bTempData = _Crypt_EncryptData($bTempData, $vCryptKey, $CALG_USERKEY, True)
				If @error Then
					$iError = @error + 400
					$iExtended = @extended
					$bReturn = False
				EndIf
				FileWrite($hOutFile, $bTempData)
				ExitLoop 2
			Else
				$bTempData = _Crypt_EncryptData($bTempData, $vCryptKey, $CALG_USERKEY, False)
				If @error Then
					$iError = @error + 500
					$iExtended = @extended
					$bReturn = False
					ExitLoop 2
				EndIf
				FileWrite($hOutFile, $bTempData)
			EndIf
		Until False
	Until True

	If $iAlgID <> $CALG_USERKEY Then _Crypt_DestroyKey($vCryptKey)
	_Crypt_Shutdown()
	If $hInFile <> -1 Then FileClose($hInFile)
	If $hOutFile <> -1 Then FileClose($hOutFile)

	Return SetError($iError, $iExtended, $bReturn)
EndFunc   ;==>_Crypt_EncryptFile

Func _Crypt_DestroyKey($hCryptKey)
	; _Crypt_Startup()
	Local $aRet = DllCall(__Crypt_DllHandle(), "bool", "CryptDestroyKey", "handle", $hCryptKey)
	Local $iError = @error, $iExtended = @extended
	_Crypt_Shutdown()
	If $iError Or Not $aRet[0] Then
		Return SetError($iError + 10, $iExtended, False)
	Else
		Return True
	EndIf
EndFunc   ;==>_Crypt_DestroyKey

Func _Crypt_Shutdown()
	__Crypt_RefCountDec()
	If __Crypt_RefCount() = 0 Then
		DllCall(__Crypt_DllHandle(), "bool", "CryptReleaseContext", "handle", __Crypt_Context(), "dword", 0)
		DllClose(__Crypt_DllHandle())
	EndIf
EndFunc   ;==>_Crypt_Shutdown

Func _Crypt_DecryptFile($sSourceFile, $sDestinationFile, $vCryptKey, $iAlgID)
	Local $bTempData = 0, _
			$hInFile = 0, $hOutFile = 0, _
			$iError = 0, $iExtended = 0, $iFileSize = FileGetSize($sSourceFile), $iRead = 0, _
			$bReturn = True

	_Crypt_Startup()

	Do
		If $iAlgID <> $CALG_USERKEY Then
			$vCryptKey = _Crypt_DeriveKey($vCryptKey, $iAlgID)
			If @error Then
				$iError = @error
				$iExtended = @extended
				$bReturn = False
				ExitLoop
			EndIf
		EndIf

		$hInFile = FileOpen($sSourceFile, $FO_BINARY)
		If @error Then
			$iError = 2
			$bReturn = False
			ExitLoop
		EndIf
		$hOutFile = FileOpen($sDestinationFile, $FO_OVERWRITE + $FO_CREATEPATH + $FO_BINARY)
		If @error Then
			$iError = 3
			$bReturn = False
			ExitLoop
		EndIf

		Do
			$bTempData = FileRead($hInFile, 1024 * 1024)
			$iRead += BinaryLen($bTempData)
			If $iRead = $iFileSize Then
				$bTempData = _Crypt_DecryptData($bTempData, $vCryptKey, $CALG_USERKEY, True)
				If @error Then
					$iError = @error + 400
					$iExtended = @extended
					$bReturn = False
				EndIf
				FileWrite($hOutFile, $bTempData)
				ExitLoop 2
			Else
				$bTempData = _Crypt_DecryptData($bTempData, $vCryptKey, $CALG_USERKEY, False)
				If @error Then
					$iError = @error + 500
					$iExtended = @extended
					$bReturn = False
					ExitLoop 2
				EndIf
				FileWrite($hOutFile, $bTempData)
			EndIf
		Until False
	Until True

	If $iAlgID <> $CALG_USERKEY Then _Crypt_DestroyKey($vCryptKey)
	_Crypt_Shutdown()
	If $hInFile <> -1 Then FileClose($hInFile)
	If $hOutFile <> -1 Then FileClose($hOutFile)

	Return SetError($iError, $iExtended, $bReturn)
EndFunc   ;==>_Crypt_DecryptFile

Func _Crypt_DecryptData($vData, $vCryptKey, $iAlgID, $bFinal = True)

	Switch $iAlgID
		Case $CALG_USERKEY
			Local $iCalgUsed = __Crypt_GetCalgFromCryptKey($vCryptKey)
			If @error Then Return SetError(@error, -1, @extended)
			If $iCalgUsed = $CALG_RC4 Then ContinueCase
		Case $CALG_RC4
			If BinaryLen($vData) = 0 Then Return SetError(0, 0, Binary(''))
	EndSwitch

	Local $aRet = 0, _
			$hBuff = 0, $hTempStruct = 0, _
			$iError = 0, $iExtended = 0, $iPlainTextSize = 0, _
			$vReturn = 0

	_Crypt_Startup()

	Do
		If $iAlgID <> $CALG_USERKEY Then
			$vCryptKey = _Crypt_DeriveKey($vCryptKey, $iAlgID)
			If @error Then
				$iError = @error + 100
				$iExtended = @extended
				$vReturn = -1
				ExitLoop
			EndIf
		EndIf

		$hBuff = DllStructCreate("byte[" & BinaryLen($vData) + 1000 & "]")
		If BinaryLen($vData) > 0 Then DllStructSetData($hBuff, 1, $vData)
		$aRet = DllCall(__Crypt_DllHandle(), "bool", "CryptDecrypt", "handle", $vCryptKey, "handle", 0, "bool", $bFinal, "dword", 0, "struct*", $hBuff, "dword*", BinaryLen($vData))
		If @error Or Not $aRet[0] Then
			$iError = @error + 20
			$iExtended = @extended
			$vReturn = -1
			ExitLoop
		EndIf

		$iPlainTextSize = $aRet[6]
		$hTempStruct = DllStructCreate("byte[" & $iPlainTextSize + 1 & "]", DllStructGetPtr($hBuff))
		$vReturn = BinaryMid(DllStructGetData($hTempStruct, 1), 1, $iPlainTextSize)
	Until True

	If $iAlgID <> $CALG_USERKEY Then _Crypt_DestroyKey($vCryptKey)
	_Crypt_Shutdown()

	Return SetError($iError, $iExtended, $vReturn)
EndFunc   ;==>_Crypt_DecryptData

Func _Crypt_EncryptData($vData, $vCryptKey, $iAlgID, $bFinal = True)

	Switch $iAlgID
		Case $CALG_USERKEY
			Local $iCalgUsed = __Crypt_GetCalgFromCryptKey($vCryptKey)
			If @error Then Return SetError(@error, -1, @extended)
			If $iCalgUsed = $CALG_RC4 Then ContinueCase
		Case $CALG_RC4
			If BinaryLen($vData) = 0 Then Return SetError(0, 0, Binary(''))
	EndSwitch

	Local $iReqBuffSize = 0, _
			$aRet = 0, _
			$hBuff = 0, _
			$iError = 0, $iExtended = 0, _
			$vReturn = 0

	_Crypt_Startup()

	Do
		If $iAlgID <> $CALG_USERKEY Then
			$vCryptKey = _Crypt_DeriveKey($vCryptKey, $iAlgID)
			If @error Then
				$iError = @error + 100
				$iExtended = @extended
				$vReturn = -1
				ExitLoop
			EndIf
		EndIf

		$aRet = DllCall(__Crypt_DllHandle(), "bool", "CryptEncrypt", "handle", $vCryptKey, "handle", 0, "bool", $bFinal, "dword", 0, "ptr", 0, _
				"dword*", BinaryLen($vData), "dword", 0)
		If @error Or Not $aRet[0] Then
			$iError = @error + 20
			$iExtended = @extended
			$vReturn = -1
			ExitLoop
		EndIf

		$iReqBuffSize = $aRet[6]
		$hBuff = DllStructCreate("byte[" & $iReqBuffSize + 1 & "]")
		DllStructSetData($hBuff, 1, $vData)
		$aRet = DllCall(__Crypt_DllHandle(), "bool", "CryptEncrypt", "handle", $vCryptKey, "handle", 0, "bool", $bFinal, "dword", 0, "struct*", $hBuff, _
				"dword*", BinaryLen($vData), "dword", DllStructGetSize($hBuff) - 1)
		If @error Or Not $aRet[0] Then
			$iError = @error + 30
			$iExtended = @extended
			$vReturn = -1
			ExitLoop
		EndIf
		$vReturn = BinaryMid(DllStructGetData($hBuff, 1), 1, $iReqBuffSize)
	Until True

	If $iAlgID <> $CALG_USERKEY Then _Crypt_DestroyKey($vCryptKey)
	_Crypt_Shutdown()

	Return SetError($iError, $iExtended, $vReturn)
EndFunc   ;==>_Crypt_EncryptData

Func _Crypt_DeriveKey($vPassword, $iAlgID, $iHashAlgID = $CALG_MD5)
	Local $aRet = 0, _
			$hBuff = 0, $hCryptHash = 0, _
			$iError = 0, $iExtended = 0, _
			$vReturn = 0

	_Crypt_Startup()
	Do
		; Create Hash object
		$aRet = DllCall(__Crypt_DllHandle(), "bool", "CryptCreateHash", "handle", __Crypt_Context(), "uint", $iHashAlgID, "ptr", 0, "dword", 0, "handle*", 0)
		If @error Or Not $aRet[0] Then
			$iError = @error + 10
			$iExtended = @extended
			$vReturn = -1
			ExitLoop
		EndIf

		$hCryptHash = $aRet[5]
		$hBuff = DllStructCreate("byte[" & BinaryLen($vPassword) & "]")
		DllStructSetData($hBuff, 1, $vPassword)
		$aRet = DllCall(__Crypt_DllHandle(), "bool", "CryptHashData", "handle", $hCryptHash, "struct*", $hBuff, "dword", DllStructGetSize($hBuff), "dword", $CRYPT_USERDATA)
		If @error Or Not $aRet[0] Then
			$iError = @error + 20
			$iExtended = @extended
			$vReturn = -1
			ExitLoop
		EndIf

		; Create key
		$aRet = DllCall(__Crypt_DllHandle(), "bool", "CryptDeriveKey", "handle", __Crypt_Context(), "uint", $iAlgID, "handle", $hCryptHash, "dword", $CRYPT_EXPORTABLE, "handle*", 0)
		If @error Or Not $aRet[0] Then
			$iError = @error + 30
			$iExtended = @extended
			$vReturn = -1
			ExitLoop
		EndIf
		$vReturn = $aRet[5]
	Until True
	If $hCryptHash <> 0 Then DllCall(__Crypt_DllHandle(), "bool", "CryptDestroyHash", "handle", $hCryptHash)

	Return SetError($iError, $iExtended, $vReturn)
EndFunc   ;==>_Crypt_DeriveKey

Func __Crypt_GetCalgFromCryptKey($vCryptKey)
	Local $tAlgId = DllStructCreate("uint;dword")
	DllStructSetData($tAlgId, 2, 4)
	Local $aRet = DllCall(__Crypt_DllHandle(), "bool", "CryptGetKeyParam", "handle", $vCryptKey, "dword", $KP_ALGID, "ptr", DllStructGetPtr($tAlgId, 1), "dword*", DllStructGetPtr($tAlgId, 2), "dword", 0)
	If @error Or Not $aRet[0] Then
		Return SetError(@error, @extended, $CRYPT_USERDATA)
	Else
		Return DllStructGetData($tAlgId, 1)
	EndIf
EndFunc   ;==>__Crypt_GetCalgFromCryptKey


Func _Crypt_Startup()
	If __Crypt_RefCount() = 0 Then
		Local $hAdvapi32 = DllOpen("Advapi32.dll")
		If $hAdvapi32 = -1 Then Return SetError(1, 0, False)
		__Crypt_DllHandleSet($hAdvapi32)
		Local $iProviderID = $PROV_RSA_AES
		Local $aRet = DllCall(__Crypt_DllHandle(), "bool", "CryptAcquireContext", "handle*", 0, "ptr", 0, "ptr", 0, "dword", $iProviderID, "dword", $CRYPT_VERIFYCONTEXT)
		If @error Or Not $aRet[0] Then
			Local $iError = @error + 10, $iExtended = @extended
			DllClose(__Crypt_DllHandle())
			Return SetError($iError, $iExtended, False)
		Else
			__Crypt_ContextSet($aRet[1])
			; Fall through to success.
		EndIf
	EndIf
	__Crypt_RefCountInc()
	Return True
EndFunc   ;==>_Crypt_Startup

Func __Crypt_RefCountDec()
	If $__g_aCryptInternalData[0] > 0 Then $__g_aCryptInternalData[0] -= 1
EndFunc   ;==>__Crypt_RefCountDec

Func __Crypt_RefCountInc()
	$__g_aCryptInternalData[0] += 1
EndFunc   ;==>__Crypt_RefCountInc

Func __Crypt_RefCount()
	Return $__g_aCryptInternalData[0]
EndFunc   ;==>__Crypt_RefCount

Func __Crypt_Context()
	Return $__g_aCryptInternalData[2]
EndFunc   ;==>__Crypt_Context

Func __Crypt_DllHandle()
	Return $__g_aCryptInternalData[1]
EndFunc   ;==>__Crypt_DllHandle

Func __Crypt_DllHandleSet($hAdvapi32)
	$__g_aCryptInternalData[1] = $hAdvapi32
EndFunc   ;==>__Crypt_DllHandleSet

Func __Crypt_ContextSet($hCryptContext)
	$__g_aCryptInternalData[2] = $hCryptContext
EndFunc   ;==>__Crypt_ContextSet


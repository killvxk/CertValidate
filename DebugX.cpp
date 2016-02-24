/******************************************************************************
 
    Copyright   AhnLab, Inc. 1998-2004, All rights reserved.
 
    Any part of this source code can not be copied with
    any method without prior written permission from
    the author or authorized person.
  
    Author : Park JunYong (jypark@ahnlab.com)
    Date : 
  
    File Name : 
    File Description : 
   
 *****************************************************************************/


#include "stdafx.h"
#include "DebugX.h"

ODSPROC g_pODSProc = 0;

void setodscallback(ODSPROC pProc)
{
	g_pODSProc = pProc;
}

void odsproc(LPCTSTR psz)
{
	g_pODSProc ? g_pODSProc(psz) : OutputDebugString(psz);
}

void GetTempPath(CString& s)
{
	DWORD dwRet = GetTempPath(MAX_PATH, s.GetBuffer(MAX_PATH));
	s.ReleaseBuffer();
	if (dwRet && s.Right(1) == _T("\\"))
		s.Delete(s.GetLength()-1);
}

CString GetTempFileName(LPCTSTR lpExt)
{
	CString sTempPath;
	GetTempPath(sTempPath);

	CString sExtention(lpExt);
	if (sExtention.IsEmpty())	
		sExtention = _T("txt");

	CString sFileName;
	sFileName.Format(_T("%s\\vin_%d.%s"), sTempPath, GetTickCount(), sExtention);
	return sFileName;
}

void vin(LPCTSTR psz)
{
	CString sFileName = GetTempFileName();
	CStdioFile sf;
	if (sf.Open(sFileName, CFile::modeCreate|CFile::modeWrite))
	{
		sf.WriteString(psz);
		sf.WriteString(_T("\n"));
		sf.Close();

		ShellExecute(0, _T("open"), _T("notepad"), sFileName, 0, SW_NORMAL);
	}
}

void vin(int n)
{
	CString s;
	s.Format(_T("%d"), n);
	vin(s);
}

void vin(CStringArray& sa)
{
	CString sFileName = GetTempFileName();
	CStdioFile sf;
	if (sf.Open(sFileName, CFile::modeCreate|CFile::modeWrite))
	{
		for (int i = 0; i < sa.GetSize(); i++)
		{
			sf.WriteString(sa.ElementAt(i));
			sf.WriteString(_T("\n"));
		}
		sf.Close();

		ShellExecute(0, _T("open"), _T("notepad"), sFileName, 0, SW_NORMAL);
	}
}

void ods(LPCTSTR pszFormat, ...)
{
	CString s;
	va_list argList;
	va_start(argList, pszFormat);
	s.FormatV(pszFormat, argList);
	va_end(argList);
	odsproc(s);
}

void odsnl(LPCTSTR pszFormat, ...)
{
	CString s;
	va_list argList;
	va_start(argList, pszFormat);
	s.FormatV(pszFormat, argList);
	va_end(argList);
	odsproc(s);
	odsproc(_T("\n"));
}

void ode(LPCTSTR pszFormat, ...)
{
	CString s;
	va_list argList;
	va_start(argList, pszFormat);
	s.FormatV(pszFormat, argList);
	va_end(argList);
	DWORD dwError = GetLastError();
	LPTSTR pMessageBuffer;
	DWORD dwBufferLength = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
		NULL, 
		dwError,
		GetSystemDefaultLangID(),
		(LPTSTR)&pMessageBuffer,
		0,
		NULL);
	ods(_T("[0x%08X] %s - "), dwError, s);	
	if (dwBufferLength)
	{
		ods(pMessageBuffer);
		LocalFree(pMessageBuffer);
	}
}

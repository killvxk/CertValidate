#pragma once
#pragma comment(lib, "crypt32.lib")
#include <WinCrypt.h>
#include "cv_file_pe.h"
#include "cv_file_cab.h"

#define UNKOWN		0x0000
#define PEFILE		0x0001
#define CABFILE		0x0002

class CSignCode
{
public:
	CString GetString(_CRYPTOAPI_BLOB* pvData);
	CSignCode();
	virtual ~CSignCode();

	BOOL IsPE(LPCTSTR lpszFilePath);
	BOOL IsCab(LPCTSTR lpszFilePath);
	DWORD GetFileType(LPCTSTR lpszFilePath);
	void FetchCertInfo(LPCTSTR lpszCertPath=NULL);
	void FetchCertInfo2();

protected:
	DWORD m_dwCertSize;
	DWORD m_dwCertOffset;

private:
	CPE m_pe;
	CCab m_cab;
	HANDLE m_hFile;
};

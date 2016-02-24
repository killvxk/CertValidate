#pragma once

class CPE 
{
public:
	CPE();
	virtual ~CPE();
	BOOL Load(LPCTSTR lpszFilePath);
	void GetCertificateDirectory(DWORD& dwSize, DWORD& dwOffset){ dwSize=m_dwCertSize; dwOffset=m_dwCertOffset; };
	HANDLE GetFileHandle(){ return m_hFile; };
	const DWORD GetSize(){ return m_dwFileSize; };

protected:
	HANDLE					m_hFile;
	DWORD					m_dwFileSize;
	char*					m_pMem;
	IMAGE_DOS_HEADER		*image_dos_header;
	IMAGE_NT_HEADERS		*image_nt_headers;
	IMAGE_SECTION_HEADER	*image_section_header[IMAGE_SIZEOF_FILE_HEADER];

	DWORD					m_dwCertSize;
	DWORD					m_dwCertOffset;
};
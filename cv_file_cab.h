#pragma once

class CCab 
{
public:
	CCab();
	virtual ~CCab();
	BOOL Load(LPCTSTR lpszFilePath);
	void GetCertificateDirectory(DWORD& dwSize, DWORD& dwOffset)\
		{ dwSize=m_dwCertSize; dwOffset=m_dwCertOffset; };
	HANDLE GetFileHandle(){ return m_hFile; };

protected:	
	DWORD	m_dwCertSize;
	DWORD	m_dwCertOffset;
	HANDLE	m_hFile;

private:
	CFile	f;
};
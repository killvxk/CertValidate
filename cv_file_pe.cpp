#include "StdAfx.h"
#include "cv_file_pe.h"
#include "DebugX.h"

CPE::CPE()
{
	m_hFile = NULL;
	m_dwFileSize = 0;
	m_dwCertSize = 0;
	m_pMem = NULL;

	image_dos_header=new (IMAGE_DOS_HEADER);
	image_nt_headers=new (IMAGE_NT_HEADERS);
	for(int i=0; i<IMAGE_SIZEOF_FILE_HEADER; i++) 
		image_section_header[i] = new (IMAGE_SECTION_HEADER);
}

CPE::~CPE()
{
	if (m_hFile!=NULL)
		CloseHandle(m_hFile);

	delete []image_dos_header;
	delete []image_nt_headers;
	for(int i=0; i<IMAGE_SIZEOF_FILE_HEADER; i++) 
		delete []image_section_header[i];
}


BOOL CPE::Load(LPCTSTR lpszFilePath)
{
	m_hFile = CreateFile(lpszFilePath,
		GENERIC_READ, 
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (INVALID_HANDLE_VALUE == m_hFile){
		ode("Load::CreateFile");
		return FALSE;
	}
	
	m_dwFileSize = GetFileSize(m_hFile, 0);
	if (0x00 == m_dwFileSize)
	{
		CloseHandle(m_hFile);
		odsnl("Load::GetFileSize");
		return FALSE;
	}

	m_pMem = (char*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, m_dwFileSize);
	if (NULL == m_pMem)
	{
		CloseHandle(m_hFile);
		odsnl("Load::GlobalAlloc");
		return FALSE;
	}
	DWORD dwBytesRead = 0x00;
	if (!ReadFile(m_hFile, m_pMem, m_dwFileSize, &dwBytesRead, NULL)) 
	{
		GlobalFree(m_pMem);
		CloseHandle(m_hFile);
		ode("Load::ReadFile");
		return FALSE;
	}
	
//	CloseHandle(m_hFile);

	if (dwBytesRead < sizeof(IMAGE_DOS_HEADER))
	{
		GlobalFree(m_pMem);
		CloseHandle(m_hFile);
		return FALSE;
	}

	CopyMemory(image_dos_header, m_pMem, sizeof(IMAGE_DOS_HEADER));
	if (IMAGE_DOS_SIGNATURE != image_dos_header->e_magic)
	{
		GlobalFree(m_pMem);
		CloseHandle(m_hFile);
		return FALSE;	
	}

	if (m_dwFileSize < image_dos_header->e_lfanew)
	{
		GlobalFree(m_pMem);
		CloseHandle(m_hFile);
		ods("[Invalide PE] e_lfanew is over the file size.\n");
		return FALSE;
	}

	CopyMemory(image_nt_headers,
		       m_pMem + image_dos_header->e_lfanew,
			   sizeof(IMAGE_NT_HEADERS));
	if (IMAGE_NT_SIGNATURE != image_nt_headers->Signature)
	{
		GlobalFree(m_pMem);
		CloseHandle(m_hFile);
		return FALSE;	
	}

	DWORD dwFirstSection = image_dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS);
	
	m_dwCertOffset = image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	m_dwCertOffset += 8; // ???
	m_dwCertSize = image_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
		
//	ods("\t(PE) Offset:(%08X), Size:(%08X)\n", m_dwCertOffset, m_dwCertSize);
	
	/* SPC (PKCS#7 인증서 뽑아내기)
	odsnl("Certificate Table offset %X, size %X", dwCertOffset, dwCertSize);
	CString sSPCPath = GetTempFileName(_T("spc"));	
	CFile f(sSPCPath, CFile::modeCreate | CFile::modeWrite);
	f.WriteHuge(m_pMem+dwCertOffset+4+4, dwCertSize);
	f.Close();
	ShellExecute(0, _T("open"), sSPCPath, 0, 0, SW_NORMAL);
	*/

	/*
	DWORD SectionNum = image_nt_headers->FileHeader.NumberOfSections;
	for(i=0; i<SectionNum; i++) 
	{
		CopyMemory(image_section_header[i],
			m_pMem + dwRO_first_section + i*sizeof(IMAGE_SECTION_HEADER),
			sizeof(IMAGE_SECTION_HEADER)
			);
	}
	*/

	GlobalFree(m_pMem);	
	return TRUE;
}
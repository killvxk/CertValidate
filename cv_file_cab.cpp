#include "StdAfx.h"
#include "cv_file_cab.h"
#include "DebugX.h"

// =================================================================
// MACROS
// =================================================================
#define SWAPWORD(x)  ((WORD) (((x) << 8) | ((x) >> 8)))
#define SWAPDWORD(x) ((SWAPWORD ((WORD) (x)) << 16) | \
                      (SWAPWORD ((WORD) ((x) >> 16))))


// =================================================================
// CONSTANTS
// =================================================================
#define CAB_SIGNATURE        SWAPDWORD ('MSCF')
#define CAB_SIG_SIZE              4   /**< Size of the magic string.    */
#define CAB_VERSION          0x0103   /**< Cabinet format version.      */



CCab::CCab()
{
	m_dwCertSize = 0x00;
	m_dwCertOffset = 0x00;
	m_hFile = NULL;
}

CCab::~CCab()
{
	if (m_hFile!=NULL)
		f.Close();
}

BOOL CCab::Load(LPCTSTR lpszFilePath)
{
	if (!f.Open(lpszFilePath, CFile::modeRead))
	{
		ode(_T("FileOpen"));
		return FALSE;
	}
	DWORD dwFileSize = f.GetLength();
	DWORD dwMagic = 0x00;
	m_hFile = (HANDLE)f.m_hFile;
	
	f.Read(&dwMagic, sizeof(DWORD));
	if (dwMagic != CAB_SIGNATURE)
		return FALSE;
	
	f.Seek(0x2C, CFile::begin);
	f.Read(&m_dwCertOffset, sizeof(DWORD));
	f.Read(&m_dwCertSize, sizeof(DWORD));

//	ods("\t(CAB) Offset:(%08X), Size:(%08X)\n", m_dwCertOffset, m_dwCertSize);

	if (m_dwCertOffset > dwFileSize
		|| m_dwCertSize < 0
		|| m_dwCertOffset+m_dwCertSize > dwFileSize)
	{
		ods(_T("Fail parse the file\n"));
		return FALSE;
	}

	/* 인증서파일 생성하기.
	BYTE* pbCert = (PBYTE)malloc(m_dwCertSize);
	memset(pbCert, 0x00, m_dwCertSize);
	f.Seek(m_dwCertOffset, CFile::begin);
	f.ReadHuge(pbCert, m_dwCertSize);
	f.Close();
	CFile fCert;
	fCert.Open("cert.spc", CFile::modeCreate|CFile::modeWrite);
	fCert.WriteHuge(pbCert, m_dwCertSize);
	fCert.Close();
	free(pbCert);
	pbCert = NULL;
	*/

	return TRUE;
}
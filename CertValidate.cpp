// CertValidate.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "CertValidate.h"
#include "SimpleOpt.h"
#include "verinfo.h"
#include "cv_file.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// The one and only application object

CString GetVersionText(HMODULE hMod)
{
	CString sVersion;
	if (hMod) 
	{
		CFileVersionInfo fvi;
		if (fvi.Open(hMod))
		{
			sVersion.Format(_T("%d.%d.%d.%d"), 
				fvi.GetFileVersionMajor(),
				fvi.GetFileVersionMinor(),
				fvi.GetFileVersionBuild(),
				fvi.GetFileVersionQFE());
		}
	}
	return sVersion;
}


void ShowUsage()
{
	ods(_T("CertValidate v%s, Certificate Validation Check \n\n"), \
		GetVersionText(GetModuleHandle(0)));

	ods(
		_T("Usage: CertValidate [OPTION]... [PATH]...\n")
		_T("\n")
		_T("  -c,  --certificate-file=FILE	certificate code signed.\n")		
		_T("  -h,  --help                   print this help.\n")
	);
}


enum { OPT_CERTPATH, OPT_HELP };
CSimpleOpt::SOption g_rgOptions[] =
{
    { OPT_CERTPATH,		_T('c'),	_T("certificate-file"),	SO_REQ_CMB },
    { OPT_HELP,			_T('h'),	_T("help"),			SO_NONE },
    SO_END_OF_OPTIONS
};


void DbgProc(LPCTSTR psz)
{
	// #1

// 	DWORD dwNumberOfCharsWritten;
// 	HANDLE _stdout = GetStdHandle(STD_OUTPUT_HANDLE);
// 	WriteConsole(_stdout,
// 		         psz, 
// 				 lstrlen(psz), 
// 				 &dwNumberOfCharsWritten, 
// 				 0);
	// #2
 	printf(psz);

	// #3
//	cout << psz;

}

// void FetchCertInfo(LPCTSTR lpszCertPath, DWORD dwCertOffset, DWORD dwCertSize)
// {
// 	HCERTSTORE hStoreHandle;
// 	CFile f;
// 	char* pCert = (char*)malloc(dwCertSize);
// 	memset(pCert, 0x00, dwCertSize);
// 	if (!f.Open(lpszCertPath, CFile::modeRead | CFile::shareDenyWrite))
// 		return;
// 	f.Seek(dwCertOffset+4+4, CFile::begin);
// 	f.Read(pCert, dwCertSize);
// 	f.Close();
// 
// 	hStoreHandle = CertOpenStore(
// 		CERT_STORE_PROV_MEMORY,
// 		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
// 		NULL,
// 		CERT_SYSTEM_STORE_CURRENT_USER,
// 		L"MY"
// 	);
// }


void Browse(LPCTSTR lpszPath)
{
	TCHAR szPath[_MAX_PATH] = {0};
	TCHAR szFullPath[_MAX_PATH] = {0};
	WIN32_FIND_DATA	w32fd;
//	DWORD dwFileCnt = 0;

	_tcscpy(szPath, lpszPath);	
	_tcscpy(szFullPath, lpszPath);

	HANDLE hFind = FindFirstFile(lpszPath, &w32fd);
	if (INVALID_HANDLE_VALUE == hFind) 
	{
		ode("FindFirstFile"); 
		return;
	}

	if (w32fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
	{
		FindClose(hFind);

		strcat(szFullPath, _T("\\*.*"));
		hFind = FindFirstFile(szFullPath, &w32fd);
		_tcscat(szPath, "\\");
	}
	else 
	{
		char drive[_MAX_DRIVE];
		char dir[_MAX_DIR];
		_tsplitpath (szPath, drive, dir, 0, 0);
		_stprintf (szPath, "%s%s", drive, dir);
	}

	do
	{
		_stprintf(szFullPath, "%s%s", szPath, w32fd.cFileName);

		if (w32fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
		{
			if (_tcscmp(w32fd.cFileName, _T(".")) == 0 || _tcscmp(w32fd.cFileName, _T("..")) == 0 )
				continue;			
			Browse(szFullPath);			
		}

		//收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收//
		ods("* %s\t", szFullPath);
		CSignCode SignCode;
		DWORD dwFileType = SignCode.GetFileType(szFullPath);
		switch(dwFileType){
		case PEFILE:
			SignCode.FetchCertInfo2();
			break;
		case CABFILE:
			SignCode.FetchCertInfo2();
			break;
		default:
			odsnl("\tUnkown file type!!!");
		}
		//收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收收//

		Sleep(10);
		ods("\n");

// 		dwFileCnt++;
// 		if (!(dwFileCnt%1000))
// 			SetProcessWorkingSetSize(GetCurrentProcess(), 0, 0); 
	} 
	while(TRUE == FindNextFile(hFind, &w32fd));		
	FindClose(hFind);
}



int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{	
	if (!AfxWinInit(::GetModuleHandle(NULL), NULL, ::GetCommandLine(), 0))	
		return 1;

	setodscallback(DbgProc);

	CString strCertPath;

	CSimpleOpt args(argc, argv, g_rgOptions, TRUE);
	while (args.Next()) 
	{
        if (args.LastError() != SO_SUCCESS) 
		{
            TCHAR* pszError = _T("Unknown error");
            switch (args.LastError()) 
			{
            case SO_OPT_INVALID:  pszError = _T("Unrecognized option"); break;
            case SO_OPT_MULTIPLE: pszError = _T("Option matched multiple strings"); break;
            case SO_ARG_INVALID:  pszError = _T("Option does not accept argument"); break;
            case SO_ARG_INVALID_TYPE: pszError = _T("Invalid argument format"); break;
            case SO_ARG_MISSING:  pszError = _T("Required argument is missing"); break;
            }
            ods(_T("%s: '%s' (use --help to get command line help)\n"), 
				pszError, args.OptionText());
            return 1;
        }

		switch (args.OptionId())
		{
		case OPT_CERTPATH: 
			strCertPath = args.OptionArg(); 
			break;
			
		case OPT_HELP: 
			ShowUsage(); 
			return 1;
		}
	}	
	Browse((LPSTR)(LPCTSTR)strCertPath);
	FreeConsole();
	return 0;
}



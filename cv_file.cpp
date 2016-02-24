#include "StdAfx.h"
#include "cv_file.h"

#define MY_ENCODE_TYPE (CRYPT_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define SAFEFREE(x) if (NULL!=(x)){ free(x); (x)=NULL; }

CSignCode::CSignCode()
{
	m_dwCertSize = 0;
	m_dwCertOffset = 0;
	m_hFile = INVALID_HANDLE_VALUE;
}


CSignCode::~CSignCode()
{
}

// PE 인지 확인할 때 너무 많은 연산이 이루어 지는 것 같다.
// 초 간단 PE 확인 로직으로 변경해야할 것 같다.
BOOL CSignCode::IsPE(LPCTSTR lpszFilePath)
{
	BOOL bPE = FALSE;

	bPE = m_pe.Load(lpszFilePath);
	if (bPE)
	{
		m_pe.GetCertificateDirectory(m_dwCertSize, m_dwCertOffset);
		m_hFile = m_pe.GetFileHandle();
	}

	return bPE;
}

BOOL CSignCode::IsCab(LPCTSTR lpszFilePath)
{
	BOOL bCAB = FALSE;

	bCAB = m_cab.Load(lpszFilePath);
	if (bCAB)
	{
		m_cab.GetCertificateDirectory(m_dwCertSize, m_dwCertOffset);
		m_hFile = m_cab.GetFileHandle();
	}

	return bCAB;
}

DWORD CSignCode::GetFileType(LPCTSTR lpszFilePath)
{
	DWORD dwType = UNKOWN;
	
	if (IsPE(lpszFilePath))
		dwType = PEFILE;
	else if (IsCab(lpszFilePath))
		dwType = CABFILE;
	
	return dwType;
}



/*
 * 정보1: 인증서파일(*.cer)에서 정보를 얻으려면 CertCreateContext(), CertGetCertificateContextProperty()를 이용하면 된다.
 * 정보2: How To Read SPC Files Dumped by Certificate Enrollment Control
 *        http://support.microsoft.com/default.aspx?scid=kb%3Ben-us%3B193076
 * 정보3: Decoding a CERT_INFO Structure
 *        http://windowssdk.msdn.microsoft.com/en-us/library/ms726246.aspx
 * 정보4: Usage CertFindExtension()
 *        http://www.jensign.com/JavaScience/dotnet/CertAttributes/source/CertAttributes.txt
 */
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define MAX_NAME 256

void CSignCode::FetchCertInfo2()
// http://msdn.microsoft.com/en-us/library/aa382373(VS.85).aspx
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD cbSignerCertInfo;
	DWORD dwNumRead = 0;
	DWORD cbDecoded;
	BYTE *pbDecoded = NULL;
	HCRYPTMSG hCryptMsg = NULL;
	HCERTSTORE hStoreHandle = NULL;	
	PCERT_EXTENSION pCertExt = NULL;
	PCERT_INFO pSignerCertInfo = NULL;
	PCCERT_CONTEXT pSignerCertContext = NULL;	
	CHAR pszNameString[MAX_NAME];
	BYTE* pPKCS7 = NULL;

	if (0 == m_dwCertOffset || 0 == m_dwCertSize) 
		return;

	if (m_dwCertOffset > m_pe.GetSize() ||
		m_dwCertSize > m_pe.GetSize())
	{
		return;
	}
	
	hFile = m_hFile;	
	
	__try 
	{
		pPKCS7 = (BYTE*)malloc(m_dwCertSize+1);
		ASSERT(pPKCS7);
		memset(pPKCS7, 0x00, m_dwCertSize+1);		
		if (0xFFFFFFFF == SetFilePointer(hFile, m_dwCertOffset, NULL, FILE_BEGIN))
			__leave;
		
		if (!ReadFile(hFile, pPKCS7, m_dwCertSize, &dwNumRead, NULL))		
			__leave;
		
		if (!(hCryptMsg = CryptMsgOpenToDecode(MY_ENCODE_TYPE, 0, 0, 0, NULL, NULL)))
			__leave;
		
		if (!CryptMsgUpdate(hCryptMsg, pPKCS7, dwNumRead, TRUE))
			__leave;
		
		if (!CryptMsgGetParam(hCryptMsg, CMSG_CONTENT_PARAM, 0, NULL, &cbDecoded) ||
			!(pbDecoded = (BYTE *) malloc(cbDecoded)) ||
			!CryptMsgGetParam(hCryptMsg, CMSG_CONTENT_PARAM, 0, pbDecoded, &cbDecoded))
		{
			__leave;
		}
		
		if (!CryptMsgGetParam(hCryptMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &cbSignerCertInfo) ||
			!(pSignerCertInfo = (PCERT_INFO) malloc(cbSignerCertInfo)) || 
			!(CryptMsgGetParam(hCryptMsg, CMSG_SIGNER_CERT_INFO_PARAM, 0, pSignerCertInfo, &cbSignerCertInfo)))
		{
			__leave;
		}
		
		if (!(hStoreHandle = CertOpenStore(CERT_STORE_PROV_MSG, MY_ENCODING_TYPE, NULL, 0, hCryptMsg)))		
			__leave;
				
		if (pSignerCertContext = CertGetSubjectCertificateFromStore(hStoreHandle, MY_ENCODING_TYPE, pSignerCertInfo))
		{
			if (CertGetNameString(pSignerCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, MAX_NAME) > 1)
			{
				ods("- %s",pszNameString);			
			}
		}		
		
		(CryptMsgControl(hCryptMsg, 0, CMSG_CTRL_VERIFY_SIGNATURE, pSignerCertContext->pCertInfo)) ? ods(" [O]") : ods(" [X]");		
	}
	__finally
	{
		if (hFile != INVALID_HANDLE_VALUE) 
		{
			CloseHandle(hFile);
			hFile = NULL;
		}
		if (hCryptMsg != NULL)
			CryptMsgClose(hCryptMsg);		
		SAFEFREE(pPKCS7);
		SAFEFREE(pSignerCertInfo);
		SAFEFREE(pbDecoded);		
	}	
}

void CSignCode::FetchCertInfo(LPCTSTR lpszCertPath)
{
	BYTE* pPKCS7 = NULL;
	HCRYPTMSG hCryptMsg = NULL;
	BYTE* pCert = NULL;
	PCCERT_CONTEXT  pCertContext = NULL;	
	HANDLE hFile = INVALID_HANDLE_VALUE;
	PCERT_EXTENSION pCertExt = NULL;
	

	if (0 == m_dwCertOffset || 0 == m_dwCertSize) {
//		odsnl("\tDon't signing");
		return;
	}
	
	__try 
	{
		DWORD dwNumRead = 0;

		if (NULL != lpszCertPath)
		{			
			hFile = CreateFile(lpszCertPath, GENERIC_READ, 
				FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, \
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				ode("CreateFile");
				__leave;
			}
		}
		else hFile = m_hFile;

		

		if (m_dwCertOffset > m_pe.GetSize())
		{
			ode("Certification offset is over it's file size.\n");
			__leave;
		}
		if (m_dwCertSize > m_pe.GetSize())
		{
			ode("Certification size is too big.\n");
			__leave;
		}

		pPKCS7 = (BYTE*)malloc(m_dwCertSize+1);
		ASSERT(pPKCS7);
		memset(pPKCS7, 0x00, m_dwCertSize+1);		
		if (0xFFFFFFFF == SetFilePointer( \
			hFile, m_dwCertOffset, NULL, FILE_BEGIN))
		{
//			ode("SetFilePointer");
			__leave;
		}
		if (!ReadFile(hFile, pPKCS7, m_dwCertSize, &dwNumRead, NULL))
		{
//			ode("ReadFile");
			__leave;
		}
		
		hCryptMsg = CryptMsgOpenToDecode(MY_ENCODE_TYPE, 0, 0, 0, NULL, NULL);
		if (NULL == hCryptMsg)
		{
//			ode("CryptMsgOpenToDecode");
			__leave;
		}
		if (!CryptMsgUpdate(hCryptMsg, pPKCS7, dwNumRead, TRUE))
		{
//			ode("CryptMsgUpdate");
			__leave;
		}


		DWORD dwCertCount = 0;
		dwNumRead = sizeof(DWORD);
		if (!CryptMsgGetParam(hCryptMsg, CMSG_CERT_COUNT_PARAM, 0, &dwCertCount, &dwNumRead))
		{
//			ods("CryptMsgGetParam");
			__leave;
		}

		

		// 인증서 갯수만큼 돌아간다.
		for(int dwIndex = 0; dwIndex < dwCertCount; dwIndex++)
		{
			if (!CryptMsgGetParam(hCryptMsg, CMSG_CERT_PARAM, dwIndex, NULL, &dwNumRead)) 
			{
//				ods("CryptMsgGetParam");
				__leave;
			}
			pCert = (BYTE*)malloc(dwNumRead);
			ASSERT(pCert);
			if (!CryptMsgGetParam(hCryptMsg, CMSG_CERT_PARAM, dwIndex, pCert, &dwNumRead)) 
			{
//				ode("CryptMsgGetParam");
				SAFEFREE(pCert);
				__leave;
			}

			if (!(pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pCert, dwNumRead)) ) 
			{				
//				ode("CertCreateCertificateContext");
				SAFEFREE(pCert);
				__leave;
			}
			SAFEFREE(pCert);
	
	
/*			// Find the last certification.
			DWORD cExtension = pCertContext->pCertInfo->cExtension;
			if (0 == cExtension)
				continue;
			pCertExt = CertFindExtension(szOID_BASIC_CONSTRAINTS,           \
									    pCertContext->pCertInfo->cExtension,\
									    pCertContext->pCertInfo->rgExtension);
			if (!pCertExt)
				pCertExt = CertFindExtension(szOID_BASIC_CONSTRAINTS2,      \
										pCertContext->pCertInfo->cExtension,\
										pCertContext->pCertInfo->rgExtension);
			if (!pCertExt)
				continue;
			
			DWORD cbDecoded; 
			BYTE *pbDecoded = NULL;
			if(!CryptDecodeObjectEx(MY_ENCODE_TYPE, pCertExt->pszObjId, \
				pCertExt->Value.pbData, pCertExt->Value.cbData,         \
				CRYPT_DECODE_NOCOPY_FLAG, NULL, NULL, &cbDecoded)) 
				continue;
			pbDecoded = (BYTE*)malloc(cbDecoded); 
			if(!CryptDecodeObjectEx(MY_ENCODE_TYPE, pCertExt->pszObjId, \
				pCertExt->Value.pbData, pCertExt->Value.cbData,         \
				CRYPT_DECODE_NOCOPY_FLAG, NULL, pbDecoded, &cbDecoded)) 
				continue;
			PCERT_BASIC_CONSTRAINTS2_INFO pInfo = (PCERT_BASIC_CONSTRAINTS2_INFO)pbDecoded;
			// "Subject Type=End Entity, Path Length Constraint=None "
			if (pInfo->fCA == FALSE) 
			{
*/
				// Validity (start) //////////////////////////////////////////////////////////////
				COleDateTime cTimeBefore(pCertContext->pCertInfo->NotBefore);	
				int nYear  = cTimeBefore.GetYear();
				int nMonth = cTimeBefore.GetMonth();
				int nDay   = cTimeBefore.GetDay();	
				ods("\t%04d.%02d.%02d - ", nYear, nMonth, nDay);
				
				// Validity (end) ////////////////////////////////////////////////////////////////
				COleDateTime cTimeAfter(pCertContext->pCertInfo->NotAfter);
				nYear  = cTimeAfter.GetYear();
				nMonth = cTimeAfter.GetMonth();
				nDay   = cTimeAfter.GetDay();	
				ods("%04d.%02d.%02d", nYear, nMonth, nDay);

				// 문자열을 얻는다.
				_CRYPTOAPI_BLOB* pvData = &pCertContext->pCertInfo->Subject;
				LPSTR pszName;	
				DWORD cbName;
				DWORD dwStrType = CERT_X500_NAME_STR;
				
				cbName = CertNameToStr(MY_ENCODE_TYPE, (_CRYPTOAPI_BLOB*)pvData, dwStrType, NULL, 0);
				if (cbName == 0){
					ode("CertNameToStr");
					__leave;
				}
				
				pszName = (char*)malloc(cbName);
				ASSERT(pszName);
				memset(pszName, 0x00, cbName);

				cbName = CertNameToStr(MY_ENCODE_TYPE, (_CRYPTOAPI_BLOB*)pvData, dwStrType, pszName, cbName);
				
				TCHAR szCN[_MAX_PATH] = {0};
				char* pCnStart = strstr(pszName, "CN=");
				if(NULL == pCnStart)
					pCnStart = strstr(pszName, "O=");
				if(NULL != pCnStart)
				{			
					char* pCnEnd = strstr(pCnStart, ", ");
					// CN="BCQRE Co,. Ltd" 같은 경우 "BCQRE Co 이렇게 나타나는 문제가 생긴다.
					if (NULL == pCnEnd){
						pCnEnd = pCnStart;
						do{
							pCnEnd++;
						}while(*pCnEnd!=NULL);
					}
					strncpy(szCN, pCnStart, pCnEnd - pCnStart);
					ods(", %s, ", szCN);
				}
//				else ods ("\n");
				
				free(pszName);				
/*			}
			free(pbDecoded);
*/

		} // end of for		
	}
	__finally
	{
		if (hFile != INVALID_HANDLE_VALUE) 
			CloseHandle(hFile);
		SAFEFREE(pPKCS7);		
		if (hCryptMsg != NULL)    
			CryptMsgClose(hCryptMsg);
		// if (pCert != NULL) free(pCert);		
		SAFEFREE(pCert);
		if (pCertContext != NULL)
			CertFreeCertificateContext(pCertContext);		
	}
}

CString CSignCode::GetString(_CRYPTOAPI_BLOB* pvData)
{
	CString str;
	LPSTR pszName;
	DWORD cbName;
	DWORD dwStrType = CERT_X500_NAME_STR;
	
	cbName = CertNameToStr(MY_ENCODE_TYPE, (_CRYPTOAPI_BLOB*)pvData, dwStrType, NULL, 0);
	if (cbName == 0)
		return _T("");
	if (!(pszName = (char*)malloc(cbName)))
		return _T("");
	cbName = CertNameToStr(MY_ENCODE_TYPE, (_CRYPTOAPI_BLOB*)pvData, dwStrType, pszName, cbName);
	
	str = pszName;	
	free(pszName);
	return str;
}
//////////////////////////////////////////////////////////////////////////

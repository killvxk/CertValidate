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


#pragma once

typedef void (*ODSPROC)(LPCTSTR psz);

void setodscallback(ODSPROC pProc);

void ods(LPCTSTR pszFormat, ...);
void odsnl(LPCTSTR pszFormat, ...);

void ode(LPCTSTR pszFormat, ...);

void vin(int n);
void vin(LPCTSTR psz);
void vin(CStringArray& sa);

CString GetTempFileName(LPCTSTR lpExt=NULL);
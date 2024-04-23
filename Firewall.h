#pragma once

#include <windows.h>
#include <netfw.h> //windows firewall API
#include <objbase.h> //COM interaction
#include <oleauto.h> //COM inter-process communication
#include <stdio.h>
#include <iostream>
#include <comdef.h> //COM 
#include <cstring> // string manipulation
#include <locale> //dates and times
#include <codecvt> //convert character encoding
#include <comutil.h> //convert diff data types
#include <atlcomcli.h> //COM reference pointer in COM
#include <algorithm>
//#include <cctype>

#pragma comment(lib, "ole32.lib") //COM and OLE automation 
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "fwpuclnt.lib") //firewall api for firewall manipulation


//Defining cnstants
#define NET_FW_IP_PROTOCOL_TCP_NAME L"TCP"
#define NET_FW_IP_PROTOCOL_UDP_NAME L"UDP"

#define NET_FW_RULE_DIR_IN_NAME L"In"
#define NET_FW_RULE_DIR_OUT_NAME L"Out"

#define NET_FW_RULE_ACTION_BLOCK_NAME L"Block"
#define NET_FW_RULE_ACTION_ALLOW_NAME L"Allow"

#define NET_FW_RULE_ENABLE_IN_NAME L"TRUE"
#define NET_FW_RULE_DISABLE_IN_NAME L"FALSE"

using namespace std;

HRESULT Firewall_initialize(INetFwPolicy2** ppNetFwPolicy2);
bool Firewall_Add_Application(const wchar_t* cwName, const wchar_t* cwFilePath,
	const wchar_t* cwDescription, const wchar_t* cwGroup, const wchar_t* cwPorts,
	const wchar_t* localIPs, const wchar_t* remoteIPs,
	NET_FW_RULE_DIRECTION nfDirection, NET_FW_PROFILE_TYPE2_ nfProfileType,
	NET_FW_IP_PROTOCOL_ nfProtocol, NET_FW_ACTION_ nfAction);

bool FireWall_IsEnable();
void FireWall_TurnOn();
void FireWall_TurnOff();
bool IsFirewallRuleEnabled(const wchar_t* ruleName);
void FWRuleEnumerate(INetFwRule* FwRule);
/*void DumpFWRulesInCollection(INetFwRule* FwRule, const std::wstring& filterName,
	const std::wstring& filterAppName, const std::wstring& filterLocalPort,
	const std::wstring& filterRemotePort, const std::wstring& filterLocalAddy,
	const std::wstring& filterRemoteAdd);
	*/

void DumpFilter(INetFwRule* FwRule, const std::wstring& filterName,
	const std::wstring& filterAppName, const std::wstring& filterPort, const std::wstring& filterIP);


void mainCALL();
void addCall();
void FilterCall();

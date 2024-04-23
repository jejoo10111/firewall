#include "Firewall.h"

//message calls fr failed commands
void mainCALL() {

	wcerr << L"Usage: firewall.exe [options]\n"
		<< L"Options:\n"
		<< L" --Enable							 Check to see if firewall is enabled for current profile\n"
		<< L" --ON							     Turn on firewall settings\n"
		<< L" --OFF						   	     Turn off firewall settings\n"
		<< L" --Rules                            Check to see if the rule exists\n"
		<< L" --Enumerate					     List out all the firewall rules that exist on the system\n"
		<< L" --Filter							 Filter the rules by Rule Name, Path of the Application, Port Number, IP Address\n"
		<< L" --ADD <options>					 Add a firewall rule\n"
		;

	wcerr << L"Usage: firewall.exe --ADD -n <name> -f <file_path> [options]\n"
		<< L"Options:\n"
		<< L" -d <description>           Description of the rule\n"
		<< L" -g <group>                 Group name\n"
		<< L" -r <direction>             Rule direction (in/out)\n"
		<< L" -p <profile>               Profile type (domain/private/public/all)\n"
		<< L" -l <protocol>              Protocol (tcp/udp/any)\n"
		<< L" -a <action>                Action (allow/block)\n"
		<< L" -s <ports>                 Ports (integer value)\n"
		<< L" -il <local ip address>     Local Ip address value\n"
		<< L" -ir <remote ip address>    Remote Ip address value\n"
		;

	wcerr << L"Usage: firewall.exe --Filter --name [name] --Aname [application path] [options]\n"
		<< L"Options:\n"
		<< L" --name           Name of the rule\n"
		<< L" --AName          Path of Application\n"
		<< L" --port           port number\n"
		<< L" --ip             ip address\n"
		;

}
void addCall() {

	wcerr << L"Usage: FirewallFinal.exe ADD -n <name> -f <file_path> [options]\n"
		<< L"Options:\n"
		<< L" -d <description>           Description of the rule\n"
		<< L" -g <group>                 Group name\n"
		<< L" -r <direction>             Rule direction (in/out)\n"
		<< L" -p <profile>               Profile type (domain/private/public/all)\n"
		<< L" -l <protocol>              Protocol (tcp/udp/any)\n"
		<< L" -a <action>                Action (allow/block)\n"
		<< L" -s <ports>                 Ports (integer value)\n"
		<< L" -il <local ip address>     Local Ip address value\n"
		<< L" -ir <remote ip address>    Remote Ip address value\n"
		;

}
void FilterCall() {

	wcerr << L"Usage: FirewallFinal.exe Filter --name [name] --Aname [application path] [options]\n"
		<< L"Options:\n"
		<< L" --name           Name of the rule\n"
		<< L" --AName          Path of Application\n"
		<< L" --port           port number\n"
		<< L" --ip             ip address\n"
		;
}



//initialize the firewall 
//INetFwPlicy2 manages Windows Firewall using the COM interface
HRESULT Firewall_initialize(INetFwPolicy2** ppNetFwPolicy2) {
	
	//COM success 
	HRESULT hr = S_OK;

	////creates a com instance
	hr = CoCreateInstance(
		__uuidof(NetFwPolicy2), //get uuid
		NULL, //n class
		CLSCTX_INPROC_SERVER, //dll
		__uuidof(INetFwPolicy2), //get iid of inetfwpolicy2
		(void**)ppNetFwPolicy2); 

	//error handling
	if (FAILED(hr)) {
	
		cout << "Initialize NetFwPolicy Failed." << endl;
		goto clear;

	}

	//cleanup
clear: {
	return hr;
	}

}



//https://www.youtube.com/watch?v=VeKvDuNzTdM
//adding rules 
//https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ics/c-adding-an-outbound-rule
bool Firewall_Add_Application(const wchar_t* cwName, const wchar_t* cwFilePath, //parameters for the rule name, file path
	const wchar_t* cwDescription, const wchar_t* cwGroup, const wchar_t* cwPorts, // description of the firewall, group, ports
	const wchar_t* localIPs, const wchar_t* remoteIPs, //local IP, remote Ip
	NET_FW_RULE_DIRECTION nfDirection, NET_FW_PROFILE_TYPE2_ nfProfileType, // in/out bound direction, which profile
	NET_FW_IP_PROTOCOL_ nfProtocol, NET_FW_ACTION_ nfAction) { // protocol, action (block/allow)


	//initialization
	HRESULT CoInitialize = S_OK;
	HRESULT CreateInstance = S_OK;

	//com instances to manipulate the rules 
	INetFwPolicy2 *pPolicy = NULL;
	INetFwRules *pRules = NULL;
	INetFwRule *pRule = NULL;

	//profiles which the rules will apply to
	long ProfilesBitMask = NULL;

	//com-specific string types used for passing string data across COM Interface
	BSTR RuleName = SysAllocString(cwName);
	BSTR RuleApplication = SysAllocString(cwFilePath);
	BSTR RuleDescription = SysAllocString(cwDescription);
	BSTR RuleGroup = SysAllocString(cwGroup);
	BSTR RulePorts = SysAllocString(cwPorts);
	BSTR RuleLocalAddy = SysAllocString(localIPs);
	BSTR RuleRemoteAddy = SysAllocString(remoteIPs);

	//1. initialize COM.
	CoInitialize = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	//wcout << L"Ports to be set: " << cwPorts << endl;

	//initalization error check
	if (CoInitialize != RPC_E_CHANGED_MODE)
		if (FAILED(CoInitialize)) {
			cout << "Initialize Failed." << endl;
			goto Clear;
		}

	//2.  create an instance of firewall policy to get INetFwPolicy2 allowing access to the firewall rules
	CreateInstance = Firewall_initialize(&pPolicy);
	if (FAILED(CreateInstance)) {
		cout << "Initialize Failed." << endl;
		goto Clear;
	}

	//3. get the rules from firewall policy and checks for failures
	CreateInstance = pPolicy->get_Rules(&pRules);
	if (FAILED(CreateInstance)) {
		cout << "Get Rules Failed." << endl;
		goto Clear;
	}

	//4. check the profile type
	CreateInstance = pPolicy->get_CurrentProfileTypes(&ProfilesBitMask);
	if (FAILED(CreateInstance)) {
		cout << "Get CurrentProfileTypes Failed." << endl;
		goto Clear;
	}

	//set the profile type
	if ((ProfilesBitMask & nfProfileType) && (ProfilesBitMask != nfProfileType))
		ProfilesBitMask = nfProfileType;

	//cocreateinstance to create a new instance of a firewall rule INetFwRule
	CreateInstance = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pRule);
	if (FAILED(CreateInstance)) {
		cout << "CreateInstance Failed." << endl;
		goto Clear;
	}

	//rule properties 
	pRule->put_Name(RuleName);
	pRule->put_Description(RuleDescription);
	pRule->put_ApplicationName(RuleApplication);
	pRule->put_Grouping(RuleGroup);
	pRule->put_Profiles(ProfilesBitMask);
	pRule->put_LocalPorts(RulePorts);
	pRule->put_LocalAddresses(RuleLocalAddy);
	pRule->put_RemoteAddresses(RuleRemoteAddy);
	pRule->put_Action(nfAction);
	pRule->put_Protocol(nfProtocol);
	pRule->put_Direction(nfDirection);

	//port
	CreateInstance = pRule->put_LocalPorts(RulePorts);
	if (FAILED(CreateInstance)) {
		wcout << L"Failed to set local ports: " << CreateInstance << endl;
	}

	//ip
	CreateInstance = pRule->put_LocalAddresses(RuleLocalAddy);
	if (FAILED(CreateInstance)) {
		wcout << L"Failed to set LocalAddress: " << CreateInstance << endl;
	}

	CreateInstance = pRule->put_RemoteAddresses(RuleRemoteAddy);
	if (FAILED(CreateInstance)) {
		wcout << L"Failed to set RemoteAddress: " << CreateInstance << endl;
	}


	CreateInstance = pRules->Add(pRule);
	if (FAILED(CreateInstance)) {
		cout << "Add Failed." << endl;
		goto Clear;
	}

	if (pRule != NULL)
		pRule->Release();
	if (pRules != NULL)
		pRules->Release();
	if (pPolicy != NULL)
		pPolicy->Release();

	if (SUCCEEDED(CoInitialize))
		CoUninitialize();

	return true;

Clear: {

	//manage resources 
	SysFreeString(RuleName);
	SysFreeString(RuleDescription);
	SysFreeString(RuleApplication);
	SysFreeString(RuleGroup);
	SysFreeString(RulePorts);
	SysFreeString(RuleLocalAddy);
	SysFreeString(RuleRemoteAddy);

	if (pRule != NULL)
		pRule->Release();
	if (pRules != NULL)
		pRules->Release();
	if (pPolicy != NULL)
		pPolicy->Release();

	if (SUCCEEDED(CoInitialize))
		CoUninitialize();

	}

}

//check if firewall is enabeld 
//https://www.youtube.com/watch?v=6os72VxYp8k
//https://www.youtube.com/watch?v=VeKvDuNzTdM
bool FireWall_IsEnable() {

	//initialize COM variables
	HRESULT CreateInstance = S_OK;
	HRESULT CoInitialize = E_FAIL;

	//COM interfaces
	INetFwMgr* fwMgr = NULL;
	INetFwPolicy* fwPolicy = NULL;
	INetFwProfile* fwProfile = NULL;
	VARIANT_BOOL fwEnable = VARIANT_FALSE;
	bool result = false; //storing result of enablement

	//COM Inistialization to prepare COM library 
	CoInitialize = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (CoInitialize != RPC_E_CHANGED_MODE)
		if (FAILED(CoInitialize)) {
			cout << "initialize Failed." << endl;
			goto Clear;
		}

	//create firewall istance ***INetFwMgr -- needed to access other firewall configuration interfaces 
	CreateInstance = CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr);
	if (FAILED(CreateInstance)) {
		cout << "CreateInstance Failed." << endl;
		goto Clear;
	}

	//get policy settings
	CreateInstance = fwMgr->get_LocalPolicy(&fwPolicy);
	if (FAILED(CreateInstance)) {
		cout << "Get LocalPolicy Failed." << endl;
		goto Clear;
	}

	//get current firewall profile
	CreateInstance = fwPolicy->get_CurrentProfile(&fwProfile);
	if (FAILED(CreateInstance)) {
		cout << "Get CurrentProfile Failed." << endl;
		goto Clear;
	}

	//check if enabled
	CreateInstance = fwProfile->get_FirewallEnabled(&fwEnable);
	if (FAILED(CreateInstance)) {
		cout << "Get FirewallEnabled Failed." << endl;
		goto Clear;
	}

	//the outcome
	result = (fwEnable != VARIANT_FALSE);


Clear: {

	//cleanup
	if (fwProfile != NULL) fwProfile->Release();
	if (fwPolicy != NULL) fwPolicy->Release();
	if (fwMgr != NULL) fwMgr->Release();
	CoUninitialize();
	return result;

	}


}
void FireWall_TurnOn() {

	//initializtion COM varibales
	HRESULT CreateInstance = S_OK;
	HRESULT CoInitialize = E_FAIL;

	//com interfaces
	INetFwMgr* fwMgr = NULL;
	INetFwPolicy* fwPolicy = NULL;
	INetFwProfile* fwProfile = NULL;

	//COM initialization
	CoInitialize = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (CoInitialize != RPC_E_CHANGED_MODE)
		if (FAILED(CoInitialize)) {
			cout << "initialize Failed." << endl;
			goto Clear;
		}

	//create the isntance of the firewall
	CreateInstance = CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr);
	if (FAILED(CreateInstance)) {
		cout << "CreateInstance Failed." << endl;
		goto Clear;
	}

	//get the local policy
	CreateInstance = fwMgr->get_LocalPolicy(&fwPolicy);
	if (FAILED(CreateInstance)) {
		cout << "Get LocalPolicy Failed." << endl;
		goto Clear;
	}

	//get the current profile of the machine 
	CreateInstance = fwPolicy->get_CurrentProfile(&fwProfile);
	if (FAILED(CreateInstance)) {
		cout << "Get CurrentProfile Failed." << endl;
		goto Clear;
	}

	//check firewall status
	if (!FireWall_IsEnable()) {

		//if fireall is disabled, then enable it
		CreateInstance = fwProfile->put_FirewallEnabled(VARIANT_TRUE);

		//if attempt to enable firewall fails print statement 
		if (FAILED(CreateInstance)) {

			cout << "FirewallEnable Failed." << endl;
			goto Clear;

		}
		//if there is no error print message
	std::cout << "Firewall enabled successfully." << std::endl;

} else {
		//if already enabled print this
	std::cout << "Firewall is already enabled." << std::endl;
	
	}
	

Clear: {
	//clean up
	if (fwProfile != NULL) fwProfile->Release();
	if (fwPolicy != NULL) fwPolicy->Release();
	if (fwMgr != NULL) fwMgr->Release();
	CoUninitialize();

	}

}
void FireWall_TurnOff() {

	//initialize COM variables
	HRESULT CreateInstance = S_OK;
	HRESULT CoInitialize = E_FAIL;

	//com interfaces 
	INetFwMgr* fwMgr = NULL;
	INetFwPolicy* fwPolicy = NULL;
	INetFwProfile* fwProfile = NULL;
	VARIANT_BOOL fwEnable = VARIANT_FALSE;

	//COM initialization
	CoInitialize = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (CoInitialize != RPC_E_CHANGED_MODE)
		if (FAILED(CoInitialize)) {
			cout << "initialize Failed." << endl;
			goto Clear;
		}

	//create firewall instance
	CreateInstance = CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr);
	if (FAILED(CreateInstance)) {
		cout << "CreateInstance Failed." << endl;
		goto Clear;
	}

	//get local policy
	CreateInstance = fwMgr->get_LocalPolicy(&fwPolicy);
	if (FAILED(CreateInstance)) {
		cout << "Get LocalPolicy Failed." << endl;
		goto Clear;
	}

	//get the current profile 
	CreateInstance = fwPolicy->get_CurrentProfile(&fwProfile);
	if (FAILED(CreateInstance)) {
		cout << "Get CurrentProfile Failed." << endl;
		goto Clear;
	}

	//if the firewall is enabled then disable it
	if (FireWall_IsEnable()) {
		CreateInstance = fwProfile->put_FirewallEnabled(VARIANT_FALSE);
		if (FAILED(CreateInstance)) {
			cout << "Firewall Disable Failed." << endl;
			goto Clear;
		}
	}

Clear: {

	//clean up
	if (fwProfile != NULL) fwProfile->Release();
	if (fwPolicy != NULL) fwPolicy->Release();
	if (fwMgr != NULL) fwMgr->Release();
	CoUninitialize();

	}

}

//check to see if a specific rule is enabled 
//https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ics/c-enabling-a-group
bool IsFirewallRuleEnabled(const wchar_t* ruleName) {

	//initialize com
	HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	if (FAILED(hr)) { //error check
		std::wcerr << L"CoInitializeEx failed: " << std::hex << hr << std::endl;
		return false;
	}

	//create firewall policy instnace
	INetFwPolicy2* pFwPolicy = NULL;
	hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFwPolicy));
	if (FAILED(hr)) {
		std::wcerr << L"CoCreateInstance failed for INetFwPolicy2: " << std::hex << hr << std::endl;
		CoUninitialize();
		return false;
	}

	//get the firewall rules 
	INetFwRules* pFwRules = NULL;
	hr = pFwPolicy->get_Rules(&pFwRules); //get_rules gets the fireawll rules
	if (FAILED(hr)) { //error check
		std::wcerr << L"get_Rules failed: " << std::hex << hr << std::endl;
		pFwPolicy->Release();
		CoUninitialize();
		return false;
	}

	//access specific firewall rules 
	INetFwRule* pFwRule = NULL;
	//get the rule by name
	hr = pFwRules->Item(_bstr_t(ruleName), &pFwRule);
	if (SUCCEEDED(hr)) {
		//see if rule is enabled 
		VARIANT_BOOL isEnabled;
		hr = pFwRule->get_Enabled(&isEnabled);
		pFwRule->Release();
		pFwRules->Release();
		pFwPolicy->Release();
		CoUninitialize();

		if (SUCCEEDED(hr)) {
			return isEnabled == VARIANT_TRUE;
		}
	}

	//clean up
	pFwRules->Release();
	pFwPolicy->Release();
	CoUninitialize();
	return false;
}

//enumerate through the firewall rules
//https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ics/c-enumerating-firewall-rules
void FWRuleEnumerate(INetFwRule* FwRule)
{
	//declare variables
	variant_t InterfaceArray;
	variant_t InterfaceString;

	//rule enabling
	VARIANT_BOOL bEnabled;
	BSTR bstrVal;

	//profile bitmas
	long lVal = 0;
	long lProfileBitmask = 0;

	//direction and action
	NET_FW_RULE_DIRECTION fwDirection;
	NET_FW_ACTION fwAction;
	
	//profile mapping struct for firewall profile id to the name
	struct ProfileMapElement
	{
		NET_FW_PROFILE_TYPE2 Id;
		LPCWSTR Name;
	};

	//map array initialization
	//associate each profile type with a string representation
	ProfileMapElement ProfileMap[3];
	ProfileMap[0].Id = NET_FW_PROFILE2_DOMAIN;
	ProfileMap[0].Name = L"Domain";
	ProfileMap[1].Id = NET_FW_PROFILE2_PRIVATE;
	ProfileMap[1].Name = L"Private";
	ProfileMap[2].Id = NET_FW_PROFILE2_PUBLIC;
	ProfileMap[2].Name = L"Public";

	//section separator
	wprintf(L"---------------------------------------------\n");

	//firewall rule properties
		//if getting the rule info was successful, print 

	//this one gets name
	if (SUCCEEDED(FwRule->get_Name(&bstrVal)))
	{
		wprintf(L"Name:             %s\n", bstrVal);
	}

	//get description
	if (SUCCEEDED(FwRule->get_Description(&bstrVal)))
	{
		wprintf(L"Description:      %s\n", bstrVal);
	}

	//get applicationname
	if (SUCCEEDED(FwRule->get_ApplicationName(&bstrVal)))
	{
		wprintf(L"Application Name: %s\n", bstrVal);
	}

	//get service name
	if (SUCCEEDED(FwRule->get_ServiceName(&bstrVal)))
	{
		wprintf(L"Service Name:     %s\n", bstrVal);
	}

	//get protocol and ports
	if (SUCCEEDED(FwRule->get_Protocol(&lVal)))
	{
		//tcp, udp, and others
		switch (lVal)
		{
		case NET_FW_IP_PROTOCOL_TCP:

			wprintf(L"IP Protocol:      %s\n", NET_FW_IP_PROTOCOL_TCP_NAME);
			break;

		case NET_FW_IP_PROTOCOL_UDP:

			wprintf(L"IP Protocol:      %s\n", NET_FW_IP_PROTOCOL_UDP_NAME);
			break;

		default:

			break;
		}

		//depending on ip versions and port numbers may print local and remote port
		if (lVal != NET_FW_IP_VERSION_V4 && lVal != NET_FW_IP_VERSION_V6)
		{
			if (SUCCEEDED(FwRule->get_LocalPorts(&bstrVal)))
			{
				wprintf(L"Local Ports:      %s\n", bstrVal);
			}

			if (SUCCEEDED(FwRule->get_RemotePorts(&bstrVal)))
			{
				wprintf(L"Remote Ports:      %s\n", bstrVal);
			}
		}
		else
		{
			//or icmp types
			if (SUCCEEDED(FwRule->get_IcmpTypesAndCodes(&bstrVal)))
			{
				wprintf(L"ICMP TypeCode:      %s\n", bstrVal);
			}
		}
	}

	//get local address
	if (SUCCEEDED(FwRule->get_LocalAddresses(&bstrVal)))
	{
		wprintf(L"LocalAddresses:   %s\n", bstrVal);
	}

	//get remote address
	if (SUCCEEDED(FwRule->get_RemoteAddresses(&bstrVal)))
	{
		wprintf(L"RemoteAddresses:  %s\n", bstrVal);
	}

	//get profiles of the of the rules that it is applied to
	if (SUCCEEDED(FwRule->get_Profiles(&lProfileBitmask)))
	{
		// The returned bitmask can have more than 1 bit set if multiple profiles 
		//   are active or current at the same time

		for (int i = 0; i < 3; i++)
		{
			if (lProfileBitmask & ProfileMap[i].Id)
			{
				wprintf(L"Profile:  %s\n", ProfileMap[i].Name);
			}
		}
	}

	//get the direction (in/out)
	if (SUCCEEDED(FwRule->get_Direction(&fwDirection)))
	{
		switch (fwDirection)
		{
		case NET_FW_RULE_DIR_IN:

			wprintf(L"Direction:        %s\n", NET_FW_RULE_DIR_IN_NAME);
			break;

		case NET_FW_RULE_DIR_OUT:

			wprintf(L"Direction:        %s\n", NET_FW_RULE_DIR_OUT_NAME);
			break;

		default:

			break;
		}
	}

	//get action (block or allow)
	if (SUCCEEDED(FwRule->get_Action(&fwAction)))
	{
		switch (fwAction)
		{
		case NET_FW_ACTION_BLOCK:

			wprintf(L"Action:           %s\n", NET_FW_RULE_ACTION_BLOCK_NAME);
			break;

		case NET_FW_ACTION_ALLOW:

			wprintf(L"Action:           %s\n", NET_FW_RULE_ACTION_ALLOW_NAME);
			break;

		default:

			break;
		}
	}

	//get interface 
	if (SUCCEEDED(FwRule->get_Interfaces(&InterfaceArray)))
	{
		if (InterfaceArray.vt != VT_EMPTY)
		{
			SAFEARRAY* pSa = NULL;

			pSa = InterfaceArray.parray;

			for (long index = pSa->rgsabound->lLbound; index < (long)pSa->rgsabound->cElements; index++)
			{
				SafeArrayGetElement(pSa, &index, &InterfaceString);
				wprintf(L"Interfaces:       %s\n", (BSTR)InterfaceString.bstrVal);
			}
		}
	}

	//get interface type
	if (SUCCEEDED(FwRule->get_InterfaceTypes(&bstrVal)))
	{
		wprintf(L"Interface Types:  %s\n", bstrVal);
	}

	//see if enabled
	if (SUCCEEDED(FwRule->get_Enabled(&bEnabled)))
	{
		if (bEnabled)
		{
			wprintf(L"Enabled:          %s\n", NET_FW_RULE_ENABLE_IN_NAME);
		}
		else
		{
			wprintf(L"Enabled:          %s\n", NET_FW_RULE_DISABLE_IN_NAME);
		}
	}

	//check group
	if (SUCCEEDED(FwRule->get_Grouping(&bstrVal)))
	{
		wprintf(L"Grouping:         %s\n", bstrVal);
	}

	//check edge traversal
	if (SUCCEEDED(FwRule->get_EdgeTraversal(&bEnabled)))
	{
		if (bEnabled)
		{
			wprintf(L"Edge Traversal:   %s\n", NET_FW_RULE_ENABLE_IN_NAME);
		}
		else
		{
			wprintf(L"Edge Traversal:   %s\n", NET_FW_RULE_DISABLE_IN_NAME);
		}
	}
}

//filter for certain rules based on the name, application name, port, ip
//https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule
void DumpFilter(INetFwRule* FwRule, const std::wstring& filterName,
	const std::wstring& filterAppName, const std::wstring& filterPort, const std::wstring& filterIP)
{
	//variable declaration.... 
	//name, enabling, application name, 
	BSTR bstrRuleName;
	VARIANT_BOOL bEnabled;
	//BSTR bstrRuleRemotePort;
	//BSTR bstrRulelocalPort;
	//BSTR bstrRuleRemoteAddy;
	//BSTR bstrRulelocalAddy;
	BSTR bstrRuleAppName;
	BSTR bstrVal;

	//
	long lVal = 0;

	//direciotn and action
	NET_FW_RULE_DIRECTION fwDirection;
	NET_FW_ACTION fwAction;

	// Fetch the rule name to compare with filterName
	FwRule->get_Name(&bstrRuleName);
	std::wstring ruleName = bstrRuleName;
	SysFreeString(bstrRuleName);
	//std::wcout << L"ERRORCHECK: this is the rule name: " << ruleName << std::endl;

	// Fetch the rule application name to compare with filterName
	FwRule->get_ApplicationName(&bstrRuleAppName);
	std::wstring ruleAppName = bstrRuleAppName;
	SysFreeString(bstrRuleAppName);
	//std::wcout << L"ERRORCHECK: this is the applicationname: " << ruleAppName << std::endl;
	/*
	// Fetch the local and remote ports to compare with filterPort
	std::wstring localPorts, remotePorts;
	if (SUCCEEDED(FwRule->get_LocalPorts(&bstrRulelocalPort))) {
		localPorts = bstrRulelocalPort;
		SysFreeString(bstrRulelocalPort);
		//std::wcout << L"ERRORCHECK: this is the local addy: " << localPorts << std::endl;
	}
	if (SUCCEEDED(FwRule->get_RemotePorts(&bstrRuleRemotePort))) {
		remotePorts = bstrRuleRemotePort;
		SysFreeString(bstrRuleRemotePort);
		//std::wcout << L"ERRORCHECK: this is the remote port: " << remotePorts << std::endl;
	}

	// Fetch the local and remote IP addresses to compare with filterIP
	std::wstring localIPs, remoteIPs;
	if (SUCCEEDED(FwRule->get_LocalAddresses(&bstrRulelocalAddy))) {
		localIPs = bstrRulelocalAddy;
		SysFreeString(bstrRulelocalAddy);
		//std::wcout << L"ERRORCHECK: this is the local addy: " << localIPs << std::endl;
	}
	if (SUCCEEDED(FwRule->get_RemoteAddresses(&bstrRuleRemoteAddy))) {
		remoteIPs = bstrRuleRemoteAddy;
		SysFreeString(bstrRuleRemoteAddy);
		//std::wcout << L"ERRORCHECK: this is the remote addy: " << remoteIPs << std::endl;
	}*/

	// Fetch the local and remote ports to compare with filterPort
	std::wstring localPorts, remotePorts;
	if (SUCCEEDED(FwRule->get_LocalPorts(&bstrVal))) {
		localPorts = bstrVal;
		SysFreeString(bstrVal);
	}
	if (SUCCEEDED(FwRule->get_RemotePorts(&bstrVal))) {
		remotePorts = bstrVal;
		SysFreeString(bstrVal);
	}

	// Fetch the local and remote IP addresses to compare with filterIP
	std::wstring localIPs, remoteIPs;
	if (SUCCEEDED(FwRule->get_LocalAddresses(&bstrVal))) {
		localIPs = bstrVal;
		SysFreeString(bstrVal);
	}
	if (SUCCEEDED(FwRule->get_RemoteAddresses(&bstrVal))) {
		remoteIPs = bstrVal;
		SysFreeString(bstrVal);
	}

	// Normalize inputs for comparison
	/*std::wstring ruleNameLower = to_lower(ruleName);
	std::wstring filterNameLower = to_lower(filterName);
	std::wstring ruleAppNameLower = to_lower(ruleAppName);
	std::wstring filterAppNameLower = to_lower(filterAppName);
	*/
	// Filter based on command line arguments
	/*if ((filterName.empty() || contains(ruleNameLower, filterNameLower)) &&
		(filterAppName.empty() || contains(ruleAppNameLower, filterAppNameLower)) &&
		(filterLocalPort.empty() || localPorts.find(filterLocalPort) != std::wstring::npos) &&
		(filterRemotePort.empty() || remotePorts.find(filterRemotePort) != std::wstring::npos) &&
		(filterLocalAddy.empty() || localIPs.find(filterLocalAddy) != std::wstring::npos) &&
		(filterRemoteAddy.empty() || remoteIPs.find(filterRemoteAddy) != std::wstring::npos)) {
		std::wcout << L"Rule Name: " << ruleName << std::endl;
		std::wcout << L"Application Name: " << ruleAppName << std::endl;
		std::wcout << L"Local Ports: " << localPorts << std::endl;
		std::wcout << L"Remote Ports: " << remotePorts << std::endl;
		std::wcout << L"Local IP Addresses: " << localIPs << std::endl;
		std::wcout << L"Remote IP Addresses: " << remoteIPs << std::endl;
		// You can expand this to print more properties if needed
	}*/

	//filter and display
	if ((filterName.empty() || ruleName == filterName) && //is the filter empty -yes then true ( filter is not done by name) .. if not empty is it an exact match then true
		(filterAppName.empty() || ruleAppName == filterAppName) && // if empty filter not done by app, if not then check for amtch between filter appname and ruleappname
		(filterPort.empty() || localPorts.find(filterPort) != std::wstring::npos || remotePorts.find(filterPort) != std::wstring::npos) && //partial matches... if contained anywhere it will match 
		(filterIP.empty() || localIPs.find(filterIP) != std::wstring::npos || remoteIPs.find(filterIP) != std::wstring::npos)) { //partial matches
		//print it out 
		std::wcout << L"Rule Name: " << ruleName << std::endl;
		std::wcout << L"Application Name: " << ruleAppName << std::endl;
		std::wcout << L"Local Ports: " << localPorts << std::endl;
		std::wcout << L"Remote Ports: " << remotePorts << std::endl;
		std::wcout << L"Local IP Addresses: " << localIPs << std::endl;
		std::wcout << L"Remote IP Addresses: " << remoteIPs << std::endl;
	}
}
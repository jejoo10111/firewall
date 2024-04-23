#include "Firewall.h"

//convert utf8 to wide 
//had to be done for the main command and return statement and getting info onthe firewall
std::wstring ConvertUTF8ToWide(const std::string& utf8Str)
{
	//is input empty 
	if (utf8Str.empty()) return std::wstring();

	//determine count/size of wide string to hold string
	int count = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, nullptr, 0);
	//if count is 0 the faield to convert
	if (count == 0) return std::wstring();

	//create wide string appropriate length 
	std::wstring wide(count - 1, L'\0');
	//perform conversion from utf-8 to wide 
	MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), -1, &wide[0], count);

	//return wuide 
	return wide;
}

//convert variant to dispaatch for pointer var 
//for COM programming 
//to convert properly for com interactions
HRESULT ConvertVariantToDispatch(VARIANT* pVar) {
	HRESULT hr = VariantChangeType(pVar, pVar, 0, VT_DISPATCH);
	return hr;
}


int main(int argc, char* argv[]){

	//com variables
	HRESULT hrComInit = S_OK;
	HRESULT hr = S_OK;

	//store the number of items fetched 
	ULONG cFetched = 0;
	//variant data 
	CComVariant var;

	////intergace drive for querying
	IUnknown* pEnumerator;
	//for enumerations 
	IEnumVARIANT* pVariant = NULL;

	//firewall settings
	INetFwPolicy2* pNetFwPolicy2 = NULL;
	INetFwRules* pFwRules = NULL;
	INetFwRule* pFwRule = NULL;

	//hold firewall rules 
	long fwRuleCount;
	//string declaration
	std::wstring filterName, filterAppName, filterPort, filterIP;



	// Initialize COM.
	hrComInit = CoInitializeEx(
		0,
		COINIT_APARTMENTTHREADED
	);

	//if command incomplete call message
	if (argc < 2) {
		mainCALL();
		return 1;
	}

	//is firewall enabled
	if (strcmp(argv[1], "--Enable") == 0)
	{
		if (FireWall_IsEnable())
			cout << "Firewall is ON" << endl;
		else
			cout << "Firewall is OFF" << endl;
	}

	//turn firewall on 
	if (strcmp(argv[1], "--ON") == 0)
	{
		FireWall_TurnOn();
		return 0;
	}
	
	//turn firewall off
	if (strcmp(argv[1], "--OFF") == 0)
	{
		FireWall_TurnOff();
		return 0;
	}
	
	//does the firewall rule exist, is it enabled or disabled
	if (argc > 2 && strcmp(argv[1], "--Rules") == 0)
	{
		// Convert argv[2] to wide string
		//convert char* to wchar_t* using std::wstring_convert and std::codecvt_utf8<wchar_t>
		//character encoding
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		std::wstring wideType = converter.from_bytes(argv[2]);
		const wchar_t* ruleName = wideType.c_str();
		bool isEnabled = IsFirewallRuleEnabled(ruleName);

		//if enabled print 
		if (isEnabled == true)
			std::wcout << L"The rule '" << ruleName << L"' exists and is " << (isEnabled ? L"enabled" : L"disabled") << std::endl;
		else
			//error statement
			std::wcerr << L"Rule not found or does not exist " << std::endl;
		return 0;
	}

	//adding a firewall for an application
	if (strcmp(argv[1], "--ADD") == 0)
	{
		//initialization
		wstring name;
		wstring filePath;
		wstring localAddy;
		wstring remoteAddy;
		wstring port = L"Default Port";
		wstring description = L"Default Description";
		wstring group = L"Default Group";

		//initialization of firewall rule properties with defaults
		NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_OUT;
		NET_FW_PROFILE_TYPE2_ profileType = NET_FW_PROFILE2_ALL;
		NET_FW_IP_PROTOCOL_ protocol = NET_FW_IP_PROTOCOL_ANY;
		NET_FW_ACTION_ action = NET_FW_ACTION_ALLOW;

		//make sure its over 3 arguments to create a new firewall
		if (argc < 3) {
			addCall();
			return 1;
		}

		// Output initial values
		// wcout << L"Initial port: " << port << endl;

		//if arguments are correct in command prompt continue 
		//check every 2 at a time ... the command should check for the value after the switch
		for (int i = 2; i < argc; i += 2) {

			//if the value is an odd value as in there is no value after the switch call the message
			if (i + 1 >= argc) {
				addCall();
				return 1;
			}

			//conversion from byte string to wstring
			wstring arg = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(argv[i]);
			wstring val = wstring_convert<codecvt_utf8<wchar_t>>().from_bytes(argv[i + 1]);

			///checking against the switches
			if (arg == L"-n") 
				name = val;

			else if (arg == L"-f") 
				filePath = val;

			else if (arg == L"-d") 
				description = val;

			else if (arg == L"-g") 
				group = val;

			else if (arg == L"-s")
				port = val;

			else if (arg == L"-il")
				localAddy = val;

			else if (arg == L"-ir")
				remoteAddy = val;

			// direction variable
			else if (arg == L"-r") {
				 // inbound rule (coming in) and outbound rule (going out)
				if (val == L"in")
					direction = NET_FW_RULE_DIR_IN;

				else
					direction = NET_FW_RULE_DIR_OUT;

			}

			//choose which profile you want the firewall on 
			else if (arg == L"-p") {

				if (val == L"domain") 
					profileType = NET_FW_PROFILE2_DOMAIN;

				else if (val == L"private") 
					profileType = NET_FW_PROFILE2_PRIVATE;

				else if (val == L"public") 
					profileType = NET_FW_PROFILE2_PUBLIC;

				else 
					profileType = NET_FW_PROFILE2_ALL;
			}

			//the protcol only check for tcp and udp
			else if (arg == L"-l") {

				if (val == L"tcp") 
					protocol = NET_FW_IP_PROTOCOL_TCP;

				else if (val == L"udp") 
					protocol = NET_FW_IP_PROTOCOL_UDP;

				else 
					protocol = NET_FW_IP_PROTOCOL_ANY;

			}

			//allow and deny 
			else if (arg == L"-a") {
				
					// allow and deny application
					if (val == L"allow")
						action = NET_FW_ACTION_ALLOW;

					else
						action = NET_FW_ACTION_BLOCK;

			}
		}
		// Output final values
		// wcout << L"Final port: " << port << endl;

		//call the adding function
		if (Firewall_Add_Application(name.c_str(), filePath.c_str(), description.c_str(),
			group.c_str(), port.c_str(), localAddy.c_str(), remoteAddy.c_str(), direction, profileType, protocol, action)) {

			wcout << L"Firewall rule added successfully." << endl;
			return 0;
		}

		else {

			wcerr << L"Failed to add firewall rule." << endl;
			return -1;

		}

	}

	//enumerate through the firewall rules
	if (strcmp(argv[1], "--Enumerate") == 0) {

		// Ignore RPC_E_CHANGED_MODE; this just means that COM has already been
	// initialized with a different mode. Since we don't care what the mode is,
	// we'll just use the existing mode.
		if (hrComInit != RPC_E_CHANGED_MODE)
		{
			if (FAILED(hrComInit))
			{
				wprintf(L"CoInitializeEx failed: 0x%08lx\n", hrComInit);
				goto Cleanup;
			}
		}

		// Retrieve INetFwPolicy2
		hr = Firewall_initialize(&pNetFwPolicy2);
		if (FAILED(hr))
		{
			goto Cleanup;
		}

		// Retrieve INetFwRules
		hr = pNetFwPolicy2->get_Rules(&pFwRules);
		if (FAILED(hr))
		{
			wprintf(L"get_Rules failed: 0x%08lx\n", hr);
			goto Cleanup;
		}

		// Obtain the number of Firewall rules
		hr = pFwRules->get_Count(&fwRuleCount);
		if (FAILED(hr))
		{
			wprintf(L"get_Count failed: 0x%08lx\n", hr);
			goto Cleanup;
		}

		wprintf(L"The number of rules in the Windows Firewall are %d\n", fwRuleCount);

		// Iterate through all of the rules in pFwRules
		pFwRules->get__NewEnum(&pEnumerator);

		if (pEnumerator)
		{
			hr = pEnumerator->QueryInterface(__uuidof(IEnumVARIANT), (void**)&pVariant);
		}

		while (SUCCEEDED(hr) && hr != S_FALSE)
		{
			var.Clear();
			hr = pVariant->Next(1, &var, &cFetched);

			if (S_FALSE != hr)
			{
				if (SUCCEEDED(hr))
				{
					hr = var.ChangeType(VT_DISPATCH);
				}
				if (SUCCEEDED(hr))
				{
					hr = (V_DISPATCH(&var))->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&pFwRule));
				}

				if (SUCCEEDED(hr))
				{
					// Output the properties of this rule
					FWRuleEnumerate(pFwRule);
				}
			}
		}

	Cleanup:

		// Release pFwRule
		if (pFwRule != NULL)
		{
			pFwRule->Release();
		}

		// Release INetFwPolicy2
		if (pNetFwPolicy2 != NULL)
		{
			pNetFwPolicy2->Release();
		}

		// Uninitialize COM.
		if (SUCCEEDED(hrComInit))
		{
			CoUninitialize();
		}

		return 0;

	}

	//filter the fireawll
	if (strcmp(argv[1], "--Filter") == 0) {
		if (argc < 3) {
			FilterCall();
			return 1;
		}

		for (int i = 1; i < argc; i += 2) {

			std::string arg = argv[i];

			if (i + 1 < argc) {
				if (arg == "--name") {
					filterName = ConvertUTF8ToWide(argv[i + 1]);
				}

				else if (arg == "--AName") {
					filterAppName = ConvertUTF8ToWide(argv[i + 1]);
				}

				/*else if (arg == "--Lport") {
					filterLocalPort = ConvertUTF8ToWide(argv[i + 1]);
				}

				else if (arg == "--Rport") {
					filterRemotePort = ConvertUTF8ToWide(argv[i + 1]);
				}

				else if (arg == "--LIP") {
					filterLocalAddy = ConvertUTF8ToWide(argv[i + 1]);
				}

				else if (arg == "--RIP") {
					filterRemoteAddy = ConvertUTF8ToWide(argv[i + 1]);
				}
				*/
				else if (arg == "--port") {
					filterPort = ConvertUTF8ToWide(argv[i + 1]);
				}
				else if (arg == "--ip") {
					filterIP = ConvertUTF8ToWide(argv[i + 1]);
				}

			}
		}

		//access to firewall policy
		INetFwPolicy2* pNetFwPolicy2 = NULL;
		IEnumVARIANT* pVariant = NULL;
		hr = Firewall_initialize(&pNetFwPolicy2);

		//get firewall rules
		CComPtr<INetFwRules> pFwRules;
		hr = pNetFwPolicy2->get_Rules(&pFwRules);
		if (FAILED(hr)) {
			std::wcerr << L"get_Rules failed: " << std::hex << hr << std::endl;
			goto Cleanup1;
		}

		//iterate through rules
		pFwRules->get__NewEnum(reinterpret_cast<IUnknown**>(&pVariant));
		if (pVariant) {
			VARIANT var; //enumeration
			VariantInit(&var);
			while (pVariant->Next(1, &var, NULL) == S_OK) {

				CComPtr<INetFwRule> pFwRule; //release object when pFwRule is not there 
				//variant check 
				if (V_VT(&var) == VT_DISPATCH) { //querying 
					//does var have dispatch .... then query 
					//querying for specific object 
					V_DISPATCH(&var)->QueryInterface(__uuidof(INetFwRule), (void**)&pFwRule);
					//if call was successful query 
					if (pFwRule) {
						DumpFilter(pFwRule, filterName, filterAppName, filterPort, filterIP); //filtering 
					} 
				}
				//clean
				VariantClear(&var);
			}
		}

	Cleanup1:
		if (pNetFwPolicy2) pNetFwPolicy2->Release();
		CoUninitialize();
		return 0;
	}

		return 0;

}
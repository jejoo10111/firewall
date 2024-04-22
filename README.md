# IPS/IDS Firewall Project

## Description:

This project was created to develop an intrusion detection/prevention system for your machine. I have created a program that will assist in the modifications to your native Windows Firewall environment. 

This is a C++ build for your native Windows Firewall environment. There are two main components to this repo: the **firewall.exe** and the **pcapFirewall.exe**. 

The **firewall.exe** does simple modifications to your firewall through the command prompt. It checks to see if the firewall is enabled, turn the firewall on/off, check for rules, enumerate the list of firewall rules, filtering rules, and add rules.

The **pcapFirewall.exe** reads an already created pcap file and is used to do analysis on. For instance, reading the pcap file per packet, signature detection for certain packets (most already hard-coded in), and ip address block and allowing. 

## Updates for the Future

There are a few updates that need to be made to this tool for it to function appropriately and efficiently: 

1. The **firewall.exe** "--Filter" switch does not read for the "Name of the Firewall". It does partial matches and exact matches for the "Rule Name" of the Rule. To further explain, some rules do not come with a name to their "Rule Name". Sometimes the name of the Rule depends on the local address name etc.
2. The **pcapFirewall.exe** currently only blocks and allows IP addresses. There are no switches that specify more. But this can be done in more depth with the **firewall.exe**.
3. The **pcapFirewall.exe** looks at only certain signatures: GET requests, magic numbers, and IP addresses.
   
## How To SetUp Environment

This project was written and tested on a Windows 11 Home.

This project can be used by simply downloading the executables of the **pcapFirewall.exe** and the **firewall.exe**.

### Installations

This project does require a few libraries and extensions:

The Windows environment for this script has utilized the Windows SDK, Npcap SDK and the "Ws2_32.lib".

#### Windows SDK Integration 

This is a setup f the visual studio environment

1. Check for fwpuclnt.lib and Corresponding Lib

2. Verify Windows SDK Installation
Check that the Windows SDK is properly installed:

Open the Visual Studio Installer.
Choose to modify your installation.
Ensure the appropriate Windows SDK is selected under the "Individual components"

3. Include fwpuclnt.lib in Your Project
If you are using functions from the Windows Firewall API, make sure to include the correct library:

Go to your project's properties
Navigate to Linker -> Input.
Add fwpuclnt.lib to the Additional Dependencies field.

4. Search for the Library
You can manually search for fwpuclnt.lib to confirm it exists

6. Set Library and Include Paths

Go to Project Properties -> VC++ Directories.


#### Npcap Installation
1. Visit the Npcap website: Go to the Npcap website (https://npcap.org/) in your web browser.
2. Navigate to the Downloads section: Look for a "Downloads" or "Get Npcap" section on the website.
3. Download the SDK: Within the downloads section, there should be an option to download the Npcap SDK.
4. Install the SDK: Once the download is complete, run the installer. 
5. Integration with Visual Studio: After installing the SDK, it should integrate with Visual Studio Community automatically. You may need to restart Visual Studio for the changes to take effect.
6. Documentation and Examples: The Npcap SDK typically comes with documentation and examples to help you get started with integrating it into your Visual Studio projects. Look for these resources in the installation directory or on the Npcap website.

If you are accessing the script through visual studi code, the below link is the link I used to help setup the Npcap SDK into my libraries:
- https://stackoverflow.com/questions/59826342/how-do-you-install-npcap-library-into-visual-studio

#### ws2_32.lib
Integrate ws2_32.lib into libraries : 

For Visual Studio: 
Go to Project Properties -> Configuration Properties -> Linker -> Input, then add Ws2_32.lib to the Additional Dependencies field.

- Make sure you locate the Ws2_32.lib library for Visual Studio 

## How to Start

Once the executables are downloaded, you simply need to know the location of the executable. 

Open an Administrative Command Prompt and either navigate to the location of the executable or drag the location of the executable to your command prompt. To execute the switches properly scroll to the **FEATURES** section of this README.

## Features

The features in this tool are discussed below. An example to utilize the command for these switches are also provided. Whitespace is needed after each switch after the switch.
commands can be written as : [Name of Executable] [command] [options] 

**pcapFirewall.exe Features**
Usage: firewall.exe file <pcap file> [options]
--GET          Filtering for the HTTP GET request in pcap file
--magic        Filtering for the magic numbers in the pcap file
--ipA          Filtering for a specific ip address in a pcap file
--block        Block ip address and add to firewall rules
--allow        Allow ip address and add to firewall rules

**firewall.exe Features**

Usage: firewall.exe [options]
Options:
--Enable							 Check to see if firewall is enabled for current profile
--ON							    Turn on firewall settings
--OFF						   	 Turn off firewall settings
--Rules                     Check to see if the rule exists
--Enumerate					    List out all the firewall rules that exist on the system
--Filter							 Filter the rules by Rule Name, Path of the Application, Port Number, IP Address
--ADD <options>				 Add a firewall rule

Usage: firewall.exe --ADD -n <name> -f <file_path> [options]
Options:
-d <description>           Description of the rule
-g <group>                 Group name
-r <direction>             Rule direction (in/out)
-p <profile>               Profile type (domain/private/public/all)
-l <protocol>              Protocol (tcp/udp/any)
-a <action>                Action (allow/block)
-s <ports>                 Ports (integer value)
-il <local ip address>     Local Ip address value
-ir <remote ip address>    Remote Ip address value

Usage: firewall.exe --Filter --name [name] --Aname [application path] [options]
Options:
--name           Name of the rule
-AName           Path of Application
--port           port number
--ip             ip address

## Credits

This project was assigned to me by Gordon Long at George Mason University for my Digital Forensics class. 

### References
Here are a list of resources that I have used that have assisted me in the creation of this project:
1. 




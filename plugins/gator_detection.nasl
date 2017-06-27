#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11998);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");

 script_name(english:"GATOR Detection");
 script_summary(english:"GATOR detection");

 script_set_attribute(attribute:"synopsis", value:"The remote host has an application installed for storing passwords.");
 script_set_attribute(attribute:"description", value:
"The remote host is using the GATOR program. You should ensure that the
user intended to install GATOR, as it is sometimes silently installed.");
 script_set_attribute(attribute:"solution", value:
"Uninstall this software if it does not agree with your corporate
security policies.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("audit.inc");

# start the script

path[0] = "software\classes\interface\{06dfeda9-6196-11d5-bfc8-00508b4a487d}";

path[1] = "software\classes\interface\{38493f7f-2922-4c6c-9a9a-8da2c940d0ee}";

path[2] = "software\classes\kbbar.kbbarband\clsid";

path[3] = "software\gatortest";

path[4] = "software\microsoft\windows\currentversion\stashedgef";

path[5] = "software\microsoft\windows\currentversion\app management\arpcache\gator";

path[6] = "software\microsoft\windows\currentversion\run\trickler";

path[7] = "software\microsoft\windows\currentversion\uninstall\gator";

path[8] = "software\microsoft\windows\currentversion\uninstall\{456ba350-947f-4406-b091-aa1c6678ebe7}";

path[9] = "software\microsoft\windows\currentversion\uninstall\{6c8dbec0-8052-11d5-a9d5-00500413153c}";


if ( ! get_kb_item("SMB/registry_access") ) exit(0);


port = kb_smb_transport();
#if(!port || ! get_port_state(port) )exit(0);

name = kb_smb_name ();
if (!name) exit(0);

login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

#soc = open_sock_tcp(port);
#if(!soc) exit(0);

#session_init(socket:soc, hostname:kb_smb_name());
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 NetUseDel();
 exit(0);
}

for (i=0; path[i]; i++) {
       key_h = RegOpenKey(handle:handle, key:path[i], mode:MAXIMUM_ALLOWED);
       if ( !isnull(key_h) )
       {
         RegCloseKey(handle:key_h);
         RegCloseKey(handle:handle);
	 security_warning(kb_smb_transport());
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();


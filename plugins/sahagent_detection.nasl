#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12000);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");
 script_name(english:"SAHAGENT Detection");
 script_summary(english:"SAHAGENT detection");

 script_set_attribute(attribute:"synopsis", value:"A spyware is running on this host.");
 script_set_attribute(attribute:"description", value:
"The remote host is using the SAHAGENT program. You should ensure that
:

- the user intended to install SAHAGENT (it is sometimes
    silently
    installed)
    - the use of SAHAGENT matches your Corporate mandates
    and Security
    Policies.

To remove this sort of software, you may wish to check out ad-aware or
spybot.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59ee10b3");
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/securityadvisor/pest/pest.aspx?id=453076082" );
 script_set_attribute(attribute:"solution", value:"Uninstall this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies( "smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");

 script_require_ports(139, 445);
 exit(0);
}


# start the script
include("smb_func.inc");
include("audit.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(0);

path[0] = "software\classes\clsid\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[1] = "software\classes\interface\{4828c95f-c5db-4ab6-a945-8d8ec44b98a8}";
path[2] = "software\classes\interface\{4e570f74-deee-4fcf-b960-feefa4b8c6fc}";
path[3] = "software\microsoft\code store database\distribution units\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[4] = "software\microsoft\windows\currentversion\moduleusage\c:/winnt/downloaded program files/lsp_.dll\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[5] = "software\microsoft\windows\currentversion\moduleusage\c:/winnt/downloaded program files/sahagent_.exe\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[6] = "software\microsoft\windows\currentversion\moduleusage\c:/winnt/downloaded program files/sahdownloader_.exe\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[7] = "software\microsoft\windows\currentversion\moduleusage\c:/winnt/downloaded program files/sahuninstall_.exe\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[8] = "software\microsoft\windows\currentversion\moduleusage\c:/winnt/downloaded program files/sporder_.dll\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[9] = "software\microsoft\windows\currentversion\moduleusage\c:/winnt/downloaded program files/webinstaller.dll\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[10] = "software\microsoft\windows\currentversion\moduleusage\c:/winnt/downloaded program files/xmlparse_.dll\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[11] = "software\microsoft\windows\currentversion\moduleusage\c:/winnt/downloaded program files/xmltok_.dll\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[12] = "software\microsoft\windows\currentversion\moduleusage\c:/winnt/system32/mfc42.dll\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[13] = "software\microsoft\windows\currentversion\moduleusage\c:/winnt/system32/msvcrt.dll\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[14] = "software\microsoft\windows\currentversion\moduleusage\c:/winnt/system32/olepro32.dll\{30402ff4-3e71-4a1c-9b4b-1cd3486a9fb2}";
path[15] = "software\microsoft\windows\currentversion\run\sahagent";
path[16] = "software\vgroup";


port = kb_smb_transport();


login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
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
	 security_hole(port);
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();

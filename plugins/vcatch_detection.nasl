#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(12004);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2015/01/12 17:12:49 $");

 script_name(english:"VCATCH Spyware Detection");
 script_summary(english:"VCATCH detection");

 script_set_attribute(attribute:"synopsis", value:"The spyware appears to be installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is using the VCATCH program. You should ensure that :

- the user intended to install VCATCH (it is sometimes
    silently installed)
    - the use of VCATCH matches your corporate mandates and
    security policies.

To remove this sort of software, you may wish to check out ad-aware or
spybot.");
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/securityadvisor/pest/pest.aspx?id=453086263");
 script_set_attribute(attribute:"solution", value:"Uninstall this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_dependencies("smb_registry_full_access.nasl");
 script_require_keys("SMB/registry_full_access");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("audit.inc");

# start the script
if ( ! get_kb_item("SMB/registry_full_access") ) exit(0);

path[0] = "software\microsoft\windows\currentversion\app management\arpcache\vcatch - the personal virus catcher";
path[1] = "software\microsoft\windows\currentversion\uninstall\vcatch - the personal virus catcher";

port = get_kb_item("SMB/transport");
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(0);
}


key = "Software\Microsoft\Windows NT\WinLogon";
item = "DontDisplayLastUserName";

for (i=0; path[i]; i++)
{
 key_h = RegOpenKey(handle:hklm, key:path[i], mode:MAXIMUM_ALLOWED);
 if ( ! isnull(key_h) )
 {
  security_hole(port);
  RegCloseKey(handle:key_h);
  break;
 }
}

RegCloseKey(handle:hklm);
NetUseDel();


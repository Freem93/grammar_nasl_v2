#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(12006);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_name(english:"Web3000 Detection");
  script_summary(english:"Web3000 detection");

  script_set_attribute(attribute:'synopsis', value:"The remote software is potentially unwanted and considered spyware.");

  script_set_attribute(attribute:'description', value:
"The remote host is using the Web3000 program. You should ensure that :

  - the user intended to install Web3000 (it is sometimes
    silently installed)
    - the use of Web3000 matches your corporate mandates and
    security policies.");

  script_set_attribute(attribute:'solution', value:"Uninstall this software.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:'see_also', value:"http://www.ca.com/securityadvisor/pest/pest.aspx?id=6689");


 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("smb_registry_full_access.nasl");
  script_require_keys("SMB/registry_full_access");

  script_require_ports(139, 445);
  exit(0);
}


# start the script
include('smb_func.inc');
include('audit.inc');
if ( ! get_kb_item("SMB/registry_full_access") ) exit(0);

path[0] = "software\microsoft\windows\currentversion\stashedgmg";
path[1] = "software\microsoft\windows\currentversion\stashedgmi";
path[2] = "software\microsoft\windows\currentversion\run\w3knetwork";
path[3] = "software\microsoft\windows\currentversion\uninstall\textwiz_is1";
path[4] = "software\microsoft\windows\currentversion\uninstall\web3000";
path[5] = "software\microsoft\windows\currentversion\uninstall\xtractor";
path[6] = "software\web3000.com";


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


for (i=0; path[i]; i++)
{
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

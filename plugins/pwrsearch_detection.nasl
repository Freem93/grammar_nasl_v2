#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12018);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2017/04/25 20:29:05 $");

 script_name(english:"POWER SEARCH Detection");
 script_summary(english:"POWER SEARCH detection");

 script_set_attribute(attribute:"synopsis", value:"A spyware is installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is using the POWER SEARCH program. You should ensure
that : - the user intended to install POWER SEARCH (it is sometimes
silently installed) - the use of POWER SEARCH matches your corporate
mandates and security policies.

To remove this sort of software, you may wish to check out ad-aware or
Spybot.");
 script_set_attribute(attribute:"solution", value:"Uninstall this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

# start the script

include("audit.inc");
include("smb_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");

path[0] = "SOFTWARE\classes\clsid\{4e7bd74f-2b8d-469e-d3fa-f27ba787ad2d}";
path[1] = "SOFTWARE\microsoft\internet explorer\toolbar\{4e7bd74f-2b8d-469e-d3fa-f27ba787ad2d}";


port = kb_smb_transport();
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


for (i=0; path[i]; i++) {
       key_h = RegOpenKey(handle:handle, key:path[i], mode:MAXIMUM_ALLOWED);
       if ( !isnull(key_h) )
       {
         RegCloseKey(handle:key_h);
         RegCloseKey(handle:handle);
	 security_hole(kb_smb_transport());
	 NetUseDel();
	 exit(0);
       }
}


RegCloseKey(handle:handle);
NetUseDel();

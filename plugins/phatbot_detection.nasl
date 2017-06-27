#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(12111);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/01/12 17:12:46 $");

 script_name(english:"PhatBOT Backdoor Detection");
 script_summary(english:"Checks if PhatBOT is installed.");

 script_set_attribute(attribute:"synopsis", value:"The remote host has a trojan installed.");

 script_set_attribute(attribute:"description", value:
"The remote systems appears to have PhatBOT installed. This program
allows the machine to be controlled via a P2P network. PhatBOT is
extremely sophisticated and allows the remote attacker to use the
victim machine to perform various actions.");

 script_set_attribute(attribute:"see_also", value:"http://www.secureworks.com/research/threats/phatbot");
 script_set_attribute(attribute:"solution", value:"Remove PhatBOT immediately.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/17");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

# start script

include("audit.inc");
include("smb_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1,"KB 'SMB/Registry/Enumerated' not set to TRUE.");

path[0] = "Software\Microsoft\Windows\CurrentVersion\Run\Generic Service Process";
path[1] = "Software\Microsoft\Windows\CurrentVersion\RunServices\Generic Service Process";

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

for (i=0; path[i]; i++)
{
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

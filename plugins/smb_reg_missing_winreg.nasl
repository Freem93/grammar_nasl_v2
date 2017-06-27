#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10431);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/12/09 21:04:55 $");

 script_name(english:"Microsoft Windows SMB Registry : Winreg Registry Key Detection");
 script_summary(english:"Determines if the winreg key is present");

 script_set_attribute(attribute:"synopsis", value:"Everyone can access the remote registry.");
 script_set_attribute(attribute:"description", value:
"The registry key
HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg is
missing.

This key allows you to define what can be viewed in the registry by
non administrators.");
 script_set_attribute(attribute:"solution", value:
"Install Service Pack 3 (SP3) if not done already, and create the
SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths
registry key. Under this key, create the value 'Machine' as a
REG_MULTI_SZ and put in it what you allow to be browsed remotely.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/library/cc749939.aspx");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/29");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl","smb_reg_service_pack.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password","SMB/registry_full_access");
 script_exclude_keys("SMB/Win2K/ServicePack");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("smb_func.inc");

access = get_kb_item("SMB/registry_access");
if(!access)exit(0, "Registry not accessible.");

version = get_kb_item("SMB/WindowsVersion");
if(!version)exit(0, "Failed to get Windows version.");
# false positive on win2k - they must protect it or something - mss
if(egrep(pattern:"^5.",string:version))exit(0);


#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
 NetUseDel();
 audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 audit(AUDIT_REG_FAIL);
}

key = "SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths";
item = "Machine";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (isnull (value))
  security_warning(port);

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();

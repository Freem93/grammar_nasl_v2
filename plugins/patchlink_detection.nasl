#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#
# Tenable grants a special exception for this plugin to use the library
# 'smb_func.inc'. This exception does not apply to any modified version of
# this plugin.
#
#


include("compat.inc");

if (description)
{
 script_id(19944);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2015/01/12 17:12:46 $");

 script_name(english:"Patchlink Detection");
 script_summary(english:"Checks for the presence of Patchlink");

 script_set_attribute(attribute:"synopsis", value:"The remote host has a patch management software installed on it.");
 script_set_attribute(attribute:"description", value:
"This script uses Windows credentials to detect whether the remote host
is running Patchlink and extracts the version number if so.

Patchlink is a fully Internet-based, automated, cross-platform,
security patch management system.");
 script_set_attribute(attribute:"see_also", value:"http://www.patchlink.com/");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/06");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"Copyright (C) 2005-2015 Josh Zlatin-Amishav and Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");

 script_require_ports(139, 445);
 exit(0);
}


include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");

get_kb_item_or_exit("SMB/registry_access");

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = "SOFTWARE\PatchLink\Agent Installer";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( isnull(key_h))
{
  key = "SOFTWARE\PatchLink\Update Agent";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( isnull(key_h)) debug_print("no key");
}
if ( ! isnull(key_h) )
{
 item = "Version";
 array = RegQueryValue(handle:key_h, item:item);
 version = array[1];
 debug_print(version );
 RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

if ( ! isnull(version) )
{
  info = string("Patchlink version ", version, " is installed on the remote host.");

  security_note(port:port, extra: info);

  set_kb_item(name:"SMB/Patchlink/version", value:version);
}


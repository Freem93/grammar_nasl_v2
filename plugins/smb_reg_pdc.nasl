#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10413);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/01/12 17:12:48 $");

 script_name(english:"Microsoft Windows SMB Registry : Remote PDC/BDC Detection");
 script_summary(english:"Determines if the remote host is a PDC/BDC");

 script_set_attribute(attribute:"synopsis", value:"The remote system is a Domain Controller.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be a Primary Domain Controller or a Backup
Domain Controller.

This can be verified by the value of the registry key 'ProductType'
under 'HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions'.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/20");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("smb_func.inc");

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


key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
item = "ProductType";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value) && (value[1] == "LanmanNT"))
   security_note (port);

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();

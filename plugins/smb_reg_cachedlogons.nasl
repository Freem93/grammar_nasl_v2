#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11457);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/06/24 19:43:56 $");

 script_name(english:"Microsoft Windows SMB Registry : Winlogon Cached Password Weakness");
 script_summary(english:"Determines the value of a remote key.");

 script_set_attribute(attribute:"synopsis", value:
"User credentials are stored in memory.");
 script_set_attribute(attribute:"description", value:
"The registry key 'HKLM\Software\Microsoft\WindowsNT\CurrentVersion\
Winlogon\CachedLogonsCount' is non-NULL. Using a non-NULL value for
the CachedLogonsCount key indicates that the remote Windows host
locally caches the passwords of the users when they login, in order to
continue to allow the users to login in the case of the failure of the
primary domain controller (PDC).");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/cc957390.aspx");
 script_set_attribute(attribute:"solution", value:
"Use regedt32 and set the value of this registry key to 0.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/24");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);

 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");

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

value = "";
key = "Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
item = "CachedLogonsCount";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel ();

if (!empty_or_null(value) && (value[1] != 0))
{
  report =
    '\n  Max cached logons : ' + value[1] + '\n'; 
  security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
}


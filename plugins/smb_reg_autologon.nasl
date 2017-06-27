#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10412);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/12/09 21:04:55 $");

 script_name(english:"Microsoft Windows SMB Registry : Autologon Enabled");
 script_summary(english:"Determines if the autologon feature is installed");

 script_set_attribute(attribute:"synopsis", value:"Anyone can logon to the remote system.");
 script_set_attribute(attribute:"description", value:
"This script determines whether the autologon feature is enabled. This
feature allows an intruder to log into the remote host as
DefaultUserName with the password DefaultPassword.");
 script_set_attribute(attribute:"solution", value:
"Delete the keys AutoAdminLogon and DefaultPassword under
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/315231");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/20");

 script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

#

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


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 username = RegQueryValue(handle:key_h, item:"DefaultUserName");
 password = RegQueryValue(handle:key_h, item:"DefaultPassword");
 autologon = RegQueryValue(handle:key_h, item:"AutoAdminLogon");

 if ((!isnull(autologon) &&  (autologon[1] =~ "^[ \t]*0*[1-9]")) &&
     (!isnull (username) && (username[1] != "")) &&
      !isnull(password) )
 {
  cleaned = substr(password[1],0,0)
          + crap(data:"*", 6)
          + substr(password[1], (strlen(password[1])-1));
  rep = 'Autologon is enabled on this host.\n' +
        "This allows an attacker to access it as " + username[1] + "/" + cleaned +
        '\n\nNote: The password displayed has been partially obfuscated.';

  security_hole(port:port, extra:rep);
 }

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();

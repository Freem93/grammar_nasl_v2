#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10449);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2016/12/09 21:04:55 $");

 script_name(english:"Microsoft Windows SMB Registry : SFCDisable Key Permission Weakness");
 script_summary(english:"Determines the value of SFCDisable");

 script_set_attribute(attribute:"synopsis", value:"Local users have full privileges on the remote host.");
 script_set_attribute(attribute:"description", value:
"The registry key HKLM\SOFTWARE\Microsoft\Windows
NT\WinLogon\SFCDisable has its value set to a value other than 0 or 4.

Any value other than 0 or 4 disables the Windows File Protection,
which allows any user on the remote host to view / modify any file he
wants.

This probably means that this host has been compromised.");
 script_set_attribute(attribute:"solution", value:"Set the value of this key to 0. You should reinstall this host");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 #https://web.archive.org/web/20060212232908/http://archives.neohapsis.com/archives/ntbugtraq/2000-q2/0296.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b1b4a46");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/q222473/" );

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/06/26");

 script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

#

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

# from http://www.bitsum.com/aboutwfp.htm
# "Microsoft didn't appreciate this discovery and added code
# to jump around the check for this value in Windows 2000 SP1"
if (hotfix_check_sp(win2k:1) <= 0)
  exit(0, 'Host is not affected based on its version / service pack.');

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


key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon";
item = "SFCDisable";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);

 # 0 = enabled
 # 4 = enabled, popup disabled
 if (!isnull (value) && (value[1] != 0) && (value[1] != 4))
   security_hole(port);

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();

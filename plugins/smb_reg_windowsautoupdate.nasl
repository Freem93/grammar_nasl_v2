#
# (C) Tenable Network Security, Inc.
#

# Thanks to Greg Hoglund <hoglund@hbgary.com> for suggesting this.
#


include("compat.inc");

if (description)
{
 script_id(12028);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/01/12 17:12:49 $");

 script_name(english:"Microsoft Windows SMB : WindowsUpdate Disabled");
 script_summary(english:"Determines the value of AUState/AUoptions");

 script_set_attribute(attribute:"synopsis", value:"Remote system is not configured for automatic updates.");
 script_set_attribute(attribute:"description", value:
"The remote host does not have Windows Update enabled.

Enabling WindowsUpdate will ensure that the remote Windows host has
all the latest Microsoft Patches installed.");
 script_set_attribute(attribute:"solution", value:"Enable Windows Update on this host");
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/security/protect/");
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/328010" );
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/01/22");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

#

include("audit.inc");
include("global_settings.inc");
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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update";
audit = NULL;
austate = NULL;
auoptions = NULL;
info = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
  value = RegQueryValue(handle:key_h, item:"AUState");
  if (!isnull (value))
  {
    if (value[1] == 7)
    {
      austate = value[1];
      info +=  "HKEY_LOCAL_MACHINE" + '\\' + key + '\\AUState : '  + austate + '\n';
    }
    else audit = 'Windows Update is enabled';
  }

  value = RegQueryValue(handle:key_h, item:"AUOptions");
  if (!isnull (value))
  {
    if (value[1] == 1)
    {
      auoptions = value[1];
      info +=  "HKEY_LOCAL_MACHINE" + '\\' + key + '\\AUOptions : '  + auoptions + '\n';
    }
    else audit = 'Windows Update is enabled';
  }

  RegCloseKey (handle:key_h);
}

# Look at another key, referenced by KB #328010

key = "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";

auoptions2 = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
  value = RegQueryValue(handle:key_h, item:"AUOptions");
  if (!isnull (value))
  {
    auoptions2 = value[1];
    if (auoptions2 == 1)
    {
      info +=  "HKEY_LOCAL_MACHINE" + '\\' + key + '\\AUOptions : '  + auoptions2 + '\n';
    }
    else if (auoptions2 == 2)
    {
      audit = 'Windows Update is configured to notify of update download and installation';
    }
    else if (auoptions2 == 3)
    {
      audit = 'Windows Update is configured to automatically download updates and notify of installation';
    }
    else if (auoptions2 == 4)
    {
      audit = 'Windows Update is configured to automatically download and install updates';
    }
  }

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();

if(!isnull(info) && (isnull(auoptions2) || auoptions2 == 1))
{
  if(report_verbosity > 0)
  {
   report = string("\n",
     "Nessus determined 'Automatic Updates' are disabled based","\n",
     "on the following registry setting(s) :","\n\n",
     info);
    security_note(port:port,extra:report);
  }
  else security_note(port);
  exit(0);
}
if (!isnull(audit))
{
  exit(0, 'The host is not affected because '+audit+'.');
}
else
{
  exit(1, 'Can\'t determine the status of Windows Update');
}

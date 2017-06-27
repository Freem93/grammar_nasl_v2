#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35453);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/01/12 17:12:48 $");

  script_name(english:"Microsoft Windows Update Reboot Required");
  script_summary(english:"Checks registry");

 script_set_attribute(attribute:"synopsis", value:"The remote Windows host requires a reboot.");
 script_set_attribute(attribute:"description", value:
"According to entries in its registry, a reboot is required by Windows
Update to complete installation of at least one update. If the pending
changes are security-related, the remote host could remain vulnerable
to attack until a reboot occurs.");

 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/cc960241.aspx");
 script_set_attribute(attribute:"solution", value:"Reboot the remote system to put pending changes into effect.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/23");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("global_settings.inc");

if (!get_kb_item("SMB/Registry/Enumerated"))  exit(1,"The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Check registry entries.
reboot = FALSE;
reason = '';

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; ++i)
  {
    item = RegEnumValue(handle:key_h, index:i);
    if (!isnull(item) && item[1] =~ "^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
    {
      value = RegQueryValue(handle:key_h, item:item[1]);
      if (!isnull(value) && value[1] == 1)
      {
        reboot = TRUE;
        reason = "One or more applications have 'RebootRequired' flag set." + '\n';
        break;
      }
    }
  }
  RegCloseKey(handle:key_h);
}

if (report_paranoia > 1)
{
  key = "SYSTEM\CurrentControlSet\Control\Session Manager";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"PendingFileRenameOperations");
    if (!isnull(value))
    {
      reboot = TRUE;
      reason += "Registry key 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations' is set." ;
    }
  }
}

RegCloseKey(handle:hklm);
NetUseDel();

if (reboot)
{
 if(report_verbosity > 0 && reason)
 {
   report = '\n' +
     "Nessus determined a reboot is required based on the following info : " +
     '\n\n' +
     reason;
   security_hole(port:0,extra:report);
 }
 else
 security_hole(0);
}
else
 exit(0, "The remote host does not need to be rebooted.");

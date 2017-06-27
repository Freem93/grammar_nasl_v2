#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50859);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"Microsoft Windows SMB : WSUS Client Configured");
  script_summary(english:"Determines if a WSUS server is utilized");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is utilizing a WSUS server.");

  script_set_attribute(attribute:"description", value:
"The remote host is configured to utilize a Windows Server Update
Services (WSUS) server.");

  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/cc708554(WS.10).aspx");
  script_set_attribute(
    attribute:"see_also",
    value:"http://technet.microsoft.com/en-us/library/cc708449(WS.10).aspx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://technet.microsoft.com/en-us/magazine/gg153542.aspx"
  );
  script_set_attribute(attribute:"solution", value:
"Verify the remote host is configured to utilize the correct WSUS
server.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/registry_full_access", "SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/registry_full_access");

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm_handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm_handle))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

handle = RegOpenKey(handle:hklm_handle, key:"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", mode:MAXIMUM_ALLOWED);
use_wsus = FALSE;

# Check to see if the system is configured to use a WSUS server
if (!isnull(handle))
{
  # http://technet.microsoft.com/en-us/library/cc708554(WS.10).aspx
  # "Verify that the UseWUServer setting has a value of 1 (0x1)"
  value = RegQueryValue(handle:handle, item:"UseWUServer");
  if (!isnull(value)) use_wsus = value[1] == 1;

  # only close at this point if we're not going to do any further registry querying
  if (!use_wsus) RegCloseKey(handle:handle);
}

if (!use_wsus)
{
  RegCloseKey(handle:hklm_handle);
  NetUseDel();
  exit(0, 'The remote host is not configured to use WSUS.');
}

# Query the remaining automatic update configuration options
au_setting_names = make_list(
  "AUOptions",
  "AutoInstallMinorUpdates",
  "DetectionFrequency",
  "DetectionFrequencyEnabled",
  "NoAutoRebootWithLoggedOnUsers",
  "NoAutoUpdate",
  "RebootRelaunchTimeout",
  "RebootRelaunchTimeoutEnabled",
  "RebootWarningTimeout",
  "RebootWarningTimeoutEnabled",
  "RescheduleWaitTime",
  "RescheduleWaitTimeEnabled",
  "ScheduledInstallDay",
  "ScheduledInstallTime"
);

au_settings = NULL;

foreach setting (au_setting_names)
{
  # 'handle' is still open from querying 'UseWUServer'
  value = RegQueryValue(handle:handle, item:setting);
  if (!isnull(value))
    au_settings += '  ' + setting + ' : ' + value[1] + '\n';
  else
    au_settings += '  ' + setting + ' : undefined\n';
}

RegCloseKey(handle:handle);

# Next, check to see which WSUS server this host is configured to use
handle = RegOpenKey(handle:hklm_handle, key:"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate", mode:MAXIMUM_ALLOWED);
server = NULL;
status_server = NULL;

if (!isnull(handle))
{
  value = RegQueryValue(handle:handle, item:"WUServer");
  if (!isnull(value)) server = value[1];

  if (isnull(server))
  {
    RegCloseKey(handle:handle);
  }
  else
  {
    value = RegQueryValue(handle:handle, item:"WUStatusServer");
    if (!isnull(value)) status_server = value[1];
  }
}

# If the config looks invalid, bail out, telling the user what went wrong
if (isnull(server))
{
  RegCloseKey(handle:hklm_handle);
  NetUseDel();

  report =
    '\nThis host is configured to utilize a WSUS server for updates,\n' +
    'though Nessus could not determine which server is providing the\n' +
    'updates.\n\n'+
    'This host may be configured incorrectly.  Make sure the following\n' +
    'registry entry is set to the desired WSUS host :\n\n'+
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUServer\n';
  security_note(port:port, extra:report);
  exit();
}
else if (server != status_server)
{
  RegCloseKey(handle:handle);
  RegCloseKey(handle:hklm_handle);
  NetUseDel();

  report =
    '\nThis host is configured to utilize a WSUS server for updates,\n' +
    'though it appears an invalid configuration is being used.  This host\n' +
    'may be configured incorrectly.  The "WUServer" and "WUStatusServer"\n' +
    'registry entries must be set to the same value in order to be valid.\n\n' +
    '  Key : HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\n' +
    '  WUServer : ' + server + '\n' +
    '  WUStatusServer : ' + status_server + '\n';
  security_note(port:port, extra:report);
  exit();
}

# Query the remaining WSUS Environment options
wsus_env = NULL;

foreach setting (make_list("ElevateNonAdmins", "TargetGroup", "TargetGroupEnabled"))
{
  # 'handle' is still open from querying WUServer + WUStatusServer
  value = RegQueryValue(handle:handle, item:setting);
  if (!isnull(value))
    wsus_env += '  ' + setting + ' : ' + value[1] + '\n';
  else
    wsus_env += '  ' + setting + ' : undefined\n';
}

RegCloseKey(handle:handle);

stats = NULL;

foreach subkey (make_list('Detect', 'Download', 'Install'))
{
  handle = RegOpenKey(handle:hklm_handle, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\" + subkey, mode:MAXIMUM_ALLOWED);
  if (!isnull(handle))
  {
    value = RegQueryValue(handle:handle, item:'LastSuccessTime');
    if (!isnull(value))
      stats += '  Updates last ' + tolower(subkey) + 'ed : ' + value[1] + '\n';

    RegCloseKey(handle:handle);
  }
}

RegCloseKey(handle:handle);
RegCloseKey(handle:hklm_handle);
NetUseDel ();

if (report_verbosity > 0)
{
  if (isnull(server))
  {
    report =
      '\nThis host is configured to utilize a WSUS server for updates,\n' +
      'though Nessus could not determine which server is providing the\n' +
      'updates.\n\n'+
      'This host may be configured incorrectly.  Make sure the following\n' +
      'registry entry is set to the desired WSUS host :\n\n'+
      'HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUServer\n';
  }
  else
  {
    report = '\nThis host is configured to get updates from the following WSUS server :\n\n  ' + server + '\n';

    if (!isnull(wsus_env))
      report += '\nWSUS Environment Options :\n\n' + wsus_env;
    if (!isnull(stats))
      report += '\nUpdate status :\n\n' + stats;
    if (!isnull(au_settings))
      report += '\nAutomatic Update settings :\n\n' + au_settings;
  }
  security_note(port:port, extra:report);
}
else security_note(port);


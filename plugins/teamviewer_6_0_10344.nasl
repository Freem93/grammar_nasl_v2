#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(52716);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_bugtraq_id(46797);
  script_osvdb_id(72288);
  script_xref(name:"Secunia", value:"43293");

  script_name(english:"TeamViewer Insecure Directory Permissions Privilege Escalation");
  script_summary(english:"Checks versions of TeamViewer");


  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by a
privilege escalation vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its version number, the TeamViewer install on the remote
Windows host is affected by a privilege escalation vulnerability due
to insecure file system permissions that are granted during
installation.

When 'Remote Access' is enabled, it may be possible for an attacker to
execute arbitrary code with escalated privileges when an
administrative user launches the desktop application.

Note that this issue does not affect TeamViewer installed on Windows
XP or 2003.");

  script_set_attribute(attribute:"see_also", value:"http://www.teamviewer.com/en/download/changelog.aspx");
  script_set_attribute(attribute:"solution", value:"Upgrade to TeamViewer 6.0.10344 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("teamviewer_detect.nasl");
  script_require_keys("SMB/TeamViewer/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");


get_kb_item_or_exit('SMB/TeamViewer/Installed');
winver = get_kb_item_or_exit('SMB/WindowsVersion');

if (winver == '5.1' || winver == '5.2')
  exit(0, "TeamViewer is installed on Windows XP or Windows 2003 and thus is not affected.");

installs = get_kb_list('SMB/TeamViewer/*');

report = NULL;
fixed_version = '6.0.10344';
foreach install (keys(installs))
{
  if ('Install' >< install) continue;
  version = install - 'SMB/TeamViewer/';

  if (version =~ '^6\\.' && ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    path = installs[install];
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

if (isnull(report)) exit(0, 'No vulnerable TeamViewer installs were detected.');

# If there is a vulnerable version installed, make sure Remote Access is enabled
# unless we're paranoid
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if (report_paranoia < 2)
{
  remoteaccess = FALSE;


  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
  if (rc != 1)
  {
    NetUseDel();
    exit(1, 'Can\'t connect to the IPC share.');
  }
  hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(hklm))
  {
    NetUseDel();
    exit(1, 'Can\'t connect to the remote registry.');
  }

  key = 'SOFTWARE\\TeamViewer\\Version6';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:'Always_Online');
    if (!isnull(value)) remoteaccess = value[1];
    RegCloseKey(handle:key_h);
  }
  RegCloseKey(handle:hklm);
  NetUseDel();
  if (!remoteaccess) exit(0, 'The remote TeamViewer install is not affected because Remote Access is disabled.');
}
else
{
  report +=
    '  Comments         : ' +
    '\n  Note though that Nessus did not check whether \'Remote Access\' has' +
    '\n  been enabled because of the Report Paranoia setting in effect when' +
    '\n  this scan was run.\n';
}

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
exit(0);

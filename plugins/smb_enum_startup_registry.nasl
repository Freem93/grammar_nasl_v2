#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58452);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_name(english:"Microsoft Windows Startup Software Enumeration");
  script_summary(english:"Enumerates the list of startup software");

  script_set_attribute(attribute:"synopsis", value:"It is possible to enumerate startup software.");
  script_set_attribute(attribute:"description", value:
"This plugin lists software that is configured to run on system startup
by crawling the registry entries in :

  - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    -
    HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersi
    on\Run");

  script_set_attribute(attribute:"solution", value:
"Review the list of applications and remove any that are not compliant
with your organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

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
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

startuplist = make_array();
key = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; i++)
  {
    item = RegEnumValue(handle:key_h, index:i);
    if (!isnull(item))
    {
      app = item[1];
      item2 = RegQueryValue(handle:key_h, item:item[1]);
      if (!isnull(item2))
      {
        path = item2[1];
        # Strip out quotes and anything that isn't the path
        path = ereg_replace(string:path, pattern:'^(")?([^"]+).*', replace:"\2");
        startuplist[app] = path;
      }
    }
  }
  RegCloseKey(handle:key_h);
}

# Also check the WOW6432Node if it exists
key = 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; i++)
  {
    item = RegEnumValue(handle:key_h, index:i);
    if (!isnull(item))
    {
      app = item[1];
      item2 = RegQueryValue(handle:key_h, item:item[1]);
      if (!isnull(item2))
      {
        path = item2[1];
        # Strip out quotes and anything that isn't the path
        path = ereg_replace(string:path, pattern:'^(")?([^"]+).*', replace:"\2");
        startuplist[app] = path;
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

if (max_index(keys(startuplist)) > 0)
{
  if (report_verbosity > 0)
  {
    if (max_index(startuplist) > 1) s = 's were found';
    else s = ' was found';

    info = '';
    foreach item (sort(keys(startuplist)))
    {
      info += '  ' + item + ' - ' + startuplist[item] + '\n';
    }

    report =
      '\nThe following startup item' + s + ' :\n' +
      '\n' +
      info;
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(0, 'No startup items were found in the remote registry.');

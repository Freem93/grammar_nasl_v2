#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66542);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/22 19:15:41 $");

  script_name(english:"JavaScript Enabled in Adobe Reader");
  script_summary(english:"Checks if JavaScript is enabled");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has JavaScript enabled in Adobe Reader.");
  script_set_attribute(attribute:"description", value:
"JavaScript is enabled in Adobe Reader. 

Note that Nessus can only check the SIDs of logged on users, and thus
the results may be incomplete.");
  script_set_attribute(attribute:"solution", value:"Disable JavaScript in Adobe Reader unless it is needed.");
  # http://www.zdnet.com/blog/security/adobe-turn-off-javascript-in-pdf-reader/3245
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f30673d6");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/Acroread/Version");

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/Acroread/Version');

info = '';

registry_init();
hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
key_h = RegOpenKey(handle:hku, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  reginfo = RegQueryInfoKey(handle:key_h);
  if (!isnull(reginfo))
  {
    for (i=0; i < reginfo[1]; i++)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (subkey =~ '^S-1-5-21-[0-9\\-]+$')
      {
        key = subkey + "\Software\Adobe\Acrobat Reader\";
        subkeys = get_registry_subkeys(handle:hku, key:key);
        foreach subkey2 (subkeys)
        {
          key2 = key + subkey2 + "\JSPrefs\bEnableJS";
          enabled = get_registry_value(handle:hku, item:key2);
          # JavaScript is enabled if the value is NULL or 1
          if (isnull(enabled) || enabled == 1)
          {
            ver = split(subkey2, sep:'.', keep:FALSE);
            info += '  Version ' + ver[0] + ' for SID ' + subkey + '\n';
          }
        }
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hku);
close_registry();

if (info)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = 's';
    else s = '';

    report =
      '\nNessus found JavaScript enabled for the following user' + s + ' and version' + s +
      '\nof Adobe Reader :' +
      '\n' +
      '\n' + info;
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else
{
  exit(0, 'JavaScript has been disabled for all detected users and versions of Adobe Reader.');
}

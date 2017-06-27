#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92430);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Registry Editor Last Accessed");
  script_summary(english:"Last registry key opened in regedit program when it was closed."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to find the last key accessed by the Registry Editor
when it was closed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to find evidence of the last key that was opened when
the Registry Editor was closed for each user.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/244004");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Incident Response");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_reg_service_pack.nasl", "set_kb_system_name.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("charset_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

exit(0, "This plugin is temporarily disabled");

# HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit : LastKEy
key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit';
value = get_hku_key_values(key:key);

report = '';
foreach user (keys(value))
{
  if (isnull(value[user]['lastkey']))
  {
    continue;
  }

  report += user + '\n';
  report += '  - ' + value[user]['lastkey'] + '\n\n';
}

if (strlen(report) > 0)
{
  security_report_v4(extra:report, port:0, severity:SECURITY_NOTE);
}
else
{
  exit(0, "No regedit history found.");
}

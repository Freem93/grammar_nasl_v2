#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92437);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"WinSCP History");
  script_summary(english:"WinSCP connection information and history.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to gather evidence of WinSCP connections.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to generate a report of WinSCP connections and
connection settings.");
  script_set_attribute(attribute:"see_also", value:"https://winscp.net/eng/index.php");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winscp:winscp");
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

# HKEY_USERS\\<sid>\\Software\\Martin Prikryl\\WinSCP 2\\Configuration\\History\\LocalTarget
# HKEY_USERS\\<sid>\\Software\\Martin Prikryl\\WinSCP 2\\Configuration\\History\\RemoteTarget
# HKEY_USERS\\<sid>\\Software\\Martin Prikryl\\WinSCP 2\\Configuration\\CDCache

lt_key = '\\Software\\Martin Prikryl\\WinSCP 2\\Configuration\\History\\LocalTarget';
localtarget = get_hku_key_values(key:lt_key);
  
rt_key = '\\Software\\Martin Prikryl\\WinSCP 2\\Configuration\\History\\RemoteTarget';
remotetarget = get_hku_key_values(key:rt_key);

cache_key = '\\Software\\Martin Prikryl\\WinSCP 2\\Configuration\\CDCache';
winscpcache = get_hku_key_values(key:cache_key);

foreach user (keys(localtarget))
{
  foreach lt (keys(localtarget[user]))
  {
    att_report += user+','+lt+','+localtarget[user][lt]+','+lt_key+'\n';
  }
}

foreach user (keys(remotetarget))
{
  foreach rt (keys(remotetarget[user]))
  {
    att_report += user+','+rt+','+localtarget[user][rt]+','+rt_key+'\n';
  }
}

foreach user (keys(winscpcache))
{
  foreach wc (keys(winscpcache[user]))
  {
    att_report += user+','+wc+','+winscpcache[user][wc]+','+cache_key+'\n';
  }
}

system = get_system_name();

if (strlen(att_report) > 0)
{
  report = 'WinSCP report attached.\n';

  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "winscp_"+system+".csv";
  attachments[0]["value"] = att_report;

  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );  
}
else
{
  exit(0, "No WinSCP data found.");
}

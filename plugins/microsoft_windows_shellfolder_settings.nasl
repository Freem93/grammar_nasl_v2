#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92431);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"User Shell Folders Settings");
  script_summary(english:"Report storage locations for some user based information."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to find the folder paths for user folders on the
remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to gather a list of settings from the target system 
that store common user folder locations. A few of the more common
locations are listed below :

  - Administrative Tools
  - AppData
  - Cache
  - CD Burning
  - Cookies
  - Desktop
  - Favorites
  - Fonts
  - History
  - Local AppData
  - My Music
  - My Pictures
  - My Video
  - NetHood
  - Personal
  - PrintHood
  - Programs
  - Recent
  - SendTo
  - Start Menu
  - Startup
  - Templates");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/cc962613.aspx");
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

get_kb_item_or_exit("SMB/Registry/Enumerated");

# HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders : History, Cookies, Cache, AppData, Recent, 
key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders';
value = get_hku_key_values(key:key);

report = '';
foreach user (keys(value))
{
  if (isnull(value[user]) || isnull(value[user]["appdata"]))
  {
    continue;
  }

  report += user + '\n';

  foreach entry (keys(value[user]))
  {
    report += '  - ' + entry  + ' : ' + value[user][entry]  + '\n';
    set_kb_item(name:"registry/shellfolder/"+entry+"/"+user ,value:value[user][entry]);
  }

  report += '\n';
}

if (strlen(report) > 0)
{
  security_report_v4(extra:report, port:0, severity:SECURITY_NOTE);
}
else
{
  exit(0, "No shellfolder data found.");
}

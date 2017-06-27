#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92427);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Microsoft Paint Recent File History");
  script_summary(english:"Report evidence of files opened in MSPaint."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate files opened in Microsoft Paint on the
remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to generate a list of files opened using the Microsoft
Paint program.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Microsoft_Paint");
  # http://www.thewindowsclub.com/delete-items-from-recent-picture-list-in-paint
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0887d2d5");
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

##
# HKEY_USERS\<sid>\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List
##
function get_Mspaint_recent()
{
  local_var hku, hku_list, user, key, res, ret, username;
  
  ret = make_array();
  key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Paint\\Recent File List';
  
  registry_init();  
  hku = registry_hive_connect(hive:HKEY_USERS);
  if (isnull(hku))
  {
    close_registry();
    return NULL;
  }

  hku_list = get_registry_subkeys(handle:hku, key:'');
  foreach user (hku_list)
  {
    username = get_hku_usernames(handle:hku, sid:user);

    res = get_reg_name_value_table(handle:hku, key:user + '\\' + key);
    if (!isnull(res))
    {
      if (username)
      {
        ret[username] = res;
      }
      else
      {
        ret[user] = res;
      }
    }
  }
  
  RegCloseKey(handle:hku);
  close_registry();
  
  return ret;
}

value = get_Mspaint_recent();
report = '';
foreach user (keys(value))
{
  report += user + '\n';
  foreach files (keys(value[user]))
  {
    report += '  - '+value[user][files] + '\n';
  }
}

if (strlen(report) > 0)
{
  security_report_v4(extra:report, port:0, severity:SECURITY_NOTE);
}
else
{
  exit(0, 'No recent files found for Microsoft Paint.');
}

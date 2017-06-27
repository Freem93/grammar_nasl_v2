#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92435);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"UserAssist Execution History");
  script_summary(english:"Report evidence of programs getting executed using userassist key."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate program execution history on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to gather evidence from the UserAssist registry key
that has a list of programs that have been executed.");
  script_set_attribute(attribute:"see_also", value:"http://www.4n6k.com/2013/05/userassist-forensics-timelines.html");
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
# \\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{Guid}\\Count
##
function get_UserAssist()
{
  local_var hku, hku_list, user, res, ret, key, subkey, subkeys,
    userassist, ua, val, username;
  
  key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\';
  ret = make_array();
  
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
    subkeys = get_registry_subkeys(handle:hku, key:user + key);
    username = get_hku_usernames(handle:hku, sid:user);

    foreach subkey (subkeys)
    {
      userassist = get_reg_name_value_table(handle:hku, key:user + key + '\\' + subkey + '\\Count');
      
      if (!isnull(userassist))
      {
        foreach ua (keys(userassist))
        {
          val = userassist[ua];
          ua = rot13(val:ua);
          res[ua] = get_raw_ascii_hex_values(val:val);
        }

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
  }
  
  RegCloseKey(handle:hku);
  close_registry();
  
  return ret;
}

value = get_UserAssist();

att_report = 'user,key,hex,ascii,raw\n';
foreach user (keys(value))
{
  foreach entry (keys(value[user]))
  {
    user = format_for_csv(data:user);
    entry = format_for_csv(data:entry);
    hex = value[user][entry]['hex'];
    raw = format_for_csv(data:value[user][entry]['raw']);
    ascii = format_for_csv(data:value[user][entry]['ascii']);

    att_report += '"'+user+'","'+entry+'","'+hex+'","'+ascii+'","'+raw+'"\n';
  }
}

system = get_system_name();

if (strlen(att_report) > 0)
{
  report = 'UserAssist report attached.\n';

  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "userassist_"+system+".csv";
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
  exit(0, "No UserAssist data found.");
}

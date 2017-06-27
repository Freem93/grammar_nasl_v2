#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92424);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"MUICache Program Execution History");
  script_summary(english:"Report program execution using the MUICache registry."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate recently executed programs on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to query the MUIcache registry key to find evidence of
program execution.");
  script_set_attribute(attribute:"see_also", value:"https://forensicartifacts.com/2010/08/registry-muicache/");
  script_set_attribute(attribute:"see_also", value:"http://windowsir.blogspot.com/2005/12/mystery-of-muicachesolved.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nirsoft.net/utils/muicache_view.html");
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
# HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache
# HKEY_USERS\\<sid>\\Software\\Classes\\Local Settings\\MuiCache
# HKEY_USERS\\<sid>\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache
##
function get_MUICache()
{
  local_var hku, hku_list, user, ShellNoRoam_key, LocalSettings_key, Shell_key,
  res, lss1, lss2, key, LocalSettings_subkey1, LocalSettings_subkey2, ret, username;

  ret = make_array();

  ShellNoRoam_key = '\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache';
  LocalSettings_key = '\\Software\\Classes\\Local Settings\\MuiCache';
  Shell_key = '\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache';

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

    # ShellNoRoam MuiCache
    res = get_reg_name_value_table(handle:hku, key:user + ShellNoRoam_key);
    if (!isnull(res))
    {
      if (username)
      {
        ret[username] = make_array("ShellNoRoam_list", res);
      }
      else
      {
        ret[user] = make_array("ShellNoRoam_list", res);
      }
    }

    # LocalSettings MuiCache
    LocalSettings_subkey1 = get_registry_subkeys(handle:hku, key:user+LocalSettings_key);
    foreach lss1 (LocalSettings_subkey1)
    {
      LocalSettings_subkey2 = get_registry_subkeys(handle:hku, key:user+LocalSettings_key+'\\'+lss1);
      foreach lss2 (LocalSettings_subkey2)
      {
        res = get_reg_name_value_table(handle:hku, key:user + LocalSettings_key + '\\' + lss1 + '\\' + lss2);

        if (!isnull(res))
        {
          if (username)
          {
            ret[username] = make_array("LocalSettings_list", res);
          }
          else
          {
          ret[user] = make_array("LocalSettings_list", res);
          }
        }

      }
    }

    # Shell MuiCache
    res = get_reg_name_value_table(handle:hku, key:user + Shell_key);
    if (!isnull(res))
    {
      if (username)
      {
        ret[username] = make_array("Shell_list", res);
      }
      else
      {
        ret[user] = make_array("Shell_list", res);
      }
    }
  }

  RegCloseKey(handle:hku);
  close_registry();

  return ret;
}

value = get_MUICache();

muicache_report = '';
foreach user (keys(value))
{
  foreach type (keys(value[user]))
  {
    foreach items (keys(value[user][type]))
    {
      user = format_for_csv(data:user);
      type = format_for_csv(data:type);
      items = format_for_csv(data:items);
      muicache = format_for_csv(data:value[user][type][items]);
      muicache_report += '"'+user+'","'+type+'","'+items+'","'+muicache+'"\n';
    }
  }
}

if (strlen(muicache_report) > 0)
{
  muicache_report = 'user,type,key,value\n'+muicache_report;
  report = 'MUICache report attached.\n';
  
  system = get_system_name();
  
  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "muicache_"+system+".csv";
  attachments[0]["value"] = muicache_report;
  
  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, "No MUICache data found.");
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92433);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Terminal Services History");
  script_summary(english:"Terminal service client and user history."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to gather terminal service connection information.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to generate a report on terminal service connections
on the target system.");
  # https://blogs.rsa.com/targeted-forensics-series-confirming-remote-desktop-connections-part-1-2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed4a0253");
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
# HKEY_USERS\\<sid>\\Software\\Microsoft\\Terminal Server Client\\Servers
##
function get_Terminal_Services_Client_Servers_MRU()
{
  local_var hku, hku_list, user, res, ret, subkey, subkeys, key, ts_info, username;
  
  key = '\\Software\\Microsoft\\Terminal Server Client\\Servers';
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
    username = get_hku_usernames(handle:hku, sid:user);
    subkeys = get_registry_subkeys(handle:hku, key:user + key);
    foreach subkey (subkeys)
    {
      res = get_reg_name_value_table(handle:hku, key:user + key + '\\' + subkey);
      if (!isnull(res))
      {
        ts_info['HKEY_USERS\\' + user + key + '\\' + subkey] = res;
      }
    }

    if (username)
    {
      ret[username] = ts_info;
    }
    else
    {
      ret[user] = ts_info;
    }
  }
  
  RegCloseKey(handle:hku);
  close_registry();
  
  return ret;
}

# HKEY_USERS\\<sid>\\Software\\Microsoft\\Terminal Server Client\\Default
key = '\\Software\\Microsoft\\Terminal Server Client\\Default';
value = get_hku_key_values(key:key);

tsc_report = '';
foreach user (keys(value))
{
  foreach tsc (keys(value[user]))
  {
    tsc_report += user + ',' + key + ',' + tsc + ',' + value[user][tsc] + '\n';
  }
}

value = get_Terminal_Services_Client_Servers_MRU();

tss_report = '';
foreach user (keys(value))
{
  foreach kval (keys(value[user]))
  {
    foreach tss (keys(value[user][kval]))
    {
      tss_report += user +','+ kval +','+tss+','+value[user][kval][tss]+'\n';
    }
  }
}

attachments = make_list();
i = 0;
system = get_system_name();

if (strlen(tsc_report) > 0)
{
  tsc_report = 'user,regkey,key,value\n'+tsc_report;

  attachments[i] = make_array();
  attachments[i]["type"] = "text/csv";
  attachments[i]["name"] = 'Terminal_Services_Client_'+system+'.csv';
  attachments[i]["value"] = tsc_report;
  i++;
}

if (strlen(tss_report) > 0)
{
  tss_report = 'user,regkey,key,value\n'+tss_report;

  attachments[i] = make_array();
  attachments[i]["type"] = "text/csv";
  attachments[i]["name"] = "Terminal_Services_Server_"+system+".csv";
  attachments[i]["value"] = tss_report;
  i++;
}

if (i>0)
{
  report = 'Terminal Services report attached.\n';

  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );  
}
else
{
  exit(0, "No Terminal Services history found.");
}

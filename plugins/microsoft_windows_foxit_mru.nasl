#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92420);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Foxit History");
  script_summary(english:"Foxit application history."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate files that were opened by Foxit
applications on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to query the system to generate a list of files opened
by Foxit programs.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
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
# HKEY_USERS\\<sid>\\Software\\Foxit Software\\Foxit Reader 6.0\\Recent File List
# HKEY_USERS\\<sid>\\Software\\Foxit Software\\Foxit Phantom\\Recent File List
##
function get_FoxitRecentFileList()
{
  local_var hku, hku_list, user, res, ret, key, subkey, subkeys, username, recentfilelist;
  
  key = '\\Software\\Foxit Software\\';
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
    recentfilelist = make_array();
    
    foreach subkey (subkeys)
    {
      res = get_reg_name_value_table(handle:hku, key:user + key + '\\' + subkey + '\\Recent File List');
      if (!isnull(res))
      {
        recentfilelist['HKEY_USERS\\'+user + key + '\\' + subkey + '\\Recent File List'] = res;
      }
    }

    if (max_index(keys(recentfilelist)) > 0)
    {
      if (!isnull(username))
      {
        ret[username] = recentfilelist;
      }
      else
      {
        ret[user] = recentfilelist;
      }
    }
  }
  
  RegCloseKey(handle:hku);
  close_registry();
  
  return ret;
}

##
# HKEY_USERS\\<sid>\\Software\\Foxit Software\\Foxit Reader 6.0\\Preferences\\History\\LastOpen
##
function get_FoxitHistoryLastOpen()
{
  local_var hku, hku_list, user, res, ret, key, subkey1, subkeys1, 
    subkey2, subkeys2, username, lastopen;
  
  key = '\\Software\\Foxit Software';
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
    lastopen = make_array();
    username = get_hku_usernames(handle:hku, sid:user);

    subkeys1 = get_registry_subkeys(handle:hku, key:user + key);    
    foreach subkey1 (subkeys1)
    {
      subkeys2 = get_registry_subkeys(handle:hku, key:user + key + '\\' + subkey1 + '\\Preferences\\History\\LastOpen');
      foreach subkey2 (subkeys2)
      {
        res = get_reg_name_value_table(handle:hku, key:user + key + '\\' + subkey1 + '\\Preferences\\History\\LastOpen\\' + subkey2);
        if (!isnull(res))
        {
          lastopen['HKEY_USERS\\' + user + key + '\\' + subkey1 + '\\Preferences\\History\\LastOpen\\' + subkey2] = res['filename'];
        }
      }
    }

    if (!isnull(lastopen) && max_index(keys(lastopen)) > 0)
    {
      if (!isnull(username))
      {
        ret[username] = lastopen;
      }
      else
      {
        ret[user] = lastopen;
      }
    }
  }
  
  RegCloseKey(handle:hku);
  close_registry();
  
  return ret;
}

##
# HKEY_USERS\\<sid>\\Software\\Foxit Software\\Foxit Reader 7.0\\MRU
##
function get_FoxitMRU()
{
  local_var hku, hku_list, user, res, ret, key, subkey, subkeys, mru, username;
  
  key = '\\Software\\Foxit Software\\';
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
    mru = make_array();

    foreach subkey (subkeys)
    {
      res = get_reg_name_value_table(handle:hku, key:user + key + '\\' + subkey + '\\MRU\\File MRU\\');
      if (!isnull(res))
      {
        mru['HKEY_USERS\\'+user + key + '\\' + subkey + '\\MRU\\File MRU\\'] = res;
      }
    }

    if (!isnull(mru) && max_index(keys(mru)) > 0)
    {
      if (!isnull(username))
      {
        ret[username] = mru;
      }
      else
      {
        ret[user] = mru;
      }
    }

  }
  
  RegCloseKey(handle:hku);
  close_registry();
  
  return ret;
}

FoxitRecentFileList = get_FoxitRecentFileList();
FoxitHistoryLastOpen = get_FoxitHistoryLastOpen();
FoxitMRU = get_FoxitMRU();

foxit_report = '';
foreach user (keys(FoxitRecentFileList))
{
  foreach regkey (keys(FoxitRecentFileList[user]))
  {
    foreach frfl (keys(FoxitRecentFileList[user][regkey]))
    {
      foxit_report += user+',' + regkey + ',' + frfl + ',' + FoxitRecentFileList[user][regkey][frfl]  + '\n';
    }
  }
}

foreach user (keys(FoxitHistoryLastOpen))
{
  foreach regkey (keys(FoxitHistoryLastOpen[user]))
  {
      foxit_report += user+',' + regkey + ', ,' + get_ascii_printable(string:FoxitHistoryLastOpen[user][regkey])  + '\n';
  }
}

foreach user (keys(FoxitMRU))
{
  foreach regkey (keys(FoxitMRU[user]))
  {
    foreach fmru (keys(FoxitMRU[user][regkey]))
    {
      foxit_report += user + ',' + regkey + ',' + fmru + ',' + FoxitMRU[user][regkey][fmru]  + '\n';
    }
  }
}


if (strlen(foxit_report) > 0)
{
  report = 'Foxit History Attached\n';
  foxit_report = 'user,regkey,key,value\n' + foxit_report;

  system = get_system_name();
  
  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "foxit_mru_"+system+".csv";
  attachments[0]["value"] = foxit_report;

  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, "No foxit history found.");
}

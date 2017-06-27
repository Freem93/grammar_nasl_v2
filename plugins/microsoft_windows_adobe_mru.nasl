#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92414);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Adobe Recent Files");
  script_summary(english:"List recently accessed compressed files by Adobe products.");  

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate recently accessed Adobe product files on
the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to query Adobe settings on the remote Windows host to
find recently opened Adobe file information.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
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
# HKEY_USERS\\<sid>\\Software\\Adobe\\Acrobat Reader\\11.0\\AVGeneral\\cRecentFiles
# HKEY_USERS\\<sid>\\Software\\Adobe\\Acrobat Acrobat\\11.0\\AVGeneral\\cRecentFiles
##
function get_AdobeRecentFiles()
{
  local_var hku, hku_list, user, res, ret, key, subkey1, subkeys1, 
    subkey2, subkeys2, subkeys3, subkey3, username, adobe_history;
  
  key = '\\Software\\Adobe\\';
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
    subkeys1 = get_registry_subkeys(handle:hku, key:user + key);

    if (isnull(subkeys1)) continue;

    adobe_history = make_array();
    
    foreach subkey1 (subkeys1)
    {
      subkeys2 = get_registry_subkeys(handle:hku, key:user + key + '\\' + subkey1 + '\\');
      foreach subkey2 (subkeys2)
      {
        subkeys3 = get_registry_subkeys(handle:hku, key:user + key + '\\' + subkey1 + '\\' + subkey2 + '\\AVGeneral\\cRecentFiles');
        foreach subkey3 (subkeys3)
        {
          username = get_hku_usernames(handle:hku, sid:user);

          res = get_reg_name_value_table(handle:hku, key:user + key + '\\' + subkey1 + '\\' + subkey2 + '\\AVGeneral\\cRecentFiles\\' + subkey3);
          if (!isnull(res))
          {
            adobe_history['HKEY_USERS\\' + user + key + subkey1 + '\\' + subkey2 + '\\AVGeneral\\cRecentFiles\\' + subkey3] = res;
          }
        }
      }
    }
    ret[username] = adobe_history;
  }

  RegCloseKey(handle:hku);
  close_registry();

  return ret;
}

value = get_AdobeRecentFiles();

if (isnull(value))
{
  exit(0,'No adobe history files found.');
}

adobe_history = '';
foreach user (keys(value))
{
  foreach regkey (keys(value[user]))
  {
    adobe_history += user + ',';
    adobe_history += value[user][regkey]['tditext']  + ',';
    adobe_history += value[user][regkey]['ufilesize']  + ',';
    adobe_history += value[user][regkey]['upagecount']  + ',';
    adobe_history += get_ascii_printable(string:value[user][regkey]['sdate'])  + ',';
    adobe_history += regkey + '\n';
  }
}

if (strlen(adobe_history) > 0)
{
  adobe_history = 'user,tditext,ufilesize,upagecount,sdate,regkey\n' + adobe_history;

  report = 'Adobe file history report attached.\n';
  system = get_system_name();
  
  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "adobe_file_history_"+system+".csv";
  attachments[0]["value"] = adobe_history;
  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, "No Adobe history found.");
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92425);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Microsoft Office File History");
  script_summary(english:"Report files opened in Microsoft office programs."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate files opened in Microsoft Office on the
remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to gather evidence of files that were opened using any
Microsoft Office application. The report was extracted from Office MRU
(Most Recently Used) registry keys.");
  script_set_attribute(attribute:"see_also", value:"https://products.office.com/en-US/");
  script_set_attribute(attribute:"see_also", value:"http://www.taksati.org/mru/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

exit(0, "This plugin is temporarily disabled");

##
# HKEY_USERS\\<sid>\\Software\\Microsoft\\Office\\<verson>\\Excel\\File MRU
# HKEY_USERS\\<sid>\\Software\\Microsoft\\Office\\<verson>\\Access\\File MRU
# HKEY_USERS\\<sid>\\Software\\Microsoft\\Office\\<verson>\\PowerPoint\\File MRU
# HKEY_USERS\\<sid>\\Software\\Microsoft\\Office\\<verson>\\Word\\File MRU
# <versions> 16.0, 15.0, 14.0, 12.0, 11.0, 10.0, 9.0, 
##
function get_officeMRU()
{
  local_var hku, hku_list, user, res, ret, versions, ver, key, key_exists, oprod, office_products, username, officemru;

  # All current versions as of 2016 go from 9.0 to 16.0, 
  # I added in more to account for potential future
  # versions of office 
  versions = make_list("9.0", "10.0", "11.0", "12.0", "13.0", "14.0", "15.0", "16.0", "17.0", "18.0", "19.0", "20.0", "21.0");
  office_products = make_list('Excel', 'Word', 'Access', 'Powerpoint', 'Publisher');
  
  key = '\\Software\\Microsoft\\Office';
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

    foreach ver (versions)
    {
      key_exists = get_registry_subkeys(handle:hku, key:'');
      if (key_exists)
      {
        foreach oprod (office_products)
        {
          res = get_reg_name_value_table(handle:hku, key:user + key + '\\' + ver + '\\' + oprod + '\\File MRU');
          if (!isnull(res))
          {
            officemru['HKEY_USERS\\'+ user + key + '\\' + ver + '\\' + oprod + '\\File MRU'] = res;
          }
        }
      }
    }

    if (!isnull(username))
    {
      ret[username] = officemru;
    }
    else
    {
      ret[user] = officemru;
    }
  }
  
  RegCloseKey(handle:hku);
  close_registry();
  
  return ret;
}

##
#
##
function get_OfficeRecentFiles()
{
  local_var share, path, user_dir, ud, file, files, ret,
    system_drive, subdirs, subdir;

  ret = make_array();
  system_drive = hotfix_get_systemdrive(as_dir:TRUE);
  path = system_drive + 'Users';

  share = hotfix_path2share(path:path);
  path = ereg_replace(string:path, pattern:"^\w:(.*)", replace:'\\1\\');

  user_dir = win_dir_ex(basedir:path, max_recurse:0, dir_pat:".*", file_pat:NULL, share:share);
  foreach ud (user_dir)
  {
    subdirs = win_dir_ex(basedir:ud+'AppData\\Roaming\\Microsoft\\Office\\Recent\\', max_recurse:100, file_pat:".*", share:share);

    foreach subdir (subdirs)
    {
      ret = make_list(ret, system_drive+subdir);
    }
  }

  return ret;
}

office_mru = get_officeMRU();
office_recentfiles = get_OfficeRecentFiles();

office_mru_report = '';
foreach user (keys(office_mru))
{
  foreach regkey (keys(office_mru[user]))
  {
    foreach omru (keys(office_mru[user][regkey]))
    {
      office_mru_report += user+','+regkey+','+omru+','+office_mru[user][regkey][omru]+'\n';
    }
  }
}

office_recent_report = '';
foreach orf (office_recentfiles)
{
  office_recent_report += orf + '\n';
}

system = get_system_name();

i = 0;
report = '';
attachments = make_list();
if (strlen(office_recent_report) > 0)
{
  report += 'User AppData recent used file report attached\n';

  attachments[i] = make_array();
  attachments[i]["type"] = "text/csv";
  attachments[i]["name"] = "office_appdata_history_report_"+system+".csv";
  attachments[i]["value"] = office_recent_report;

  i++;
}

if (strlen(office_mru_report) > 0)
{
  report += 'Office MRU registry report attached.\n';

  attachments[i] = make_array();
  attachments[i]["type"] = "text/csv";
  attachments[i]["name"] = "office_registry_history_report_"+system+".csv";
  attachments[i]["value"] = office_mru_report;

  i++;
}

if (i > 0)
{
  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, 'No Office files detected.');
}

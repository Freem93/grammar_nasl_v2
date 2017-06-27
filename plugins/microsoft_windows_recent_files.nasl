#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92428);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Recent File History");
  script_summary(english:"Report evidence of files that where recently opened."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate recently opened files on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to gather evidence of files opened by file type from
the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.4n6k.com/2014/02/forensics-quickie-pinpointing-recent.html");
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
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

exit(0, "This plugin is temporarily disabled");

##
#
##
function get_RecentFiles()
{
  local_var hku, hku_list, user, res, key, ret, filetypes, filetype, i, recentfiles, rf, username;

  key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs';
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
    i = 0;
    username = get_hku_usernames(handle:hku, sid:user);

    filetypes = get_registry_subkeys(handle:hku, key:user + '\\' + key);
    foreach filetype (filetypes)
    {
      if (i==0)
      {
        if (username)
        {
          ret[username] = make_array();
        }
        else
        {
          ret[user] = make_array();
        }
      }

      res = get_reg_name_value_table(handle:hku, key:user + '\\' + key + '\\' + filetype);

      if (!isnull(res))
      {
        foreach rf (keys(res))
        {
          recentfiles = get_raw_ascii_hex_values(val:res[rf]);
          res[rf] = recentfiles;
        }

        if (username)
        {
          ret[username][filetype] = res;
        }
        else
        {
          ret[user][filetype] = res;
        }

        i++;
      }
    }
  }

  RegCloseKey(handle:hku);
  close_registry();

  return ret;
}

##
#
##
function get_WindowsRecent()
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
    subdirs = win_dir_ex(basedir:ud+'AppData\\Roaming\\Microsoft\\Windows\\Recent\\', max_recurse:100, file_pat:".*", share:share);

    foreach subdir (subdirs)
    {
      ret = make_list(ret, system_drive+subdir);
    }
  }

  return ret;
}

reg_recentfile = get_RecentFiles();
appdata_recentfile = get_WindowsRecent();

reg_rf_report = '';
foreach user (keys(reg_recentfile))
{
  foreach filetype (keys(reg_recentfile[user]))
  {
    foreach files (reg_recentfile[user][filetype])
    {
      user = format_for_csv(data:user);
      filetype = format_for_csv(data:filetype);
      entry = format_for_csv(data:entry);
      hex = files['hex'];
      raw = format_for_csv(data:files['raw']);
      ascii = format_for_csv(data:files['ascii']);

      reg_rf_report += '"'+user+'","'+filetype+'","'+files['raw']+'","'+files['ascii']+'","'+files['hex']+'"\n';
    }
  }
}

appdata_rf_report = '';
foreach appfile (appdata_recentfile)
{
  appdata_rf_report += appfile + '\n';
}


if (strlen(reg_rf_report) <= 0 || strlen(appdata_rf_report) <= 0)
{
  exit(0, "No recent file data found.");
}


reg_rf_report = 'user,filetype,raw,ascii,hex\n'+reg_rf_report;

report = 'Recent files found in registry and appdata attached.\n';

system = get_system_name();

attachments = make_list();

attachments[0] = make_array();
attachments[0]["type"] = "text/csv";
attachments[0]["name"] = "registry_recent_files_"+system+".csv";
attachments[0]["value"] = reg_rf_report;

attachments[1] = make_array();
attachments[1]["type"] = "text/csv";
attachments[1]["name"] = "appdata_recent_files_"+system+".csv";
attachments[1]["value"] = appdata_rf_report;


security_report_with_attachments(
  port  : 0,
  level : 0,
  extra : report,
  attachments : attachments
);

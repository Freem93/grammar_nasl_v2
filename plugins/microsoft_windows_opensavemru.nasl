#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92426);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"OpenSaveMRU History");
  script_summary(english:"Report files that were opened or saved using Windows shell dialog box.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate opened and saved files on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to generate a report on files that were opened using
the shell dialog box or saved using the shell dialog box. This is the
box that appears when you attempt to save a document or open a
document in Windows Explorer.");
  # https://digital-forensics.sans.org/blog/2010/04/02/openrunsavemru-lastvisitedmru
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac4dd3fb");
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
#
##
function get_OpenSaveMRU()
{
  local_var hku, hku_list, user, res, key, ret, filetypes, filetype, val, i, username, osmru, osmru_i, file;
  
  key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU';
  ret = make_array();
  
  registry_init();
  hku = registry_hive_connect(hive:HKEY_USERS);
  if (isnull(hku)) return NULL;

  hku_list = get_registry_subkeys(handle:hku, key:'');
  foreach user (hku_list)
  {
    username = get_hku_usernames(handle:hku, sid:user);

    i = 0;
    osmru = make_list();
    filetypes = get_registry_subkeys(handle:hku, key:user + '\\' + key);
    foreach filetype (filetypes)
    {
      osmru_i = make_array();

      res = get_reg_name_value_table(handle:hku, key:user + '\\' + key + '\\' + filetype);

      if (!isnull(res))
      {
        foreach file (keys(res))
        {
          osmru_i[file] = get_raw_ascii_hex_values(val:res[file]);
        }

        osmru[filetype] = osmru_i;
        i++;
      }
    }

    if (i > 0)
    {
      if (username)
      {
        ret[username] = osmru;
      }
      else
      {
        ret[user] = osmru;
      }
    }
  }
  
  RegCloseKey(handle:hku);
  close_registry();
  
  return ret;
}

value = get_OpenSaveMRU();
osmru_report = '';
foreach user (keys(value))
{
  foreach filetype (keys(value[user]))
  {
    foreach fileval (keys(value[user][filetype]))
    {
      user = format_for_csv(data:user);
      regkey = format_for_csv(data:regkey);
      entry = format_for_csv(data:entry);
      hex = value[user][filetype][fileval]['hex'];
      raw = format_for_csv(data:value[user][filetype][fileval]['raw']);
      ascii = format_for_csv(data:value[user][filetype][fileval]['ascii']);

      osmru_report += '"'+user+'","'+filetype+'","'+fileval+'","'+raw+'","'+ascii+'","'+hex+'"\n';
    }
  }
}


if (strlen(osmru_report) > 0)
{
  osmru_report = 'user,filetype,regkey,raw,ascii,hex\n'+osmru_report;

  report += 'Open / Save report attached.\n';
  
  system = get_system_name();
  
  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "open_save_"+system+".csv";
  attachments[0]["value"] = osmru_report;
  
  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, "No OpenSaveMRU data found.");
}

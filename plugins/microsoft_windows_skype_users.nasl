#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92432);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Skype User Configuration Files");
  script_summary(english:"Collect Skype user configuration files."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to gather Skype users configuration files on the
remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to collect the Skype user configuration files for each
system user.");
  script_set_attribute(attribute:"see_also", value:"https://warrenpost.wordpress.com/2012/06/21/skype-forensics/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
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
# C:\\Users\\<user>\\AppData\\Roaming\\Skype\\<skype-name>
##
function get_SkypeMRU()
{
  local_var share, path, user_dir, ud, file, files, ret,
    system_drive, skype_users, skype_user, content;

  ret = make_array();
  system_drive = hotfix_get_systemdrive(as_dir:TRUE);
  path = system_drive + '\\Users';

  share = hotfix_path2share(path:path);
  path = ereg_replace(string:path, pattern:"^\w:(.*)", replace:'\\1\\');

  user_dir = win_dir_ex(basedir:path, max_recurse:0, dir_pat:".*", file_pat:NULL, share:share);

  foreach ud (user_dir)
  {
    skype_users = win_dir_ex(basedir:ud+'AppData\\Roaming\\Skype\\', max_recurse:0, dir_pat:".*", share:share);

    foreach skype_user (skype_users)
    {
      files = win_dir_ex(basedir:skype_user, max_recurse:100, file_pat:".*", share:share);

      foreach file (files)
      {
        if ("config.xml" >< file)
        {
          content = hotfix_get_file_contents(path:system_drive + file);
          ret[file] = content;
        }
      }
    }
  }

  return ret;
}

value = get_SkypeMRU();
i=0;
system = get_system_name();

attachments = make_list();
foreach user (keys(value))
{
  filepath = split(sep:'\\', user, keep:FALSE);
  filename = system + '.' + filepath[max_index(filepath)-2] + "." + filepath[max_index(filepath)-1];

  attachments[i] = make_array();
  attachments[i]["type"] = "text/xml";
  attachments[i]["name"] = filename;
  attachments[i]["value"] = value[user]['data'];

  i++;
} 

if (i > 0)
{
  report = 'Skype configuration files attached.\n';
  
  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, "No Skype data found.");
}

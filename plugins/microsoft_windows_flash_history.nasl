#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92419);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Flash Cookie History");
  script_summary(english:"Flash cookie showing flash URL history."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to gather Flash cookie URL history on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to generate a list of URLs that set Flash cookies on
the remote host.");
  # https://helpx.adobe.com/flash-player/kb/disable-local-shared-objects-flash.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59436209");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flash_player");
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
# C:\\Users\\<user>\\AppData\\Roaming\\Macromedia\\Flash Player\\#SharedObjects
##
function get_FlashMRU()
{
  local_var share, path, user_dir, ud, file, files, ret,
    system_drive, subdirs, subdir, values;

  ret = make_array();
  system_drive = hotfix_get_systemdrive(as_dir:TRUE);
  path = system_drive + 'Users';

  share = hotfix_path2share(path:path);
  path = ereg_replace(string:path, pattern:"^\w:(.*)", replace:'\\1\\');

  user_dir = win_dir_ex(basedir:path, max_recurse:0, dir_pat:".*", file_pat:NULL, share:share);
  foreach ud (user_dir)
  {
    subdirs = win_dir_ex(basedir:ud+'AppData\\Roaming\\Macromedia\\Flash Player\\#SharedObjects', max_recurse:0, dir_pat:".*", share:share);

    foreach subdir (subdirs)
    {
      values = win_dir_ex(basedir:subdir, max_recurse:0, dir_pat:".*", share:share);

      foreach value (values)
      {
        ret = make_list(ret, system_drive + value);
      }
    }
  }

  return ret;
}

value = get_FlashMRU();
report = '';
foreach flashhistory (value)
{
  report += flashhistory + '\n';
}

if (strlen(report) > 0)
{
  security_report_v4(extra:report, port:0, severity:SECURITY_NOTE);
}
else
{
  exit(0, "No flash cookies found.");
}

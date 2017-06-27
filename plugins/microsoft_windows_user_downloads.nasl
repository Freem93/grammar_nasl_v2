#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92434);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"User Download Folder Files");
  script_summary(english:"Files in the user download folder."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate downloaded files on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to generate a report of all files listed in the
default user download folder.");
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
function get_DownloadFolder()
{
  local_var share, path, user_dir, ud, file, files, ret, system_drive;

  ret = make_list();
  system_drive = hotfix_get_systemdrive(as_dir:TRUE);
  path = system_drive + 'Users';

  share = hotfix_path2share(path:path);
  path = ereg_replace(string:path, pattern:"^\w:(.*)", replace:'\\1\\');

  user_dir = win_dir_ex(basedir:path, max_recurse:0, dir_pat:".*", file_pat:NULL, share:share);
  foreach ud (user_dir)
  {
    files = win_dir_ex(basedir:ud+'Downloads\\', max_recurse:100, dir_pat:NULL, file_pat:".*", share:share);
    foreach file (files)
    {
      ret = make_list(ret, system_drive+file);
    }
  }

  return ret;
}

value = get_DownloadFolder();

att_report = '';
foreach file (value)
{
  att_report += file + '\n';
}

system = get_system_name();

if (strlen(att_report) > 0)
{
  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "downloads_"+system+".csv";
  attachments[0]["value"] = att_report;

  report = 'Download folder content report attached.\n';

  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );  
}
else
{
  exit(0, "No download files found.");
}

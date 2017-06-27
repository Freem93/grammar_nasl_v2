#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92429);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Recycle Bin Files");
  script_summary(english:"Report files in the Windows Recycle Bin."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate files in the recycle bin on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to generate a list of all files found in $Recycle.Bin
subdirectories.");
  # https://dereknewton.com/2010/06/recycle-bin-forensics-in-windows-7-and-vista/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c1a03df");
  # http://www.csee.umbc.edu/courses/undergraduate/FYS102D/Recycle.Bin.Forensics.for.Windows7.and.Windows.Vista.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5f6b056");
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
function get_RecycleBin()
{
  local_var system_drive, share, path, recyclebin, rb, ret;

  ret = make_list();

  system_drive = hotfix_get_systemdrive(as_dir:TRUE);
  path = system_drive+'$Recycle.Bin';

  share = hotfix_path2share(path:path);
  path = ereg_replace(string:path, pattern:"^\w:(.*)", replace:'\\1\\');

  recyclebin = list_dir(basedir:path, level:0, max_recurse:2, file_pat:".*", share:share);
  foreach rb (recyclebin)
  {
    ret = make_list(ret, system_drive+rb);
  }

  return ret;
}

value = get_RecycleBin();
foreach file (value)
{
  att_report += file + '\n';
}

if (strlen(att_report) > 0)
{
  report = 'Recycle Bin report attached.\n';

  system = get_system_name();

  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "recyclebin_"+system+".csv";
  attachments[0]["value"] = att_report;

  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, "No files found in the Recycle Bin.");
}

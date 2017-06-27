#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92423);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/06 19:52:16 $");

  script_name(english:"Windows Explorer Recently Executed Programs");
  script_summary(english:"Report evidence of recently executed programs in the registry."); 

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate recently executed programs on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to find evidence of program execution using Windows
Explorer registry logs and settings.");
  script_set_attribute(attribute:"see_also", value:"http://www.forensicswiki.org/wiki/LastVisitedMRU");
  # http://www.forensicfocus.com/a-forensic-analysis-of-the-windows-registry
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e00b191");
  # https://digital-forensics.sans.org/blog/2010/04/02/openrunsavemru-lastvisitedmru
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac4dd3fb");
  # http://windowsir.blogspot.com/2013/07/howto-determine-program-execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c409cb41");
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

# HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU
# HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU
# HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU
# HKEY_USERS\\<sid>\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StreamMRU

key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU';
LastVisitedPidMRU = get_hku_key_values(key:key, decode:TRUE);
key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU';
RunMRU = get_hku_key_values(key:key, decode:TRUE);
key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU';
CIDSizeMRU = get_hku_key_values(key:key, decode:TRUE);
key = '\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StreamMRU';
StreamMRU = get_hku_key_values(key:key, decode:TRUE);

mru_report = '';

foreach user (keys(LastVisitedPidMRU))
{
  foreach lvpm (keys(LastVisitedPidMRU[user]))
  {
    user = format_for_csv(data:user);
    lvpm = format_for_csv(data:lvpm);
    raw = format_for_csv(data:LastVisitedPidMRU[user][lvpm]['raw']);
    ascii = format_for_csv(data:LastVisitedPidMRU[user][lvpm]['ascii']);
    hex = LastVisitedPidMRU[user][lvpm]['hex'];

    mru_report += '"'+user+'","'+'\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU'+'","'+lvpm+'","'+raw+'","'+ascii+'","'+hex+'"\n';
  }
}

foreach user (keys(RunMRU))
{
  foreach rmru (keys(RunMRU[user]))
  {
    user = format_for_csv(data:user);
    rmru = format_for_csv(data:rmru);
    raw = format_for_csv(data:RunMRU[user][rmru]['raw']);
    ascii = format_for_csv(data:RunMRU[user][rmru]['ascii']);
    hex = RunMRU[user][rmru]['hex'];

    mru_report += '"'+user+'","'+'\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU'+'","'+rmru+'","'+raw+'","'+ascii+'","'+hex+'"\n';
  }
}

foreach user (keys(CIDSizeMRU))
{
  foreach csmru (keys(CIDSizeMRU[user]))
  {
    user = format_for_csv(data:user);
    csmru = format_for_csv(data:csmru);
    raw = format_for_csv(data:CIDSizeMRU[user][csmru]['raw']);
    ascii = format_for_csv(data:CIDSizeMRU[user][csmru]['ascii']);
    hex = CIDSizeMRU[user][csmru]['hex'];

    mru_report += '"'+user+'","'+'\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\CIDSizeMRU'+'","'+csmru+'","'+raw+'","'+ascii+'","'+hex+'"\n';
  }
}

foreach user (keys(StreamMRU))
{
  foreach smru (keys(StreamMRU[user]))
  {
    user = format_for_csv(data:user);
    smru = format_for_csv(data:smru);
    raw = format_for_csv(data:StreamMRU[user][smru]['raw']);
    ascii = format_for_csv(data:StreamMRU[user][smru]['ascii']);
    hex = StreamMRU[user][smru]['hex'];

    mru_report += '"'+user+'","'+'\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StreamMRU'+'","'+smru+'","'+raw+'","'+ascii+'","'+hex+'"\n';
  }
}


if (strlen(mru_report))
{
  mru_report = 'user,regkey,key,raw,ascii,hex\n'+mru_report;

  report = 'MRU program report attached.\n';
  
  system = get_system_name();
  
  attachments = make_list();
  attachments[0] = make_array();
  attachments[0]["type"] = "text/csv";
  attachments[0]["name"] = "mru_exe_"+system+".csv";
  attachments[0]["value"] = mru_report;
  security_report_with_attachments(
    port  : 0,
    level : 0,
    extra : report,
    attachments : attachments
  );
}
else
{
  exit(0, "No executed programs found.");
}

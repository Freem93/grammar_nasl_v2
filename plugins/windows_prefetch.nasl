#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77668);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/12 20:36:53 $");

  script_name(english:"Windows Prefetch Folder");
  script_summary(english:"Display the contents of the prefetch folder.");

  script_set_attribute(attribute:"synopsis", value:"Nessus was able to retrieve the Windows prefetch folder file list.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to retrieve and display the contents of the Windows
prefetch folder (%systemroot%\prefetch\*). This information shows
programs that have run with the prefetch and superfetch mechanisms
enabled.");
  # http://resources.infosecinstitute.com/windows-systems-artifacts-digital-forensics-part-iii-prefetch-files/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ab4c9af");
  # http://windows.microsoft.com/en-us/windows-vista/what-is-the-prefetch-folder
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6b15983");
  script_set_attribute(attribute:"see_also", value:"http://www.forensicswiki.org/wiki/Prefetch");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

report = '';

# Get Reg key with prefetch setting
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

reg_key = "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters";
regkeys = get_reg_name_value_table(handle:hklm, key:reg_key);

if (isnull(regkeys["enableprefetcher"])) enableprefetcher = "NULL";
else enableprefetcher = regkeys["enableprefetcher"];

if (isnull(regkeys["rootdirpath"])) rootdirpath = "NULL";
else rootdirpath = regkeys["rootdirpath"];

report += '+ HKLM\\'+reg_key+'\n';
report += "rootdirpath : " + regkeys["rootdirpath"]  + '\n';
report += "enableprefetcher : " + regkeys["enableprefetcher"]  + '\n';
report += '\n';

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');
share = hotfix_path2share(path:systemroot);
path = ereg_replace(string:systemroot, pattern:"^\w:(.*)", replace:"\1\prefetch");

pf_dir = list_dir(basedir:path, level:0, file_pat:"\.pf$", share:share);
if (empty_or_null(pf_dir)) exit(0, "Unable to obtain directory listing of prefetch files.");

report += '+ Prefetch file list :\n';

foreach pf (pf_dir)
{
  report += "  - " + pf + '\n';
}

security_note(port:0, extra:report);

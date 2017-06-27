#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100161);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/15 12:08:04 $");

  script_cve_id("CVE-2017-8360");

  script_name(english:"Conexant Audio Driver MicTray.exe / MicTray64.exe Keylogger");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An audio driver installed on the remote Windows host can act as a
keylogger.");
  script_set_attribute(attribute:"description",value:
"The Conexant audio driver package installed on the remote Windows
host is affected by an information disclosure vulnerability in the
debugging features of MicTray.exe or MicTray64.exe due to a
LowLevelKeyboardProc Windows hook that is being used to capture
keystrokes. This data is then leaked via debug messages that are
accessible to any process that is running in the current user session
or to a publicly readable log file. A local attacker can exploit this
vulnerability, via a specially crafted application, to access the
keylogging data and thereby disclose potentially sensitive
information.");
  # https://www.modzero.ch/modlog/archives/2017/05/11/en_keylogger_in_hewlett-packard_audio_driver/index.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?a4145f6a");
  script_set_attribute(attribute:"see_also",value:"https://www.modzero.ch/advisories/MZ-17-01-Conexant-Keylogger.txt");
  script_set_attribute(attribute:"see_also",value:"https://support.hp.com/us-en/drivers");
  script_set_attribute(attribute:"solution",value:
"Apply the appropriate vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/05/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:conexant_systems:mictray");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

# Temporarily disabled
exit(0, "Temporarily disabled.");

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

if (hotfix_check_fversion_init() != HCF_OK)
  audit(AUDIT_FN_FAIL, 'hotfix_check_fversion_init');

systemroot = hotfix_get_systemroot();
if (isnull(systemroot)) exit(1, "Failed to determine the location of %windir%.");

path = hotfix_append_path(path:systemroot, value:"system32\");

if (
 hotfix_check_fversion(
         file:"MicTray.exe",
         path:path,
         version:"1.4.0.1",
         min_version:"0"
  ) == HCF_OLDER
  ||
  hotfix_check_fversion(
         file:"MicTray64.exe",
         path:path,
         version:"1.4.0.1",
         min_version:"0"
  ) == HCF_OLDER
)
{
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

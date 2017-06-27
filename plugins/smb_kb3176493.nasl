#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92818);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/08/10 01:38:08 $");

  script_name(english:"MS KB3179528: Update for Kernel Mode Blacklist");
  script_summary(english:"Checks the version of securekernel.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an out-of-date kernel mode blacklist.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing an update to the kernel mode
blacklist. The update adds some publicly released versions of
securekernel.exe to the blacklist.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/3179528.aspx");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Only builds 10586 and 10240 are affected / build 1067 is not
os_build = get_kb_item_or_exit("SMB/WindowsVersionBuild");
if (os_build != "10586" && os_build != "10240")
  audit(AUDIT_HOST_NOT, 'affected based on its build version');

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"securekernel.exe", version:"10.0.10586.494", os_build:"10586", dir:"\system32", kb:"3176493") ||

  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"securekernel.exe", version:"10.0.10240.17022", os_build:"10240", dir:"\system32", kb:"3176492")
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

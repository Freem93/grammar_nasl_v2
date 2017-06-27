#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85880);
  script_version("$Revision: 1.2 $");
  script_xref(name:"IAVA", value:"2015-A-0217");
  script_cvs_date("$Date: 2015/09/13 16:16:40 $");

  script_name(english:"MS KB3083992: Update to Improve AppLocker Publisher Rule Enforcement");
  script_summary(english:"Checks the version of Appidsvc.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a security update that prevents a
potential rules bypass.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3083992, a defense-in-depth
update that improves the enforcement of publisher rules by Windows
AppLocker. Specifically, the update corrects how AppLocker handles
certificates to prevent bypassing publisher rules.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/3083992");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/3083992");
  script_set_attribute(attribute:"solution", value:"Install Microsoft KB3083992.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

kb = '3083992';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Appidsvc.dll", version:"6.3.9600.18002", min_version:"6.3.9600.16000", dir:"\system32", kb:kb) ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Appidsvc.dll", version:"6.2.9200.21579", min_version:"6.2.9200.20000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Appidsvc.dll", version:"6.2.9200.17465", min_version:"6.2.9200.16000", dir:"\system32", kb:kb) ||
 
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Appidsvc.dll", version:"6.1.7600.23153", min_version:"6.1.7601.22000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Appidsvc.dll", version:"6.1.7601.18950", min_version:"6.1.7600.16000", dir:"\system32", kb:kb)
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

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82779);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/04/15 02:34:48 $");

  script_name(english:"MS KB3045755: Update to Improve PKU2U Authentication");
  script_summary(english:"Checks the version of Pku2u.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update that improves
the authentication used by the Public Key Cryptography User-to-User
(PKU2U) security support provider (SSP).");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/3045755.aspx");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of updates for Windows 8.1, RT 8.1, and
2012 R2.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

kb = '3045755';

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# fix does not increment sp version
if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Pku2u.dll", version:"6.3.9600.17728", min_version:"6.3.9600.16000", dir:"\system32", kb:kb)
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

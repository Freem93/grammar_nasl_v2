#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81731);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/11 02:12:42 $");

  script_name(english:"MS KB3033929: Availability of SHA-2 Code Signing Support for Windows 7 and Windows Server 2008 R2");
  script_summary(english:"Checks the version of crypt32.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing an update that improves cryptography and
digital certificate handling in Windows.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Microsoft KB3033929, an update that
improves cryptography and digital certificate handling in Windows 7
and Windows Server 2008 R2.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/3033929");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/3033929");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7 and 2008 R2.

Note that KB3033929 has binaries in common with KB3035131 from
bulletin MS15-025. Customers planning to install both should install
KB3035131 before KB3033929.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");

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
include("byte_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 SP1 and Windows Server 2008 R2 SP1
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"crypt32.dll", version:"6.1.7601.22948", min_version:"6.1.7601.21000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"crypt32.dll", version:"6.1.7601.18741", min_version:"6.1.7600.17000", dir:"\system32")
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

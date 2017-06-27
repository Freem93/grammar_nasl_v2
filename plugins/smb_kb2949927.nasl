# @DEPRECATED@
#
# This script has been deprecated as Microsoft has removed
# the download.
#
# Disabled on 2014/10/17.
#

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78445);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/10/18 00:32:20 $");

  script_name(english:"MS KB2949927: Availability of SHA-2 Hashing Algorithm for Windows 7 and Windows Server 2008 R2");
  script_summary(english:"Checks the version of crypt32.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing an update that improves cryptography and
digital certificate handling in Windows.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Microsoft KB2949927, an update that
improves cryptography and digital certificate handling in Windows 7
and Windows Server 2008 R2.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2949927");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/kb/2949927");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 7 and 2008 R2.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

# Deprecated.
exit(0, "Microsoft has pulled the download for KB 2949927 and recommends that customers experiencing issues with it uninstall the update.");


include("audit.inc");
include("byte_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 SP1 and Windows Server 2008 R2 SP1
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"crypt32.dll", version:"6.1.7601.22736", min_version:"6.1.7601.21000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"crypt32.dll", version:"6.1.7601.18526", min_version:"6.1.7600.17000", dir:"\system32")
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

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83359);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/05/13 01:33:16 $");

  script_name(english:"MS KB3042058: Update to Default Cipher Suite Priority Order");
  script_summary(english:"Checks the version of schannel.dll.");

  script_set_attribute(attribute:"synopsis", value:"
The remote Windows host is missing an update to the cipher suite.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing an update to the cryptographic
cipher suite prioritization. The update adds additional cipher suites
and improves cipher suite priority ordering.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/3042058");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7, 2008 R2, 8,
2012, 8.1, and 2012 R2.

Note that Microsoft has only made this update available via the
Microsoft Download Center. It will be available via Microsoft Update
and WSUS in Q4 of 2015.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

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

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (

  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Schannel.dll", version:"6.3.9600.17728", min_version:"6.3.9600.16000", dir:"\system32") ||

  # Windows 8 / Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Schannel.dll", version:"6.2.9200.21410", min_version:"6.2.9200.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Schannel.dll", version:"6.2.9200.17293", min_version:"6.2.9200.16000", dir:"\system32") ||

  # Windows 7 SP1 and Windows Server 2008 R2 SP1
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Schannel.dll", version:"6.1.7601.23017", min_version:"6.1.7601.21000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Schannel.dll", version:"6.1.7601.18812", min_version:"6.1.7600.17000", dir:"\system32")
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

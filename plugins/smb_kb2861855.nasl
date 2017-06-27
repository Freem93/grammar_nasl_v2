#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69333);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/09 20:36:07 $");

  script_name(english:"MS KB2861855: Updates to Improve Remote Desktop Protocol Network-Level Authentication");
  script_summary(english:"Checks version of Icaapi.dll or tssecsrv.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing an update for Remote Desktop Protocol.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Microsoft KB2861855.  This update provides
defense-in-depth measures for Remote Desktop Protocol Network Level
Authentication.");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Windows Vista, Server 2008, 7, and
Server 2008 R2 :

http://technet.microsoft.com/en-us/security/advisory/2861855");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp_range(vista:'2', win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"tssecsrv.sys", version:"6.1.7601.22361", min_version:"6.1.7601.22000", dir:"\system32\drivers") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"tssecsrv.sys", version:"6.1.7601.18186", min_version:"6.1.7600.17000", dir:"\system32\drivers") ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"icaapi.dll", version:"6.0.6002.23140", min_version:"6.0.6002.23000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"icaapi.dll", version:"6.0.6002.18868", min_version:"6.0.6000.16000", dir:"\system32")
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

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69332);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/30 21:09:49 $");

  script_name(english:"MS KB2862966: Updates to Improve Cryptography and Digital Certificate Handling in Windows");
  script_summary(english:"Check version of crypt32.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing an update that improves cryptography and
digital certificate handling in Windows."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing Microsoft KB2862966, an update that improves
cryptography and digital certificate handling in Windows."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2854544");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/kb/2862966");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, and 2012 :

https://support.microsoft.com/kb/2862966"
  );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 / Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"crypt32.dll", version:"6.2.9200.20774", min_version:"6.2.9200.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"crypt32.dll", version:"6.2.9200.16666", min_version:"6.2.9200.16000", dir:"\system32") ||

  # Windows 7 SP1 and Windows Server 2008 R2 SP1
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"crypt32.dll", version:"6.1.7601.22380", min_version:"6.1.7601.21000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"crypt32.dll", version:"6.1.7601.18205", min_version:"6.1.7600.17000", dir:"\system32") ||

  # Vista SP2 / Windows 2008 SP2
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"crypt32.dll", version:"6.0.6002.23154", min_version:"6.0.6002.22000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"crypt32.dll", version:"6.0.6002.18881", min_version:"6.0.6002.18000", dir:"\system32")
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

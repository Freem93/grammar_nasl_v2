#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84763);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/07/15 17:13:59 $");

  script_name(english:"MS KB3057154: Update to harden use of DES encryption (3057154)");
  script_summary(english:"Checks the file version of Kerberos.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a Microsoft security update.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing KB3057154, which hardens the use of
DES encryption for secure communication.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/3057154");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

kb = '3057154';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Kerberos.dll", version:"6.2.9200.21525", min_version:"6.2.9200.20000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Kerberos.dll", version:"6.2.9200.17415", min_version:"6.2.9200.16000", dir:"\system32", kb:kb) ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Kerberos.dll", version:"6.1.7601.23115", min_version:"6.1.7601.22000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Kerberos.dll", version:"6.1.7601.18912", min_version:"6.1.7600.16000", dir:"\system32", kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Kerberos.dll", version:"6.0.6002.23734", min_version:"6.0.6002.23000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Kerberos.dll", version:"6.0.6002.19428", min_version:"6.0.6001.18000", dir:"\system32", kb:kb)
)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

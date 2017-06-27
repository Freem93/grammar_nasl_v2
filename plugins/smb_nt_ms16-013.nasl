#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88645);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/29 19:33:20 $");

  script_cve_id("CVE-2016-0038");
  script_bugtraq_id(82639);
  script_osvdb_id(134308);
  script_xref(name:"MSFT", value:"MS16-013");
  script_xref(name:"IAVA", value:"2016-A-0045");

  script_name(english:"MS16-013: Security Update for Windows Journal to Address Remote Code Execution (3134811)");
  script_summary(english:"Checks the version of journal.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a remote code execution
vulnerability in Windows Journal due to improper parsing of Journal
files. An unauthenticated, remote attacker can exploit this by
convincing a user to open a specially crafted Journal file, resulting
in the execution of arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-013");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

bulletin = 'MS16-013';
kbs = make_list("3115858", "3135173", "3135174");
kb = '3115858';

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

base_path = hotfix_get_commonfilesdir();
if (!base_path) base_path = hotfix_get_commonfilesdirx86();

if (!base_path) audit(AUDIT_PATH_NOT_DETERMINED, "Common Files");

full_path = hotfix_append_path(path:base_path, value:"\microsoft shared\ink");
# Vista, 7, 2008 R2, 8.1, 2012, 2012 R2, and 10.
if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"journal.dll", version:"6.0.6002.23888", min_version:"6.0.6002.23000", path:full_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"journal.dll", version:"6.0.6002.19578", min_version:"6.0.6001.18000", path:full_path, bulletin:bulletin, kb:kb) ||

  #Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"journal.dll", version:"6.1.7601.23316", min_version:"6.1.7601.22000", path:full_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"journal.dll", version:"6.1.7601.19112", min_version:"6.1.7600.18000", path:full_path, bulletin:bulletin, kb:kb) ||

   # windows server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"journal.dll", version:"6.2.9200.21743", min_version:"6.2.9200.20000", path:full_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"journal.dll", version:"6.2.9200.17623", min_version:"6.2.9200.16000", path:full_path, bulletin:bulletin, kb:kb) ||

  # windows 8.1 / windows server 2012 r2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"journal.dll", version:"6.3.9600.18189", min_version:"6.3.9600.16000", path:full_path, bulletin:bulletin, kb:kb) ||

  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"journal.dll", version:"10.0.10240.16683", path:full_path, bulletin:bulletin, kb:"3135174") ||
  # 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"journal.dll", version:"10.0.10586.103", min_version:"10.0.10586.0", path:full_path, bulletin:bulletin, kb:"3135173")

)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}


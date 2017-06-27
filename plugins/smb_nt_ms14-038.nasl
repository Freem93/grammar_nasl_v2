#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76407);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/16 21:12:00 $");

  script_cve_id("CVE-2014-1824");
  script_bugtraq_id(68396);
  script_osvdb_id(108826);
  script_xref(name:"MSFT", value:"MS14-038");

  script_name(english:"MS14-038: Vulnerability in Windows Journal Could Allow Remote Code Execution (2975689)");
  script_summary(english:"Checks the version of Journal.dll.");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a code execution vulnerability
due to an error related to parsing Windows Journal files. An attacker
could convince a user into opening a specially crafted file, resulting
in the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-038");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS14-038';
kb = "2971850";

kbs = make_list(kb, "2974286");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

commonfiles = hotfix_get_commonfilesdir();
if (!commonfiles) commonfiles = hotfix_get_commonfilesdirx86();

if (!commonfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');

journal_path = commonfiles + "\microsoft shared\ink";

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Journal.dll", version:"6.3.9600.17195", min_version:"6.3.9600.17000", path:journal_path, bulletin:bulletin, kb:kb) ||
  # without KB2919355
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Journal.dll", version:"6.3.9600.16670", min_version:"6.3.9600.16000", path:journal_path, bulletin:bulletin, kb:"2974286") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Journal.dll", version:"6.2.9200.21135", min_version:"6.2.9200.20000", path:journal_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Journal.dll", version:"6.2.9200.17016", min_version:"6.2.9200.16000", path:journal_path, bulletin:bulletin, kb:kb) ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Journal.dll", version:"6.1.7601.22709", min_version:"6.1.7601.22000", path:journal_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Journal.dll", version:"6.1.7601.18493", min_version:"6.1.7600.18000", path:journal_path, bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Journal.dll", version:"6.0.6002.23415", min_version:"6.0.6002.23000", path:journal_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Journal.dll", version:"6.0.6002.19116", min_version:"6.0.6002.18000", path:journal_path, bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

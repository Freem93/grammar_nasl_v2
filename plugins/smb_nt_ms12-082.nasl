#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63229);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2012-1537");
  script_bugtraq_id(56839);
  script_osvdb_id(88312);
  script_xref(name:"MSFT", value:"MS12-082");
  script_xref(name:"IAVB", value:"2012-B-0124");

  script_name(english:"MS12-082: Vulnerability in DirectPlay Could Allow Remote Code Execution (2770660)");
  script_summary(english:"Checks version of Dpnet.DLL");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host could allow arbitrary code execution.");
  script_set_attribute(attribute:"description", value:
"The version of Windows on the remote host is affected by a heap
overflow vulnerability in DirectPlay that could allow an attacker to
execute arbitrary code on the system.  Successful exploitation requires
that an attacker convince a user to view a specially crafted Office
document with embedded content.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-082");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for XP, 2003, Vista, 2008, 7,
2008 R2, 8, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS12-082';
kb = '2770660';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (!get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version")) audit(AUDIT_NOT_INST, "DirectX");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Dpnet.dll", version:"6.2.9200.16450", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Dpnet.dll", version:"6.2.9200.20554", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Dpnet.dll", version:"6.1.7600.17157", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Dpnet.dll", version:"6.1.7600.21360", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Dpnet.dll", version:"6.1.7601.17989", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Dpnet.dll", version:"6.1.7601.22150", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Vista Service Pack 2 / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Dpnet.dll", version:"6.0.6002.18722", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Dpnet.dll", version:"6.0.6002.22964", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2003 Service Pack 2 / Windows XP Professional x64 Edition Service Pack 2
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Dpnet.dll", version:"5.3.3790.5083", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP Service Pack 3
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Dpnet.dll", version:"5.3.2600.6311", dir:"\system32", bulletin:bulletin, kb:kb)
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

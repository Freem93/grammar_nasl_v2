#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59908);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2012-1891");
  script_bugtraq_id(54308);
  script_osvdb_id(83657);
  script_xref(name:"MSFT", value:"MS12-045");
  script_xref(name:"IAVA", value:"2012-A-0107");

  script_name(english:"MS12-045: Vulnerability in Microsoft Data Access Components Could Allow Remote Code Execution (2698365)");
  script_summary(english:"Checks the version of Msado15.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Data Access Components.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Data Access Components (MDAC) installed on
the remote Windows host is affected by a remote code execution
vulnerability that could allow arbitrary code execution if a user
views a specially crafted web page.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-158/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/280");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-045");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:data_access_components");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-045';
kb = "2698365";
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

ado_path = hotfix_get_commonfilesdir() + "\system\ado";
if (!ado_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:ado_path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL,share);


if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Msado15.dll", version:"6.1.7600.17036", min_version:"6.1.7600.16000", path:ado_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Msado15.dll", version:"6.1.7600.21227", min_version:"6.1.7600.20000", path:ado_path, bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Msado15.dll", version:"6.1.7601.17857", min_version:"6.1.7601.17000", path:ado_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Msado15.dll", version:"6.1.7601.22012", min_version:"6.1.7601.21000", path:ado_path, bulletin:bulletin, kb:kb) ||


  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msado15.dll", version:"6.0.6002.22869", min_version:"6.0.6002.22000", path:ado_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msado15.dll", version:"6.0.6002.18644", min_version:"6.0.6002.18000", path:ado_path, bulletin:bulletin, kb:kb) ||

  # Windows 2003 and XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Msado15.dll", version:"2.82.5011.0",                                  path:ado_path, bulletin:bulletin, kb:kb) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Msado15.dll", version:"2.81.3014.0",                                  path:ado_path, bulletin:bulletin, kb:kb)
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


# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53383);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/07 12:06:04 $");

  script_cve_id("CVE-2011-0096");
  script_bugtraq_id(46055);
  script_osvdb_id(70693);
  script_xref(name:"CERT", value:"326549");
  script_xref(name:"EDB-ID", value:"16071");
  script_xref(name:"Secunia", value:"43093");
  script_xref(name:"MSFT", value:"MS11-026");

  script_name(english:"MS11-026: Vulnerability in MHTML Could Allow Information Disclosure (2503658)");
  script_summary(english:"Checks MHTML version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A flaw exists in the way MHTML interprets MIME-formatted requests for
content blocks within a document.  An attacker, exploiting this flaw,
could cause a victim to run malicious scripts when visiting various web
sites, resulting in information disclosure."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-026");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-026';
kb = '2503658';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Inetcomm.dll", version:"6.1.7601.21677", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Inetcomm.dll", version:"6.1.7601.17574", min_version:"6.1.7600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Inetcomm.dll", version:"6.1.7600.20918", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Inetcomm.dll", version:"6.1.7600.16776", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Inetcomm.dll", version:"6.0.6002.22601", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Inetcomm.dll", version:"6.0.6002.18417", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Inetcomm.dll", version:"6.0.6001.22867", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Inetcomm.dll", version:"6.0.6001.18612", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Inetcomm.dll", version:"6.0.3790.4841", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Inetcomm.dll", version:"6.0.2900.6090", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

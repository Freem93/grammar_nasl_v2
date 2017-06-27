#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76406);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2014-1763",
    "CVE-2014-1765",
    "CVE-2014-2783",
    "CVE-2014-2785",
    "CVE-2014-2786",
    "CVE-2014-2787",
    "CVE-2014-2788",
    "CVE-2014-2789",
    "CVE-2014-2790",
    "CVE-2014-2791",
    "CVE-2014-2792",
    "CVE-2014-2794",
    "CVE-2014-2795",
    "CVE-2014-2797",
    "CVE-2014-2798",
    "CVE-2014-2800",
    "CVE-2014-2801",
    "CVE-2014-2802",
    "CVE-2014-2803",
    "CVE-2014-2804",
    "CVE-2014-2806",
    "CVE-2014-2807",
    "CVE-2014-2809",
    "CVE-2014-2813"
  );
  script_bugtraq_id(
    66200,
    66244,
    68369,
    68371,
    68372,
    68373,
    68374,
    68375,
    68376,
    68377,
    68378,
    68379,
    68380,
    68381,
    68382,
    68383,
    68384,
    68385,
    68386,
    68387,
    68388,
    68389,
    68390,
    68391
  );
  script_osvdb_id(
    104612,
    104582,
    104583,
    108803,
    108804,
    108805,
    108806,
    108807,
    108808,
    108809,
    108810,
    108811,
    108812,
    108813,
    108814,
    108815,
    108816,
    108817,
    108818,
    108819,
    108820,
    108821,
    108822,
    108823,
    108824
  );
  script_xref(name:"MSFT", value:"MS14-037");

  script_name(english:"MS14-037: Cumulative Security Update for Internet Explorer (2975687)");
  script_summary(english:"Checks the version of Mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Internet Explorer (IE) Security Update
2975687.

The version of Internet Explorer installed on the remote host is
affected by multiple vulnerabilities, the majority of which are remote
code execution vulnerabilities. An attacker could exploit these
vulnerabilities by convincing a user to visit a specially crafted web
page.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532797/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-037");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-217");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 6, 7, 8,
9, 10, and 11.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS14-037';
kb = '2962872';

kbs = make_list(kb, '2963952');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / 2012 R2
  #
  # - Internet Explorer 11 with KB2919355 applied
  hotfix_is_vulnerable(os:"6.3", file:"Mshtml.dll", version:"11.0.9600.17207", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 11 without KB2919355 applied
  hotfix_is_vulnerable(os:"6.3", file:"Mshtml.dll", version:"11.0.9600.16672", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:'2963952') ||

  # Windows 8 / 2012
  #
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.21145", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.17028", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  # - Internet Explorer 11 with KB2929437 applied
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"11.0.9600.17207", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 11 without KB2929437 applied
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"11.0.9600.16672", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:'2963952') ||
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.21145", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.17028", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.20672", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.16561", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.22703", min_version:"8.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.18487", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.20672", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.16561", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.23603", min_version:"8.0.6001.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.19543", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.23413", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.19114", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # Windows 2003
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.23603", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21396", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.5358",  min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
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

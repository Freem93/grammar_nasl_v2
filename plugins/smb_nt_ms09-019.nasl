#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39341);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/09 20:55:00 $");

  script_cve_id(
    "CVE-2007-3091",
    "CVE-2009-1140",
    "CVE-2009-1141",
    "CVE-2009-1528",
    "CVE-2009-1529",
    "CVE-2009-1530",
    "CVE-2009-1531",
    "CVE-2009-1532"
  );
  script_bugtraq_id(
    24283,
    35198,
    35200,
    35222,
    35223,
    35224,
    35234,
    35235
  );
  script_osvdb_id(
    38497,
    54944,
    54945,
    54946,
    54947,
    54948,
    54949,
    54950,
    54951
  );
  script_xref(name:"MSFT", value:"MS09-019");
  script_xref(name:"CERT", value:"471361");
  script_xref(name:"EDB-ID", value:"33024");

  script_name(english:"MS09-019: Cumulative Security Update for Internet Explorer (969897)");
  script_summary(english:"Checks version of Mshtml.dll / MSrating.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through a web
browser.");
  script_set_attribute(attribute:"description", value:
"he remote host is missing IE Security Update 969897.

The remote version of IE is affected by several vulnerabilities that may
allow an attacker to execute arbitrary code on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-019");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-036/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-037/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-038/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-039/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-041/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 362, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS09-019';
kb = "969897";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.22874", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.18783", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.22121", min_version:"7.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.18024", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.22418", min_version:"7.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mshtml.dll", version:"7.0.6001.18248", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.21046", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mshtml.dll", version:"7.0.6000.16851", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.22873", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.18783", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21045", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.16850", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4504", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.22873", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.18783", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"8.0.6001.22873", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Mshtml.dll", version:"8.0.6001.18783", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"7.0.6000.21045", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"7.0.6000.16850", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"6.0.2900.5803", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"7.0.6000.16850", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.3562", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Msrating.dll", version:"6.0.2800.1972", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"5.0.3877.2200", min_version:"5.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
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

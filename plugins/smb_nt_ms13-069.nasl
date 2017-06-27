#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69829);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id(
    "CVE-2013-3201",
    "CVE-2013-3202",
    "CVE-2013-3203",
    "CVE-2013-3204",
    "CVE-2013-3205",
    "CVE-2013-3206",
    "CVE-2013-3207",
    "CVE-2013-3208",
    "CVE-2013-3209",
    "CVE-2013-3845"
  );
  script_bugtraq_id(
    62187,
    62204,
    62206,
    62207,
    62208,
    62209,
    62211,
    62212,
    62213,
    62214
  );
  script_osvdb_id(
    97092,
    97093,
    97094,
    97095,
    97096,
    97097,
    97098,
    97099,
    97100,
    97101
  );
  script_xref(name:"MSFT", value:"MS13-069");

  script_name(english:"MS13-069: Cumulative Security Update for Internet Explorer (2870699)");
  script_summary(english:"Checks version of Mshtml.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Internet Explorer (IE) Security Update
2870699.

The installed version of IE is affected by multiple vulnerabilities
that could allow an attacker to execute arbitrary code on the remote
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-216/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-217/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-218/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-219/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-220/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-221/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-222/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-223/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-224/");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-069");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for XP, 2003, Vista, 2008, 7,
2008 R2, 8, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS13-069 Microsoft Internet Explorer CCaret Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-069';
kb = '2870699';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 / 2012
  #
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.20796", min_version:"10.0.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.16688", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  #
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.20794", min_version:"10.0.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.16686", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.20617", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.16506", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.22410", min_version:"8.0.7601.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.18228", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.20617", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.16506", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.23520", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.19458", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.23183", min_version:"7.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.18910", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.23520", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21352", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.5208",  min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"8.0.6001.23520", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"7.0.6000.21352", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"6.0.2900.6434",  min_version:"6.0.2900.0", dir:"\system32", bulletin:bulletin, kb:kb)
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

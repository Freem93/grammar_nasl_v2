#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(67212);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id(
    "CVE-2013-3115",
    "CVE-2013-3143",
    "CVE-2013-3144",
    "CVE-2013-3145",
    "CVE-2013-3146",
    "CVE-2013-3147",
    "CVE-2013-3148",
    "CVE-2013-3149",
    "CVE-2013-3150",
    "CVE-2013-3151",
    "CVE-2013-3152",
    "CVE-2013-3153",
    "CVE-2013-3161",
    "CVE-2013-3162",
    "CVE-2013-3163",
    "CVE-2013-3164",
    "CVE-2013-3166",
    "CVE-2013-3846",
    "CVE-2013-4015"
  );
  script_bugtraq_id(
    60941,
    60957,
    60962,
    60963,
    60964,
    60965,
    60966,
    60967,
    60968,
    60969,
    60970,
    60971,
    60972,
    60973,
    60974,
    60975,
    60976,
    61482,
    62372,
    62376
  );
  script_osvdb_id(
    94967,
    94968,
    94969,
    94971,
    94972,
    94973,
    94974,
    94975,
    94976,
    94977,
    94978,
    94979,
    94980,
    94981,
    94982,
    94983,
    94984,
    95687,
    97340
  );
  script_xref(name:"MSFT", value:"MS13-055");

  script_name(english:"MS13-055: Cumulative Security Update for Internet Explorer (2846071)");
  script_summary(english:"Checks version of Mshtml.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Internet Explorer (IE) Security Update
2846071.

The installed version of IE is affected by multiple vulnerabilities that
could allow an attacker to execute arbitrary code on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-162/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-163/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-164/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-165/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-166/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-167/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-172/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-173/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-174/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-175/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-176/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-231/");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-055");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for XP, 2003, Vista, 2008, 7,
2008 R2, 8, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS13-055 Microsoft Internet Explorer CAnchorElement Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS13-055';
kb = '2846071';

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
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.20742", min_version:"10.0.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.16635", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  #
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.20742", min_version:"10.0.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.16635", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.20606", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.16496", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.22341", min_version:"8.0.7601.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.18170", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.20606", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.16496", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.23507", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.19443", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.23133", min_version:"7.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.18861", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.23507", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21342", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.5170",  min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"8.0.6001.23507", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"7.0.6000.21342", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"6.0.2900.6400",  min_version:"6.0.2900.0", dir:"\system32", bulletin:bulletin, kb:kb)
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

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56455);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id(
    "CVE-2011-1993",
    "CVE-2011-1995",
    "CVE-2011-1996",
    "CVE-2011-1997",
    "CVE-2011-1998",
    "CVE-2011-1999",
    "CVE-2011-2000",
    "CVE-2011-2001"
  );
  script_bugtraq_id(
    49947,
    49960,
    49961,
    49962,
    49963,
    49964,
    49965,
    49966
  );
  script_osvdb_id(76206, 76207, 76208, 76209, 76210, 76211, 76212, 76213);
  script_xref(name:"MSFT", value:"MS11-081");

  script_name(english:"MS11-081: Critical Cumulative Security Update for Internet Explorer (2586448)");
  script_summary(english:"Checks version of Mshtml.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through a web
browser."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing Internet Explorer (IE) Security Update
2586448.

The installed version of IE is affected by several vulnerabilities that
could allow an attacker to execute arbitrary code on the remote host."
  );
  # http://ifsec.blogspot.com/2011/10/internet-explorer-select-element-remote.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e0ffba2");
  # http://ifsec.blogspot.com/2011/10/internet-explorer-option-element-remote.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23a44ebd");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-287/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-288/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-289/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-290/");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-081");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for XP, 2003, Vista, 2008, 7,
and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS11-081 Microsoft Internet Explorer Option Element Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS11-081';
kb = '2586448';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 and Windows Server 2008 R2
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1",       file:"Mshtml.dll", version:"9.0.8112.20537", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",       file:"Mshtml.dll", version:"9.0.8112.16437", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.21830", min_version:"8.0.7601.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.17699", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Mshtml.dll", version:"8.0.7600.21062", min_version:"8.0.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Mshtml.dll", version:"8.0.7600.16891", min_version:"8.0.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"9.0.8112.20537", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"9.0.8112.16437", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.23250", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       file:"Mshtml.dll", version:"8.0.6001.19154", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.22698", min_version:"7.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.18510", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.23250", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.19154", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21306", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.17104", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4904",  min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"8.0.6001.23250", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"8.0.6001.19154", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"7.0.6000.21306", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"7.0.6000.17104", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mshtml.dll", version:"6.0.2900.6148",  min_version:"6.0.2900.0", dir:"\system32", bulletin:bulletin, kb:kb)
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

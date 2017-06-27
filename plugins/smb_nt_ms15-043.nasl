#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83358);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id(
    "CVE-2015-1658",
    "CVE-2015-1684",
    "CVE-2015-1685",
    "CVE-2015-1686",
    "CVE-2015-1688",
    "CVE-2015-1689",
    "CVE-2015-1691",
    "CVE-2015-1692",
    "CVE-2015-1694",
    "CVE-2015-1703",
    "CVE-2015-1704",
    "CVE-2015-1705",
    "CVE-2015-1706",
    "CVE-2015-1708",
    "CVE-2015-1709",
    "CVE-2015-1710",
    "CVE-2015-1711",
    "CVE-2015-1712",
    "CVE-2015-1713",
    "CVE-2015-1714",
    "CVE-2015-1717",
    "CVE-2015-1718"
  );
  script_bugtraq_id(
    74504,
    74505,
    74506,
    74507,
    74508,
    74509,
    74510,
    74511,
    74512,
    74513,
    74514,
    74515,
    74516,
    74517,
    74518,
    74519,
    74520,
    74521,
    74522,
    74530,
    74606,
    74607
  );
  script_osvdb_id(
    121975,
    121976,
    121977,
    121978,
    121979,
    121980,
    121981,
    121982,
    121983,
    121984,
    121985,
    121986,
    121987,
    121988,
    121989,
    121990,
    121991,
    121992,
    121993,
    121994,
    121995,
    121996
  );
  script_xref(name:"MSFT", value:"MS15-043");

  script_name(english:"MS15-043: Cumulative Security Update for Internet Explorer (3049563)");
  script_summary(english:"Checks the version of Mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3049563. It is, therefore, affected
by multiple vulnerabilities, the majority of which are remote code
execution vulnerabilities. An attacker can exploit these
vulnerabilities by convincing a user to visit a specially crafted
website.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-043");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 6, 7, 8,
9, 10, and 11.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS15-043';
kb       = '3049563';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Some of the 2k3 checks could flag XP 64, which is unsupported
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln   = 0;

if (
  # Windows 8.1 / 2012 R2
  #
  # - Internet Explorer 11 with KB2919355 applied
  hotfix_is_vulnerable(os:"6.3", file:"Mshtml.dll", version:"11.0.9600.17801", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / 2012
  #
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.21470", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.17357", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  # - Internet Explorer 11 with KB2929437 applied
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"11.0.9600.17801", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.21470", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.17357", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.20758", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.16644", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.23038", min_version:"8.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.18835", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.20758", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.16644", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.23676", min_version:"8.0.6001.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.19621", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.23675", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.19367", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # Windows 2003
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.23676", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7 64bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21455", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.5602",  min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;

if( vuln )
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

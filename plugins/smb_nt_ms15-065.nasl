#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84761);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id(
    "CVE-2015-1729",
    "CVE-2015-1733",
    "CVE-2015-1738",
    "CVE-2015-1767",
    "CVE-2015-2372",
    "CVE-2015-2383",
    "CVE-2015-2384",
    "CVE-2015-2385",
    "CVE-2015-2388",
    "CVE-2015-2389",
    "CVE-2015-2390",
    "CVE-2015-2391",
    "CVE-2015-2397",
    "CVE-2015-2398",
    "CVE-2015-2401",
    "CVE-2015-2402",
    "CVE-2015-2403",
    "CVE-2015-2404",
    "CVE-2015-2406",
    "CVE-2015-2408",
    "CVE-2015-2410",
    "CVE-2015-2411",
    "CVE-2015-2412",
    "CVE-2015-2413",
    "CVE-2015-2414",
    "CVE-2015-2419",
    "CVE-2015-2421",
    "CVE-2015-2422",
    "CVE-2015-2425"
  );
  script_bugtraq_id(
    75626,
    75631,
    75636,
    75677,
    75679,
    75687,
    75689,
    75690,
    75745
  );
  script_osvdb_id(
    123546,
    124554,
    124555,
    124556,
    124557,
    124558,
    124559,
    124560,
    124561,
    124562,
    124563,
    124564,
    124565,
    124566,
    124567,
    124568,
    124569,
    124570,
    124571,
    124572,
    124573,
    124574,
    124575,
    124576,
    124577,
    124578,
    124579,
    124580,
    124597
  );
  script_xref(name:"MSFT", value:"MS15-065");

  script_name(english:"MS15-065: Cumulative Security Update for Internet Explorer (3076321)");
  script_summary(english:"Checks the version of Mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3076321. It is, therefore, affected
by multiple vulnerabilities, the majority of which are remote code
execution vulnerabilities. An attacker can exploit these
vulnerabilities by convincing a user to visit a specially crafted
website.

Hosts running Internet Explorer 10 or Internet Explorer 11 will not 
be fully protected until both security update 3065822 and security 
update 3075516 are applied to the system. Security update 3075516
may require manual installation depending on your patching method.

Note that the majority of the vulnerabilities addressed by Cumulative
Security Update 3076321 are mitigated by the Enhanced Security
Configuration (ESC) mode which is enabled by default on Windows Server
2003, 2008, 2008 R2, 2012, and 2012 R2.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-065");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 6, 7, 8,
9, 10, and 11.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/15");

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

bulletin = 'MS15-065';
kb       = '3065822';
kb2       = '3075516';

kbs = make_list(kb,kb2);
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
  #######################################
  # KB 3076321 (kb)                     #
  #######################################

  # Windows 8.1 / 2012 R2
  #
  # - Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", file:"Mshtml.dll", version:"11.0.9600.17905", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / 2012
  #
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.17412", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.21523", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  # - Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"11.0.9600.17915", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.17412", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.21523", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.16669", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.20784", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.18896", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.23099", min_version:"8.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.16669", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.20784", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.19652", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.23707", min_version:"8.0.6001.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.19421", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.23728", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.23707", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21481", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.5662",  min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;



if (
  #######################################
  # KB 3075516 (kb2)                    #
  #######################################

  # Windows 8.1 / 2012 R2
  #
  # - Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", file:"jscript9.dll", version:"11.0.9600.17923", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb2) ||

  # Windows 8 / 2012
  #
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", file:"jscript9.dll", version:"10.0.9200.21531", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb2) ||
  hotfix_is_vulnerable(os:"6.2", file:"jscript9.dll", version:"10.0.9200.17422", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb2) ||

  # Windows 7 / 2008 R2
  # - Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jscript9.dll", version:"11.0.9600.17918", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb2) ||
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jscript9.dll", version:"10.0.9200.21531", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb2) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jscript9.dll", version:"10.0.9200.17422", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb2)
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

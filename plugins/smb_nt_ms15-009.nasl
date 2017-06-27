#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81262);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id(
    "CVE-2014-8967",
    "CVE-2015-0017",
    "CVE-2015-0018",
    "CVE-2015-0019",
    "CVE-2015-0020",
    "CVE-2015-0021",
    "CVE-2015-0022",
    "CVE-2015-0023",
    "CVE-2015-0025",
    "CVE-2015-0026",
    "CVE-2015-0027",
    "CVE-2015-0028",
    "CVE-2015-0029",
    "CVE-2015-0030",
    "CVE-2015-0031",
    "CVE-2015-0035",
    "CVE-2015-0036",
    "CVE-2015-0037",
    "CVE-2015-0038",
    "CVE-2015-0039",
    "CVE-2015-0040",
    "CVE-2015-0041",
    "CVE-2015-0042",
    "CVE-2015-0043",
    "CVE-2015-0044",
    "CVE-2015-0045",
    "CVE-2015-0046",
    "CVE-2015-0048",
    "CVE-2015-0049",
    "CVE-2015-0050",
    "CVE-2015-0051",
    "CVE-2015-0052",
    "CVE-2015-0053",
    "CVE-2015-0054",
    "CVE-2015-0055",
    "CVE-2015-0066",
    "CVE-2015-0067",
    "CVE-2015-0068",
    "CVE-2015-0069",
    "CVE-2015-0070",
    "CVE-2015-0071"
  );
  script_bugtraq_id(
    71483,
    72402,
    72403,
    72404,
    72409,
    72410,
    72411,
    72412,
    72413,
    72414,
    72415,
    72416,
    72417,
    72418,
    72419,
    72420,
    72421,
    72422,
    72423,
    72424,
    72425,
    72426,
    72436,
    72437,
    72438,
    72439,
    72440,
    72441,
    72442,
    72443,
    72444,
    72445,
    72446,
    72447,
    72448,
    72453,
    72454,
    72455,
    72478,
    72479,
    72480
  );
  script_osvdb_id(
    115477,
    118135,
    118136,
    118137,
    118138,
    118139,
    118140,
    118141,
    118142,
    118143,
    118144,
    118145,
    118146,
    118147,
    118148,
    118149,
    118150,
    118151,
    118152,
    118153,
    118154,
    118155,
    118156,
    118157,
    118158,
    118159,
    118160,
    118161,
    118162,
    118163,
    118164,
    118165,
    118166,
    118167,
    118168,
    118169,
    118170,
    118171,
    118172,
    118173,
    118174
  );
  script_xref(name:"MSFT", value:"MS15-009");

  script_name(english:"MS15-009: Security Update for Internet Explorer (3034682)");
  script_summary(english:"Checks the version of Mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3034682. It is, therefore, affected
by multiple vulnerabilities, the majority of which are remote code
execution vulnerabilities. An attacker can exploit these by convincing
a user to visit a specially crafted web page.

Hosts running Internet Explorer 9, Internet Explorer 10, or Internet 
Explorer 11 will not be fully protected until both security update 
3021952 and security update 3034196 are applied to the system.
Security update 3034196 may require manual installation depending on
your patching method.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-009");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-14-403/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 6, 7, 8,
9, 10, and 11.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/05");

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

bulletin = 'MS15-009';
kb = '3021952';
kb2 = '3034196';

kbs = make_list(kb, kb2);
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
  # KB 3021952 (kb)                     #
  #######################################

  # Windows 8.1 / 2012 R2
  #
  # - Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", file:"Mshtml.dll", version:"11.0.9600.17631", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / 2012
  #
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.21345", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.17228", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  # - Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"11.0.9600.17631", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.21345", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.17229", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.20725", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.16609", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.22921", min_version:"8.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.18715", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.20725", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.16609", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.23655", min_version:"8.0.6001.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.19600", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.23590", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.19281", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.23644", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21432", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.5508",  min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;

if (

  #######################################
  # KB 3034196 (kb2)                    #
  #######################################

  # Windows 8.1 / 2012 R2
  #
  # - Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", file:"jscript9.dll", version:"11.0.9600.17640", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb2) ||

  # Windows 8 / 2012
  #
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", file:"jscript9.dll", version:"10.0.9200.21359", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb2) ||
  hotfix_is_vulnerable(os:"6.2", file:"jscript9.dll", version:"10.0.9200.17241", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb2) ||

  # Windows 7 / 2008 R2
  # - Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jscript9.dll", version:"11.0.9600.17640", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb2) ||
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jscript9.dll", version:"10.0.9200.21359", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb2) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jscript9.dll", version:"10.0.9200.17241", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb2) ||
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jscript9.dll", version:"9.0.8112.20730", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb2) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jscript9.dll", version:"9.0.8112.16620", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb2) ||

  # Vista / 2008
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"jscript9.dll", version:"9.0.8112.20730", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb2) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"jscript9.dll", version:"9.0.8112.16620", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb2)
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

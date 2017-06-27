#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49223);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-1899", "CVE-2010-2730", "CVE-2010-2731");
  script_bugtraq_id(41314, 43138, 43140);
  script_osvdb_id(66160, 67978, 67979);
  script_xref(name:"IAVA", value:"2010-A-0120");
  script_xref(name:"MSFT", value:"MS10-065");

  script_name(english:"MS10-065: Vulnerabilities in Microsoft Internet Information Services (IIS) Could Allow Remote Code Execution (2267960)");
  script_summary(english:"Checks versions of Asp.dll / Cgi.dll / Infocomm.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server may allow remote code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IIS installed on the remote host has the following
vulnerabilities :

  - Sending a specially crafted request for an ASP page
    on a website hosted by IIS can result in a denial of
    service. (CVE-2010-1899)

  - Sending a specially crafted HTTP request to an IIS
    server with FastCGI enabled can result in remote
    code execution. (CVE-2010-2730)

  - Sending a specially crafted request to an IIS server
    running on Windows XP can allow a remote attacker to
    bypass the need to authenticate to access restricted
    resources. (CVE-2010-2731)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-065");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for IIS on Windows XP, 2003,
Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS10-065';
kbs = make_list("2124261", "2271195", "2290570");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_iis_installed() <= 0) audit(AUDIT_NOT_INST, "IIS");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", file:"Asp.dll", version:"7.5.7600.20741", min_version:"7.5.7600.20000", dir:"\system32\inetsrv", bulletin:bulletin, kb:'2124261') ||
  hotfix_is_vulnerable(os:"6.1", file:"Asp.dll", version:"7.5.7600.16620", min_version:"7.5.7600.16000", dir:"\system32\inetsrv", bulletin:bulletin, kb:'2124261') ||
  hotfix_is_vulnerable(os:"6.1", file:"Cgi.dll", version:"7.5.7600.20752", min_version:"7.5.7600.20000", dir:"\system32\inetsrv", bulletin:bulletin, kb:'2271195') ||
  hotfix_is_vulnerable(os:"6.1", file:"Cgi.dll", version:"7.5.7600.16632", min_version:"7.5.7600.16000", dir:"\system32\inetsrv", bulletin:bulletin, kb:'2271195') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Asp.dll", version:"7.0.6002.22431", min_version:"7.0.6002.22000", dir:"\system32\inetsrv", bulletin:bulletin, kb:'2124261') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Asp.dll", version:"7.0.6002.18276", min_version:"7.0.6002.18000", dir:"\system32\inetsrv", bulletin:bulletin, kb:'2124261') ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Asp.dll", version:"7.0.6001.22718", min_version:"7.0.6001.22000", dir:"\system32\inetsrv", bulletin:bulletin, kb:'2124261') ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Asp.dll", version:"7.0.6001.18497", min_version:"7.0.6001.18000", dir:"\system32\inetsrv", bulletin:bulletin, kb:'2124261') ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Asp.dll", version:"6.0.3790.4735", dir:"\system32\inetsrv", bulletin:bulletin, kb:'2124261') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Infocomm.dll", version:"6.0.2600.6018", dir:"\system32\inetsrv", bulletin:bulletin, kb:'2290570') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Asp51.dll", version:"5.1.2600.6007", dir:"\system32\inetsrv", bulletin:bulletin, kb:'2124261')
)
{
  set_kb_item(name:'SMB/Missing/MS10-065', value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

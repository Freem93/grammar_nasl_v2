#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42109);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2009-2521", "CVE-2009-3023");
  script_bugtraq_id(36273, 36189);
  script_osvdb_id(57589, 57753);
  script_xref(name:"EDB-ID", value:"17476");
  script_xref(name:"IAVB", value:"2009-B-0052");
  script_xref(name:"MSFT", value:"MS09-053");
  script_xref(name:"CERT", value:"276653");
  script_xref(name:"EDB-ID", value:"9541");
  script_xref(name:"EDB-ID", value:"9559");
  script_xref(name:"EDB-ID", value:"9587");
  script_xref(name:"EDB-ID", value:"16740");
  script_xref(name:"EDB-ID", value:"17476");

  script_name(english:"MS09-053: Vulnerabilities in FTP Service for Internet Information Services Could Allow Remote Code Execution (975254)");
  script_summary(english:"Checks version of ftpsvc2.dll");

  script_set_attribute(attribute:"synopsis", value:"The remote FTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IIS whose FTP service is affected by
one or both of the following vulnerabilities :

  - By sending specially crafted list commands to the
    remote Microsoft FTP service, an attacker is able
    to cause the service to become unresponsive.
    (CVE-2009-2521)

  - A flaw in the way the installed Microsoft FTP service
    in IIS handles list commands can be exploited to
    execute remote commands in the context of the
    LocalSystem account with IIS 5.0 under Windows 2000 or
    to cause the FTP server to stop and become unresponsive
    with IIS 5.1 under Windows XP or IIS 6.0 under Windows
    2003. (CVE-2009-3023)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-053");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for IIS 5.0, 5.1, 6.0, and
7.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS09-053 Microsoft IIS FTP Server NLST Response Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS09-053';
kb = '975254';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"ftpsvc2.dll", version:"7.0.6002.22219", min_version:"7.0.6002.22000", dir:"\System32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"ftpsvc2.dll", version:"7.0.6002.18107",                               dir:"\System32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"ftpsvc2.dll", version:"7.0.6001.22516", min_version:"7.0.6001.22000", dir:"\System32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"ftpsvc2.dll", version:"7.0.6001.18327",                               dir:"\System32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"ftpsvc2.dll", version:"7.0.6000.21123", min_version:"7.0.6000.20000", dir:"\System32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"ftpsvc2.dll", version:"7.0.6000.16923",                               dir:"\System32\inetsrv", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"ftpsvc2.dll", version:"6.0.3790.4584",                                dir:"\System32\inetsrv", bulletin:bulletin, kb:kb) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"ftpsvc2.dll", version:"6.0.2600.5875",                                dir:"\System32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"ftpsvc2.dll", version:"6.0.3790.4584",                                dir:"\System32\inetsrv", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"ftpsvc2.dll", version:"6.0.2600.3624",                                dir:"\System32\inetsrv", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"ftpsvc2.dll", version:"5.0.2195.7336",                                dir:"\System32\inetsrv", bulletin:bulletin, kb:kb)
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

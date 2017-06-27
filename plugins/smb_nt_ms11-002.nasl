#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51455);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/05/07 12:06:04 $");

  script_cve_id("CVE-2011-0026", "CVE-2011-0027");
  script_bugtraq_id(45695, 45698);
  script_osvdb_id(70443, 70444);
  script_xref(name:"EDB-ID", value:"15984");
  script_xref(name:"IAVA", value:"2011-A-0004");
  script_xref(name:"MSFT", value:"MS11-002");

  script_name(english:"MS11-002: Vulnerabilities in Microsoft Data Access Components Could Allow Remote Code Execution (2451910)");
  script_summary(english:"Checks the version of Msado15.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Data Access Components.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Data Access Components (MDAC) installed on
the remote Windows host is affected by two vulnerabilities, which
could allow arbitrary code execution if a user views a specially
crafted web page:

  - A buffer overflow in the Open Database Connectivity
    (ODBC) API used by third-party applications can be
    triggered by an overly long Data Source Name (DSN)
    argument. (CVE-2011-0026)

  - A failure of MDAC to correctly allocate memory when
    handling internal data structures in ActiveX Data
    Objects (ADO) records can be abused to execute
    arbitrary code. (CVE-2011-0027)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-002");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-001/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-002/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-002';
kbs = make_list("2419640");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

ado_path = hotfix_get_commonfilesdir();
if (!ado_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
ado_path += "\system\ado";

share = hotfix_path2share(path:ado_path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 / Server 2008 R2
  # - KB 2419640
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Msado15.dll", version:"6.1.7600.20818", min_version:"6.1.7600.20000", path:ado_path, bulletin:bulletin, kb:"2419640") ||
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Msado15.dll", version:"6.1.7600.16688", min_version:"6.1.0.0",        path:ado_path, bulletin:bulletin, kb:"2419640") ||

  # Vista / Windows Server 2008
  # - KB 2419640
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Msado15.dll", version:"6.0.6002.22555", min_version:"6.0.6002.22000", path:ado_path, bulletin:bulletin, kb:"2419640") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Msado15.dll", version:"6.0.6002.18362", min_version:"6.0.0.0",        path:ado_path, bulletin:bulletin, kb:"2419640") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Msado15.dll", version:"6.0.6001.22821", min_version:"6.0.6001.22000", path:ado_path, bulletin:bulletin, kb:"2419640") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Msado15.dll", version:"6.0.6001.18570", min_version:"6.0.0.0",        path:ado_path, bulletin:bulletin, kb:"2419640") ||

  # Windows 2003 and XP x64
  # - KB 2419635
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Msado15.dll", version:"2.82.4795.0",                                  path:ado_path, bulletin:bulletin, kb:"2419635") ||

  # Windows XP
  # - KB 2419632
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Msado15.dll", version:"2.81.3012.0",                                  path:ado_path, bulletin:bulletin, kb:"2419632")
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

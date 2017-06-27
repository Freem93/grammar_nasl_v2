#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91602);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/13 20:59:28 $");

  script_cve_id("CVE-2016-3216", "CVE-2016-3219", "CVE-2016-3220");
  script_bugtraq_id(91083);
  script_osvdb_id(139965, 139966, 139967);
  script_xref(name:"MSFT", value:"MS16-074");
  script_xref(name:"IAVA", value:"2016-A-0149");

  script_name(english:"MS16-074: Security Update for Microsoft Graphics Component (3164036)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    Windows Graphics Component due to a failure to properly
    handle objects in memory. A local attacker can exploit
    this to disclose memory contents. (CVE-2016-3216)

  - An elevation of privilege vulnerability exists due to a
    failure to properly handle objects in memory. A local
    attacker can exploit this vulnerability, via a specially
    crafted application, to run processes in an elevated
    context. (CVE-2016-3219)

  - An elevation of privilege vulnerability exists in the
    Adobe Type Manager Font Driver due to improper handling
    of objects in memory. A local attacker can exploit this
    vulnerability, via a specially crafted application, to
    execute arbitrary code in an elevated context.
    (CVE-2016-3220)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS16-074");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

bulletin = 'MS16-074';

kbs = make_list(
  3164033,
  3164035,
  3163017,
  3163018
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"gdi32.dll", version:"10.0.10586.420", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3163018") ||

  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"gdi32.dll", version:"10.0.10240.16942", dir:"\system32", bulletin:bulletin, kb:"3163017") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"atmfd.dll", version:"5.1.2.248", dir:"\system32", bulletin:bulletin, kb:'3164033') ||
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"gdi32.dll", version:"6.3.9600.18344", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'3164035') ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"atmfd.dll", version:"5.1.2.248", dir:"\system32", bulletin:bulletin, kb:'3164033') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"gdi32.dll", version:"6.2.9200.21881", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'3164035') ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"atmfd.dll", version:"5.1.2.248", dir:"\system32", bulletin:bulletin, kb:'3164033') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"gdi32.dll", version:"6.1.7601.23457", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:'3164035') ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"atmfd.dll", version:"5.1.2.248", dir:"\system32", bulletin:bulletin, kb:'3164033') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdi32.dll", version:"6.0.6002.19660", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:'3164035') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdi32.dll", version:"6.0.6002.23975", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:'3164035')
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

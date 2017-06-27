#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92018);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/03 21:01:56 $");

  script_cve_id("CVE-2016-3238", "CVE-2016-3239");
  script_bugtraq_id(91609, 91612);
  script_osvdb_id(141403, 141404);
  script_xref(name:"MSFT", value:"MS16-087");
  script_xref(name:"IAVA", value:"2016-A-0181");

  script_name(english:"MS16-087: Security Update for Windows Print Spooler (3170005)");
  script_summary(english:"Checks the version of ntprint.dll and localspl.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    Windows Print Spooler service due to improper validation
    of print drivers while installing a printer from network
    servers. An unauthenticated, remote attacker can exploit
    this vulnerability, via a man-in-the-middle attack on a
    workstation or print server or via a rogue print server,
    to execute arbitrary code in the context of the current
    user. (CVE-2016-3238)

  - An elevation of privilege vulnerability exists in the
    Windows Print Spooler service due to improperly allowing
    arbitrary writing to the file system. An attacker can
    exploit this issue, via a specially crafted script or
    application, to execute arbitrary code with elevated
    system privileges. (CVE-2016-3239)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-087");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-087';
kbs = make_list('3170455', '3163912', '3172985');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (hotfix_check_server_core() == 1)
{
  #check to see if Printing-ServerCore-Role is enabled
  registry_init();
  hcf_init = TRUE;
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  dval = get_registry_value(handle:hklm, item:"SOFTWARE\Policies\Microsoft\Windows NT\Printers\RegisterSpoolerRemoteRpcEndPoint");
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  # if dval == 0, then the system is not vulnerable
  if (!dval) audit(AUDIT_HOST_NOT, 'affected');
}

if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntprint.dll", version:"6.0.6002.19666", min_version:"6.0.6002.16000", dir:"\System32", bulletin:bulletin, kb:"3170455") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntprint.dll", version:"6.0.6002.23981", min_version:"6.0.6002.20000", dir:"\System32", bulletin:bulletin, kb:"3170455") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntprint.dll", version:"6.1.7601.23488", min_version:"6.1.7600.16000", dir:"\System32", bulletin:bulletin, kb:"3170455") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntprint.dll", version:"6.2.9200.21913", min_version:"6.2.9200.16000", dir:"\System32", bulletin:bulletin, kb:"3170455") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntprint.dll", version:"6.3.9600.18398", min_version:"6.3.9600.16000", dir:"\System32", bulletin:bulletin, kb:"3170455") ||

  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"localspl.dll", version:"10.0.10240.17023", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3163912") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"localspl.dll", version:"10.0.10586.494", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3172985")
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

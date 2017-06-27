#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36150);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/12/09 20:55:00 $");

  script_cve_id(
    "CVE-2008-1436",
    "CVE-2009-0078",
    "CVE-2009-0079",
    "CVE-2009-0080"
  );
  script_bugtraq_id(28833, 34442, 34443, 34444);
  script_osvdb_id(44580, 53666, 53667, 53668);
  script_xref(name:"MSFT", value:"MS09-012");
  script_xref(name:"EDB-ID", value:"31667");
  script_xref(name:"EDB-ID", value:"32891");
  script_xref(name:"EDB-ID", value:"32892");
  script_xref(name:"EDB-ID", value:"32893");

  script_name(english:"MS09-012: Vulnerabilities in Windows Could Allow Elevation of Privilege (959454)");
  script_summary(english:"Checks version of Msdtcprx.dll / Ntoskrnl.exe");

  script_set_attribute(attribute:"synopsis", value:"A local user can elevate his privileges on the remote host.");
  script_set_attribute(attribute:"description", value:
"The version of Windows running on the remote host is affected by
potentially four vulnerabilities involving its MSDTC transaction
facility and/or Windows Service Isolation that may allow a local user to
escalate his privileges and take complete control of the affected
system.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-012");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-012';
kbs = make_list("952004", "956572");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Vista and Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Ntoskrnl.exe", version:"6.0.6001.22389", min_version:"6.0.6001.20000", dir:"\System32", bulletin:bulletin, kb:"956572") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Msdtcprx.dll", version:"2001.12.6931.22197", min_version:"2001.12.6931.20000", dir:"\System32", bulletin:bulletin, kb:"952004") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Ntoskrnl.exe", version:"6.0.6001.18226", dir:"\System32", bulletin:bulletin, kb:"956572") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Msdtcprx.dll", version:"2001.12.6931.18085", dir:"\System32", bulletin:bulletin, kb:"952004") ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Ntoskrnl.exe", version:"6.0.6000.21023", min_version:"6.0.6000.20000", dir:"\System32", bulletin:bulletin, kb:"956572") ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Msdtcprx.dll", version:"2001.12.6930.20852", min_version:"2001.12.6930.20000", dir:"\System32", bulletin:bulletin, kb:"952004") ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Ntoskrnl.exe", version:"6.0.6000.16830", dir:"\System32", bulletin:bulletin, kb:"956572") ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Msdtcprx.dll", version:"2001.12.6930.16697", dir:"\System32", bulletin:bulletin, kb:"952004") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Ntoskrnl.exe", version:"5.2.3790.4478", dir:"\System32", bulletin:bulletin, kb:"956572") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Msdtcprx.dll", version:"2001.12.4720.4340", dir:"\System32", bulletin:bulletin, kb:"952004") ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Ntoskrnl.exe", version:"5.2.3790.3309", dir:"\System32", bulletin:bulletin, kb:"956572") ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Msdtcprx.dll", version:"2001.12.4720.3180", dir:"\System32", bulletin:bulletin, kb:"952004") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Ntoskrnl.exe", version:"5.1.2600.5755", dir:"\System32", bulletin:bulletin, kb:"956572") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Msdtcprx.dll", version:"2001.12.4414.706", dir:"\System32", bulletin:bulletin, kb:"952004") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Ntoskrnl.exe", version:"5.1.2600.3520", dir:"\System32", bulletin:bulletin, kb:"956572") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Msdtcprx.dll", version:"2001.12.4414.320", dir:"\System32", bulletin:bulletin, kb:"952004") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Msdtcprx.dll", version:"2000.2.3549.0", dir:"\System32", bulletin:bulletin, kb:"952004")
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

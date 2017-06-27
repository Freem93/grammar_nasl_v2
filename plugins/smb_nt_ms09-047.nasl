#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40890);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id("CVE-2009-2498", "CVE-2009-2499");
  script_bugtraq_id(36225, 36228);
  script_osvdb_id(57802, 57803);
  script_xref(name:"MSFT", value:"MS09-047");
  script_xref(name:"IAVA", value:"2009-A-0076");

  script_name(english:"MS09-047: Vulnerabilities in Windows Media Format Could Allow Remote Code Execution (973812)");
  script_summary(english:"Checks version of wmvcore.dll / wmsserver.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through opening a
Windows Media Format file.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of the Windows Media Format
Runtime or Windows Media Services that is affected by multiple
vulnerabilities :

  - The ASF parser has an invalid free vulnerability.
    A remote attacker could exploit this by tricking a
    user into opening a specially crafted ASF file, which
    could lead to arbitrary code execution. (CVE-2009-2498)

  - The MP3 parser has a memory corruption vulnerability.
    A remote attacker could exploit this by tricking a
    user into opening a specially crafted MP3 file, which
    could lead to arbitrary code execution. (CVE-2009-2499)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-047");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS09-047';
kbs = make_list('968816', '972554');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows 2008
  # WMFR 11
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6000.6351", min_version:"11.0.6000.6300", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6000.6510", min_version:"11.0.6000.6500", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6001.7006", min_version:"11.0.6001.7000", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6001.7113", min_version:"11.0.6002.7100", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6002.18049", min_version:"11.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"6.0",   file:"wmvcore.dll", version:"11.0.6002.22150", min_version:"11.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  # WMS
  hotfix_is_vulnerable(os:"6.0", file:"Wmsserver.dll", version:"9.5.6001.18281", dir:"\system32\windows media\server", bulletin:bulletin, kb:'972554') ||

  # Windows 2003
  # WMFR 9.5
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Wmvcore.dll", version:"10.0.0.4005", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Wmvcore.dll", version:"10.0.0.4005", min_version:"10.0.0.0", dir:"\SysWOW64") ||
  # Windows Media Services
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Wmsserver.dll", version:"9.1.1.5001", dir:"\system32\windows media\server", bulletin:bulletin, kb:'972554') ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Wmsserver.dll", version:"9.1.1.5001", dir:"\system32\windows media\server", bulletin:bulletin, kb:'972554') ||

  # Windows XP
  # WMFR 9.5, and 11 for XP x86 SP2 and SP3
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4372", min_version:"10.0.0.4300", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4372", min_version:"10.0.0.4300", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.3705", min_version:"10.0.0.3700", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.3705", min_version:"10.0.0.3700", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4072", min_version:"10.0.0.4000", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"10.0.0.4072", min_version:"10.0.0.4000", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"11.0.5721.5265", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"11.0.5721.5265", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:'968816') ||

  # WMFR 9.0 for XP x86 SP2
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"9.0.0.3270", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmvcore.dll",  version:"9.0.0.3362", min_version:"9.0.0.3300", dir:"\system32", bulletin:bulletin, kb:'968816') ||

  # WMFR 9.0 for XP x86 SP3
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmvcore.dll",  version:"9.0.0.4506", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'968816') ||

  # WMFR 9.5 and 11 for XP x64 SP2
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Wwmvcore.dll", version:"10.0.0.4005", min_version:"10.0.0.0", dir:"\SysWOW64", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Wmvcore.dll",  version:"11.0.5721.5265", min_version:"11.0.0.0", dir:"\SysWOW64", bulletin:bulletin, kb:'968816') ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Wmvcore.dll",   version:"9.0.0.3270",    min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'968816') ||
  hotfix_is_vulnerable(os:"5.0", file:"Wmvcore.dll",   version:"9.0.0.3362",    min_version:"9.0.0.3300", dir:"\system32", bulletin:bulletin, kb:'968816')
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

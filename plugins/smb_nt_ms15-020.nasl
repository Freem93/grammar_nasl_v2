#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81735);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/04/19 13:27:09 $");

  script_cve_id("CVE-2015-0081", "CVE-2015-0096");
  script_bugtraq_id(72886, 72894);
  script_osvdb_id(119355, 119356);
  script_xref(name:"MSFT", value:"MS15-020");
  script_xref(name:"IAVA", value:"2015-A-0053");

  script_name(english:"MS15-020: Vulnerabilities in Microsoft Windows Could Allow Remote Code Execution (3041836) (EASYHOOKUP)");
  script_summary(english:"Checks the version of msctf.dll and shell32.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by the following vulnerabilities :

  - A remote code execution vulnerability exists in Windows
    Text Services due to improper handling of objects in
    memory. A remote attacker can exploit this vulnerability
    by convincing a user to visit a specially crafted
    website or open a specially crafted file, resulting in
    the execution of arbitrary code. (CVE-2015-0059)

  - A remote code execution vulnerability exists due to
    improper loading of DLL files. A remote attacker can
    exploit this vulnerability by convincing a user to visit
    a specially crafted website or remote network share,
    resulting in the execution of arbitrary code.
    (CVE-2015-0096) (EASYHOOKUP)

EASYHOOKUP is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/14 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-020");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows Shell LNK Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

bulletin = 'MS15-020';

kbs = make_list("3033889","3039066");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# The 2k3 checks could flag XP 64, which is unsupported
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"msctf.dll", version:"6.3.9600.17664", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3033889") ||
  hotfix_is_vulnerable(os:"6.3", file:"shell32.dll", version:"6.3.9600.17680", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3039066") ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"msctf.dll", version:"6.2.9200.21361", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3033889") ||
  hotfix_is_vulnerable(os:"6.2", file:"msctf.dll", version:"6.2.9200.17243", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3033889") ||
  hotfix_is_vulnerable(os:"6.2", file:"shell32.dll", version:"6.2.9200.21395", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3039066") ||
  hotfix_is_vulnerable(os:"6.2", file:"shell32.dll", version:"6.2.9200.17279", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3039066") ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"msctf.dll", version:"6.1.7601.22937", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3033889") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"msctf.dll", version:"6.1.7601.18731", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3033889") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"shell32.dll", version:"6.1.7601.22969", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3039066") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"shell32.dll", version:"6.1.7601.18762", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3039066") ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"msctf.dll", version:"6.0.6002.23606", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3033889") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"msctf.dll", version:"6.0.6002.19296", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3033889") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"shell32.dll", version:"6.0.6002.23632", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3039066") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"shell32.dll", version:"6.0.6002.19322", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3039066") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"msctf.dll", version:"5.2.3790.5528", dir:"\system32", bulletin:bulletin, kb:"3033889") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"shell32.dll", version:"5.2.3790.5558", dir:"\system32", bulletin:bulletin, kb:"3039066")

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

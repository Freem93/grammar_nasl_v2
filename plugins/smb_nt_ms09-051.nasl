#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42107);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2009-0555", "CVE-2009-2525");
  script_bugtraq_id(36602, 36614);
  script_osvdb_id(58844, 58845);
  script_xref(name:"IAVA", value:"2009-A-0091");
  script_xref(name:"MSFT", value:"MS09-051");

  script_name(english:"MS09-051: Vulnerabilities in Windows Media Runtime Could Allow Remote Code Execution (975682)");
  script_summary(english:"Checks version of wmspdmod.dll and msaud32.acm");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through opening a
Windows Media Format file.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of the Windows Media Runtime
that is affected by multiple vulnerabilities :

  - The ASF parser incorrectly parses files which make use
    of the Window Media Speech codec. A remote attacker can
    exploit this by tricking a user into opening a specially
    crafted ASF file, which can lead to arbitrary code
    execution. (CVE-2009-0555)

  - The Audio Compression Manager does not properly initialize
    certain functions in compressed audio files. A remote
    attacker can exploit this by tricking a user into opening
    a specially crafted media file, which can lead to
    arbitrary code execution. (CVE-2009-2525)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-051");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = 'MS09-051';
kbs = make_list('954155', '969878', '975025');
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
  # WMFR 11 x86 and x64
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"wmspdmod.dll", version:"11.0.6000.6350",  dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"wmspdmod.dll", version:"11.0.6000.6509",  min_version:"11.0.6000.6500", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"wmspdmod.dll", version:"11.0.6001.7005",  dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"wmspdmod.dll", version:"11.0.6001.7111",  min_version:"11.0.6001.7100", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"wmspdmod.dll", version:"11.0.6002.18034", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"wmspdmod.dll", version:"11.0.6002.22131", min_version:"11.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:'954155') ||

  # Windows 2003 x64
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"wmavds32.ax",  version:"9.0.0.3360",     min_version:"9.0.0.0", dir:"\SysWOW64", bulletin:bulletin, kb:'969878') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"msaud32.acm",  version:"8.0.0.4502",     min_version:"8.0.0.0", dir:"\SysWOW64", bulletin:bulletin, kb:'975025') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"wmspdmod.dll", version:"10.0.0.3712",    min_version:"10.0.0.3000", dir:"\SysWOW64", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"wmspdmod.dll", version:"10.0.0.4004",    min_version:"10.0.0.3900", dir:"\SysWOW64", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"wmspdmod.dll", version:"11.0.5721.5263", min_version:"11.0.0.0", dir:"\SysWOW64", bulletin:bulletin, kb:'954155') ||

   # Windows 2003 x86
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"wmavds32.ax",  version:"9.0.0.3360",     min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'969878') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"msaud32.acm",  version:"8.0.0.4502",     min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:'975025') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"wmspdmod.dll", version:"10.0.0.3712",    min_version:"10.0.0.3000", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"wmspdmod.dll", version:"10.0.0.4004",    min_version:"10.0.0.3900", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"wmspdmod.dll", version:"11.0.5721.5263", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:'954155') ||

  # Windows XP x64
  hotfix_is_vulnerable(os:"5.1", arch:"x64", file:"wmavds32.ax",  version:"9.0.0.3360",     min_version:"9.0.0.0", dir:"\SysWOW64", bulletin:bulletin, kb:'969878') ||
  hotfix_is_vulnerable(os:"5.1", arch:"x64", file:"msaud32.acm",  version:"8.0.0.4502",     min_version:"8.0.0.0", dir:"\SysWOW64", bulletin:bulletin, kb:'975025') ||
  hotfix_is_vulnerable(os:"5.1", arch:"x64", file:"wmspdmod.dll", version:"10.0.0.3819",    min_version:"10.0.0.3000", dir:"\SysWOW64", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.1", arch:"x64", file:"wmspdmod.dll", version:"11.0.5721.5263", min_version:"11.0.0.0", dir:"\SysWOW64", bulletin:bulletin, kb:'954155') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"wmavds32.ax",   version:"9.0.0.3360",    min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'969878') ||
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"msaud32.acm",   version:"8.0.0.4502",    min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:'975025') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"wmspdmod.dll", version:"9.0.0.3269", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"wmspdmod.dll", version:"9.0.0.4505", min_version:"9.0.0.4000", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"wmspdmod.dll",   version:"10.0.0.3704",    min_version:"10.0.0.3000", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"wmspdmod.dll",   version:"10.0.0.4070",    min_version:"10.0.0.3800", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"wmspdmod.dll",   version:"10.0.0.4365",    min_version:"10.0.0.4300", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"wmspdmod.dll",   version:"11.0.5721.5263", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:'954155') ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"wmspdmod.dll",   version:"9.0.0.3269",   min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.0", file:"wmspdmod.dll",   version:"10.0.0.4070",  min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:'954155') ||
  hotfix_is_vulnerable(os:"5.0", file:"wmavds32.ax",   version:"9.0.0.3360",    min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'969878') ||
  hotfix_is_vulnerable(os:"5.0", file:"msaud32.acm",   version:"8.0.0.4502",    min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:'969878')
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

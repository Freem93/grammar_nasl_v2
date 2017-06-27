#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84747);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/19 04:43:59 $");

  script_cve_id(
    "CVE-2015-2363",
    "CVE-2015-2365",
    "CVE-2015-2366",
    "CVE-2015-2367",
    "CVE-2015-2381",
    "CVE-2015-2382"
  );
  #script_bugtraq_id();
  script_osvdb_id(
    124587,
    124588,
    124589,
    124590,
    124591,
    124592
  );
  script_xref(name:"MSFT", value:"MS15-073");
  script_xref(name:"IAVA", value:"2015-A-0162");

  script_name(english:"MS15-073: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (3070102)");
  script_summary(english:"Checks the file version of Win32k.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple vulnerabilities :

  - Multiple privilege escalation vulnerabilities exist in
    the Windows kernel-mode driver due to improper handling
    of objects in memory. A local attacker can exploit these
    vulnerabilities, with a specially crafted application,
    to elevate privileges to full administrative rights.
    (CVE-2015-2363, CVE-2015-2365, CVE-2015-2366)

  - An information disclosure vulnerability exists in the
    Windows kernel-mode driver due to improper handling of
    non-initialized values in memory. An attacker can
    exploit this vulnerability, with a specially crafted
    application, to leak memory addresses or other sensitive
    kernel information that can be used for further
    exploitation of the system. (CVE-2015-2367)

  - An information disclosure vulnerability exists in the
    Windows kernel-mode driver due to improper handling of
    private address information during a function call. An
    attacker can exploit this vulnerability, with a
    specially crafted application, to request the contents
    of specific memory addresses. (CVE-2015-2381,
    CVE-2015-2382)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-073");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, RT, 2012, 8.1, RT 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

bulletin = 'MS15-073';
kb = '3070102';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Some of the 2k3 checks could flag XP 64, which is unsupported
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Win32k.sys", version:"6.3.9600.17915", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Win32k.sys", version:"6.2.9200.21528", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Win32k.sys", version:"6.2.9200.17419", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.23109", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.18906", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.23735", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.19429", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.5667", dir:"\system32", bulletin:bulletin, kb:kb)
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

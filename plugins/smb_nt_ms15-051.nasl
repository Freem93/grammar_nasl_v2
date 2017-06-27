#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83370);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2015-1676",
    "CVE-2015-1677",
    "CVE-2015-1678",
    "CVE-2015-1679",
    "CVE-2015-1680",
    "CVE-2015-1701"
  );
  script_bugtraq_id(
    74245,
    74483,
    74494,
    74495,
    74496,
    74497
  );
  script_osvdb_id(
    120976,
    122012,
    122013,
    122014,
    122015,
    122016
  );
  script_xref(name:"MSFT", value:"MS15-051");
  script_xref(name:"IAVA", value:"2015-A-0108");

  script_name(english:"MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191)");
  script_summary(english:"Checks the file version of Win32k.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Windows running on the remote host is affected by
multiple vulnerabilities :

  - Multiple information disclosure vulnerabilities exist
    due to the Win32k.sys kernel-mode driver improperly
    handling objects in memory. A local attacker can exploit
    this to reveal private address information during a
    function call, resulting in the disclosure of kernel
    memory contents. (CVE-2015-1676, CVE-2015-1677,
    CVE-2015-1678, CVE-2015-1679, CVE-2015-1680)

  - A privilege escalation vulnerability exists due to the
    Win32k.sys kernel-mode driver improperly handling
    objects in memory. A local attacker can exploit this
    flaw, via a specially crafted application, to execute
    arbitrary code in kernel mode. This vulnerability is
    reportedly being exploited in the wild. (CVE-2015-1701)");
  # https://www.fireeye.com/blog/threat-research/2015/04/probable_apt28_useo.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37b0306c");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-051");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Windows ClientCopyImage Win32k Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS15-051';
kb = '3045171';

kbs = make_list('3057191', kb, '3065979');
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
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Win32k.sys", version:"6.3.9600.17796", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Win32k.sys", version:"6.2.9200.21457", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Win32k.sys", version:"6.2.9200.17343", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.23038", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.18834", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.23680", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.19372", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.5615", dir:"\system32", bulletin:bulletin, kb:kb)
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

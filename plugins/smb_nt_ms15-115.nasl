#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86822);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id(
    "CVE-2015-6100",
    "CVE-2015-6101",
    "CVE-2015-6102",
    "CVE-2015-6103",
    "CVE-2015-6104",
    "CVE-2015-6109",
    "CVE-2015-6113"
  );
  script_bugtraq_id(
    77458,
    77460,
    77462,
    77463,
    77464,
    77465,
    77466
  );
  script_osvdb_id(
    130043,
    130044,
    130045,
    130046,
    130047,
    130048,
    130049
  );
  script_xref(name:"MSFT", value:"MS15-115");
  script_xref(name:"IAVA", value:"2015-A-0299");

  script_name(english:"MS15-115: Security Update for Microsoft Windows to Address Remote Code Execution (3105864)");
  script_summary(english:"Checks the version of win32k.sys, ntdll.dll, and msobjs.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by the following vulnerabilities :

  - Multiple elevation of privilege vulnerabilities exist
    that are related to the handling of objects in memory.
    A local attacker can exploit these, via a crafted
    application, to run arbitrary code in kernel mode.
    (CVE-2015-6100, CVE-2015-6101)

  - Multiple information disclosure vulnerabilities exist
    due to a failure to properly initialize memory
    addresses. A local attacker can exploit these, via a
    specially crafted application, to bypass the Kernel
    Address Space Layout Randomization (KASLR) and retrieve
    the base address of the Kernel driver from a compromised
    process. (CVE-2015-6102, CVE-2015-6109)

  - Multiple remote code execution vulnerabilities exist
    in the Adobe Type Manager Library due to improper
    handling of specially crafted fonts. An unauthenticated,
    remote attacker can exploit these, via a crafted
    document or web page, to execute arbitrary code.
    (CVE-2015-6103, CVE-2015-6104)

  - A security feature bypass vulnerability exists due to
    improper validation of permissions. A local attacker can
    exploit this to interact with the file system in an
    inappropriate manner to modify files, by using a
    crafted, low-integrity-level, user-mode application.
    (CVE-2015-6113)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-115");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Vista, 2008, 7, 2008 R2,
8, 2012, 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS15-115';
kbs = make_list(
    "3101746",
    "3097877",
    "3105211",
    "3105213"
);
vuln = 0;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"win32k.sys", version:"6.3.9600.18093", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3097877") ||
  # 8 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.17554", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3097877") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.21671", min_version:"6.2.9200.20000 ", dir:"\system32", bulletin:bulletin, kb:"3097877") ||
  # 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.19054", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3097877") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.23259", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3097877") ||
  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19525", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3097877") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.23835", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"3097877")
)
  vuln++;

if (
  # 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntdll.dll", version:"6.3.9600.18007", min_version:"6.3.9600.18000", dir:"\system32", bulletin:bulletin, kb:"3101746") ||
  # 8 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"msobjs.dll", version:"6.2.9200.16384", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3101746") ||
  # 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntdll.dll", version:"6.1.7601.19045", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3101746") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntdll.dll", version:"6.1.7601.23250", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3101746") ||
  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdll.dll", version:"6.0.6002.19514", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3101746") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdll.dll", version:"6.0.6002.23824", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"3101746") 
)
  vuln++;
if (
  # 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10586.3", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3105211") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10240.16590", dir:"\system32", bulletin:bulletin, kb:"3105213")
)
  vuln++;

if (vuln)
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


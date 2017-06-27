#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88646);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2016-0040",
    "CVE-2016-0041",
    "CVE-2016-0042",
    "CVE-2016-0044",
    "CVE-2016-0049"
  );
  script_bugtraq_id(
    82505,
    82510,
    82511,
    82515
  );
  script_osvdb_id(
    134291,
    134309,
    134310,
    134311,
    134312
  );
  script_xref(name:"MSFT", value:"MS16-014");
  script_xref(name:"IAVA", value:"2016-A-0050");

  script_name(english:"MS16-014: Security Update for Microsoft Windows to Address Remote Code Execution (3134228)");
  script_summary(english:"Checks the version of the DLL files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in the
    Windows kernel due to improper handling of objects in
    memory. A local attacker can exploit this, via a crafted
    application, to run arbitrary code in kernel mode and
    therefore take control of the affected system.
    (CVE-2016-0040)

  - Multiple code execution vulnerabilities exist due to
    improper validation of user-supplied input when loading
    DLL files. A local attacker can exploit these, via a
    specially crafted application, to execute arbitrary
    code. (CVE-2016-0041, CVE-2016-0042)

  - A denial of service vulnerability exists in Microsoft
    Sync Framework due to improper processing of crafted
    input that uses the 'change batch' structure. An
    authenticated, remote attacker can exploit this, via
    specially crafted packets sent to the SyncShareSvc
    service, to cause the service to stop responding.
    (CVE-2016-0044)

  - A security feature bypass vulnerability exists when
    Kerberos fails to check the password change of a user
    signing into a workstation. An attacker can exploit
    this, by connecting the workstation to a malicious
    Kerberos Key distribution Center, to bypass Kerberos
    authentication on a target machine, thus allowing
    decryption of drives protected by BitLocker.
    (CVE-2016-0049)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-014");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Office OLE Multiple DLL Side Loading Vulnerabilities');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

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
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-014';
kbs = make_list(
    "3126041",
    "3126587",
    "3126593",
    "3126434",
    "3135174",
    "3135173"
);
vuln = 0;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# KB3126587
if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"cfgbkend.dll", version:"6.3.9600.18192", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3126587") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"cfgbkend.dll", version:"6.2.9200.17623", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3126587") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"cfgbkend.dll", version:"6.2.9200.21743", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3126587") ||

  # Windows 7 / Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"advapi32.dll", version:"6.1.7601.19135", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3126587") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"advapi32.dll", version:"6.1.7601.23338", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3126587") ||

  # Windows Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"advapi32.dll", version:"6.0.6002.19594", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3126587") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"advapi32.dll", version:"6.0.6002.23905", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"3126587")
)
  vuln++;

# KB3126593
if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntoskrnl.exe", version:"6.3.9600.18192", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3126593")  ||
  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntoskrnl.exe", version:"6.2.9200.21743", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3126593") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntoskrnl.exe", version:"6.2.9200.17623", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3126593") ||
  # Windows 7 / Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntoskrnl.exe", version:"6.1.7601.23321", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3126593") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntoskrnl.exe", version:"6.1.7601.19117", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3126593") ||
  # Windows Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.23890", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"3126593") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.19580", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3126593")
)
  vuln++;

# KB3126434
if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"winsync.dll", version:"2007.94.9600.18183", dir:"\system32", bulletin:bulletin, kb:"3126434")
)
  vuln++;

# KB3135173
if (
  # Windows 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10586.103", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3135173")
)
  vuln++;

# KB3135174
if (
  # Windows 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10240.16683", dir:"\system32", bulletin:bulletin, kb:"3135174") 
)
  vuln++;

# KB3126041
if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"kerberos.dll", version:"6.3.9600.18192", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3126041")  ||
  # Windows Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"kerberos.dll", version:"6.0.6002.23888", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"3126041") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"kerberos.dll", version:"6.0.6002.19578", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3126041")
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

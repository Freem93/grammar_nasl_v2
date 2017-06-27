#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87890);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/10 20:49:25 $");

  script_cve_id(
    "CVE-2016-0014",
    "CVE-2016-0015",
    "CVE-2016-0016",
    "CVE-2016-0018",
    "CVE-2016-0019",
    "CVE-2016-0020"
  );
  script_bugtraq_id(
    79896,
    79900,
    79902,
    79906,
    79908,
    79909
  );
  script_osvdb_id(
    132805,
    132806,
    132807,
    132808,
    132809,
    132810
  );
  script_xref(name:"MSFT", value:"MS16-007");
  script_xref(name:"IAVA", value:"2016-A-0014");

  script_name(english:"MS16-007: Security Update for Microsoft Windows to Address Remote Code Execution (3124901)");
  script_summary(english:"Checks the version of the DLL files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple elevation of privilege vulnerabilities exist
    due to improper validation of user-supplied input before
    loading DLL files. A local attacker can exploit these,
    via a crafted application, to elevate their privileges
    and take control of the affected system. (CVE-2016-0014,
    CVE-2016-0020)

  - A remote code execution vulnerability exists in
    DirectShow due to improper validation of user-supplied
    input. A remote attacker can exploit this, by convincing
    a user to open a specially crafted file, to execute
    arbitrary code in the context of the current user,
    resulting in taking control of the affected system.
    (CVE-2016-0015)

  - Multiple remote code execution vulnerabilities exist
    due to improper validation of user-supplied input before
    loading DLL files. A local attacker can exploit these,
    via a specially crafted application, to execute
    arbitrary code. (CVE-2016-0016, CVE-2016-0018)

  - A security bypass vulnerability exists in the Windows
    Remote Desktop Protocol (RDP) due to a failure to
    prevent remote logons to accounts that have no passwords
    set. A remote attacker can exploit this, by using an
    older version of the RDP client to connect to a Windows
    10 host, to generate a list of user accounts.
    (CVE-2016-0019)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-007");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.

Note that Windows 10 with Citrix XenDesktop installed will not be
offered the patch due to an issue with the XenDesktop software that
prevents users from logging on when the patch is applied. To apply the
patch you must first uninstall XenDesktop or contact Citrix for help
with the issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_nt_ms16-001.nasl");
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

bulletin = 'MS16-007';
kbs = make_list(
    "3108664",
    "3109560",
    "3110329",
    "3121461",
    "3121918",
    "3124263",
    "3124266",
    "3124901"
);
vuln = 0;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# KB3108664
if (
  # Windows 7 / Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"fixmapi.exe", version:"6.1.7601.19073", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3108664") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"fixmapi.exe", version:"6.1.7601.23278", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3108664") ||
  
  # Windows Vista Service Pack 2 / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"fixmapi.exe", version:"6.0.6002.19549", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3108664") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"fixmapi.exe", version:"6.0.6002.23859", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"3108664")
)
  vuln++;

# KB3109560
if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"qedit.dll", version:"6.6.9600.18152", min_version:"6.6.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3109560") ||
  
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"qedit.dll", version:"6.6.9200.17590", min_version:"6.6.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3109560") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"qedit.dll", version:"6.6.9200.21708", min_version:"6.6.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3109560") ||

  # Windows 7 / Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"qedit.dll", version:"6.6.7601.19091", min_version:"6.6.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3109560") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"qedit.dll", version:"6.6.7601.23290", min_version:"6.6.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3109560") ||

  # Windows Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"qedit.dll", version:"6.6.6002.19554", min_version:"6.6.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3109560") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"qedit.dll", version:"6.6.6002.23864", min_version:"6.6.6002.22000", dir:"\system32", bulletin:bulletin, kb:"3109560")
)
  vuln++;

# KB3110329
if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"wmspdmoe.dll", version:"6.3.9600.18154", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3110329") ||
  
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"devenum.dll", version:"6.2.9200.17590", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3110329") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"devenum.dll", version:"6.2.9200.21708", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3110329") ||

  # Windows 7 / Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"devenum.dll", version:"6.1.7601.19091", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3110329") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"devenum.dll", version:"6.1.7601.23290", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3110329") ||

  # Windows Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"devenum.dll", version:"6.6.6002.19554", min_version:"6.6.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3110329") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"devenum.dll", version:"6.6.6002.23864", min_version:"6.6.6002.22000", dir:"\system32", bulletin:bulletin, kb:"3110329")
)
  vuln++;

# KB3121461
if (
  # Windows 8.1 for 64-bit / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"aeinv.dll", version:"10.0.11065.1000", min_version:"10.0.11000.0000", dir:"\system32", bulletin:bulletin, kb:"3121461") ||
  
  # Windows 8.1 for 32-bit 
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"devinv.dll", version:"10.0.11065.1000", min_version:"10.0.11000.0000", dir:"\system32", bulletin:bulletin, kb:"3121461") ||
  
  # Windows 8
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"aeinv.dll", version:"10.0.11065.1000", min_version:"10.0.11000.0000", dir:"\system32", bulletin:bulletin, kb:"3121461") ||

  # Windows 7 
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"aeinv.dll", version:"10.0.11065.1000", min_version:"10.0.11000.0000", dir:"\system32", bulletin:bulletin, kb:"3121461")
)
  vuln++;

# KB3121918

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"advapi32.dll", version:"6.3.9600.18155", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||
  
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"advapi32.dll", version:"6.2.9200.17591", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"advapi32.dll", version:"6.2.9200.21713", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||
  
  # Windows 7 
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"advapi32.dll", version:"6.1.7601.19091", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"advapi32.dll", version:"6.1.7601.23290", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||

  # Windows Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"advapi32.dll", version:"6.0.6002.19555", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"advapi32.dll", version:"6.0.6002.23865", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"3121918")
)
  vuln++;

# Windows 10
if (
  hotfix_is_vulnerable(os:"10", sp:0, file:"advapi32.dll", version:"10.0.10586.63", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3124263") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"advapi32.dll", version:"10.0.10240.16644", min_version:"10.0.10240.0", dir:"\system32", bulletin:bulletin, kb:"3124266")
)
  vuln++;

# KB3124901

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"advapi32.dll", version:"6.3.9600.18155", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||
  
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"advapi32.dll", version:"6.2.9200.17591", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"advapi32.dll", version:"6.2.9200.21713", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||
  
  # Windows 7 
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"advapi32.dll", version:"6.1.7601.19091", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"advapi32.dll", version:"6.1.7601.23290", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||

  # Windows Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"advapi32.dll", version:"6.0.6002.19555", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3121918") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"advapi32.dll", version:"6.0.6002.23865", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"3121918")
) 
  vuln++;

##
# To be protected from this vulnerability on Windows 7 and Windows Server 2008 R2 systems, in addition to installing 
# this update customers must also install the 3124275 cumulative update (MS16-001) for Internet Explorer 10 or IE 11. 
##  
if (get_kb_item("SMB/Missing/MS16-001"))
{
  hotfix_add_report("The remote host is missing MS16-001.");
  vuln++;
}

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

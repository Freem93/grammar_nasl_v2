#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92023);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/03 21:01:56 $");

  script_cve_id("CVE-2016-3258", "CVE-2016-3272");
  script_bugtraq_id(91603, 91606);
  script_osvdb_id(141420, 141421);
  script_xref(name:"MSFT", value:"MS16-092");
  script_xref(name:"IAVA", value:"2016-A-0178");

  script_name(english:"MS16-092: Security Update for Windows Kernel (3171910)");
  script_summary(english:"Checks the version of ntoskrnl.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - A security feature bypass vulnerability exists in the
    Windows kernel due to improper validation of how a low
    integrity application can use certain object manager
    features. An attacker can exploit this issue to take
    advantage of time-of-check time-of-use (TOCTOU) issues
    in file path-based checks from a low integrity
    application, allowing the attacker to modify files
    outside of a low integrity level application.
    (CVE-2016-3258)

  - An information disclosure vulnerability exists in the
    Windows kernel due to a failure to properly handle
    certain page fault system calls. A local attacker can
    exploit this, via a specially crafted application, to
    disclose information from one process to another.
    (CVE-2016-3272)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-092");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1, RT 8.1,
2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

bulletin = 'MS16-092';
kbs = make_list('3170377',
                '3169704',
                '3163912',
                '3172985');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


# Check Registry Update
if ("Windows 10" >!< productname)
{
  registry_init();
  hcf_init = TRUE;
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  pcval = get_registry_value(handle:hklm, item:"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\DisablePageCombining");
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);
  if (!pcval)
  {
    hotfix_add_report('   The registry does not contain the update to\n   DisablePageCombining\n',bulletin:bulletin, kb:"3169704");
  }
}

if (
  # 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntoskrnl.exe", version:"6.3.9600.18378", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3170377")  ||
  # 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntoskrnl.exe", version:"6.2.9200.21896", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3170377") ||
  # 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"ntoskrnl.exe", version:"10.0.10586.494", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3172985") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"ntoskrnl.exe", version:"10.0.10240.17022", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3163912")
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

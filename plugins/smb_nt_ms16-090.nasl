#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92021);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/03/21 03:23:57 $");

  script_cve_id(
    "CVE-2016-3249",
    "CVE-2016-3250",
    "CVE-2016-3251",
    "CVE-2016-3252",
    "CVE-2016-3254",
    "CVE-2016-3286"
  );
  script_bugtraq_id(
    91597,
    91600,
    91613,
    91614,
    91615,
    91616
  );
  script_osvdb_id(
    141413,
    141414,
    141415,
    141416,
    141417,
    141418
  );
  script_xref(name:"MSFT", value:"MS16-090");

  script_name(english:"MS16-090: Security Update for Windows Kernel-Mode Drivers (3171481)");
  script_summary(english:"Checks version of win32k.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple elevation of privilege vulnerabilities exist in
    the kernel-mode driver due to improper handling of
    objects in memory. An authenticated, remote attacker can
    exploit these, via a specially crafted application, to
    run arbitrary code in kernel mode. (CVE-2016-3249,
    CVE-2016-3250, CVE-2016-3252, CVE-2016-3254,
    CVE-2016-3286)

  - An information disclosure vulnerability exists in the
    Windows GDI component due improper handling of objects
    in memory. An authenticated, remote attacker can exploit
    this, via a specially crafted application, to disclose
    kernel memory addresses. (CVE-2016-3251)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-090");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

bulletin = 'MS16-090';
kbs = make_list(
  "3163912",
  "3168965",
  "3172985"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


if (
  # 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10586.494", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3172985") ||

  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10240.17022", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3163912") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"win32k.sys", version:"6.3.9600.18377", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3168965") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.21896", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3168965") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.23471", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3168965") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.23979", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3168965") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19664", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3168965")
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


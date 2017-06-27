#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89756);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/07/18 20:50:58 $");

  script_cve_id(
    "CVE-2016-0093",
    "CVE-2016-0094",
    "CVE-2016-0095",
    "CVE-2016-0096"
  );
  script_bugtraq_id(
    84054,
    84066,
    84069,
    84072
  );
  script_osvdb_id(
    135538,
    135539,
    135540,
    135541
  );
  script_xref(name:"MSFT", value:"MS16-034");

  script_name(english:"MS16-034: Security Update for Windows Kernel-Mode Drivers to Address Elevation of Privilege (3143145)");
  script_summary(english:"Checks the version of win32k.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple flaws in the Win32k kernel-mode driver
due to improper handling of objects in memory. An authenticated,
remote attacker can exploit these, via a specially crafted
application, to elevate privileges, allowing the execution of
arbitrary code in kernel mode.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-034");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Vista, 2008, 7, 2008 R2,
2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS16-034';
kbs = make_list(
  "3140768",
  "3139852",
  "3143145",
  "3140745"
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
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10586.162", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3140768") ||

  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10240.16724", dir:"\system32", bulletin:bulletin, kb:"3140745") ||

  # Windows 8.1 / Windows Server 2012 R2    
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"win32k.sys", version:"6.3.9600.18228", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3139852") ||

  # Windows 8 / Windows Server 2012    
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.21766", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3139852") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.17647", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3139852") ||

  # Windows 7 / Server 2008 R2    
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.23346", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3139852") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.19145", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3139852") ||

  # Vista / Windows Server 2008    
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.23908", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3139852") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19597", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3139852")
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


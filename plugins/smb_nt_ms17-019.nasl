#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97754);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id("CVE-2017-0043");
  script_bugtraq_id(96628);
  script_osvdb_id(153709);
  script_xref(name:"MSFT", value:"MS17-019");
  script_xref(name:"MSKB", value:"3217882");
  script_xref(name:"MSKB", value:"4012212");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"MSKB", value:"4012214");
  script_xref(name:"MSKB", value:"4012217");
  script_xref(name:"MSKB", value:"4012213");
  script_xref(name:"MSKB", value:"4012216");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");
  script_xref(name:"MSKB", value:"4013429");
  script_xref(name:"IAVB", value:"2017-B-0032");

  script_name(english:"MS17-019: Security Update for Active Directory Federation Services (4010320)");
  script_summary(english:"Checks the installed rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by an information disclosure vulnerability in
Active Directory Federation Services (ADFS) when handling XML external
entities. An authenticated, remote attacker can exploit this issue,
via a specially crafted request, to disclose sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS17-019");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2008, 2008 R2,
2012, 2012 R2, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl", "wmi_enum_server_features.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-019';
kbs = make_list(
  "3217882", # Server 2008
  "4012212", # Server 2008 R2 Security Only
  "4012215", # Server 2008 R2 Monthly Rollup
  "4012214", # Server 2012 Security Only
  "4012217", # Server 2012 Monthly Rollup
  "4012213", # Server 2012 R2 Security Only
  "4012216", # Server 2012 R2 Monthly Rollup
  "4012606", # Server 2016 build 10240
  "4013198", # Server 2016 build 10586
  "4013429"  # Server 2016 build 14393  
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# non-server OSes are not affected
if ("Server" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);
# 2008 / 2008 R2 Core not affected
if (hotfix_check_server_core() == 1 && (winver == "6.0" || winver == "6.1"))
  audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# ADFS check
adfs_is_present = FALSE;

if (winver == "6.0")
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  adfs_value = get_registry_value(handle:hklm, item:"SYSTEM\CurrentControlSet\Services\adfssrv\ImagePath");
  if (!isnull(adfs_value)) adfs_is_present = TRUE;

  RegCloseKey(handle:hklm);
  close_registry();
}
else
{
  features = get_kb_list("WMI/server_feature/*");
  foreach key (keys(features))
  {
    if (features[key] == "Active Directory Federation Services")
    {
      adfs_is_present = TRUE;
      break;
    }
  }
}
if (!adfs_is_present) audit(AUDIT_NOT_INST, "ADFS");

if (
  # Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"microsoft.identityserver.dll", version:"6.1.7601.23675", dir:"\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35", bulletin:bulletin, kb:"3217882") ||
  # Windows Server 2008 R2 # security: 4012212, monthly: 4012215
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012212, 4012215)) ||
  # Windows Server 2012 # security: 4012214, monthly: 4012217
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012214, 3205409)) ||
  # Windows Server 2012 R2 # security: 4012213, monthly: 4012216
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012213, 4012216)) ||
  # Windows 2016
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012606)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013198)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013429))
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100056);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_cve_id("CVE-2017-0248");
  script_bugtraq_id(98117);
  script_osvdb_id(157277);
  script_xref(name:"MSKB", value:"4016871");
  script_xref(name:"MSKB", value:"4019108");
  script_xref(name:"MSKB", value:"4019109");
  script_xref(name:"MSKB", value:"4019110");
  script_xref(name:"MSKB", value:"4019111");
  script_xref(name:"MSKB", value:"4019112");
  script_xref(name:"MSKB", value:"4019113");
  script_xref(name:"MSKB", value:"4019114");
  script_xref(name:"MSKB", value:"4019115");
  script_xref(name:"MSKB", value:"4019472");
  script_xref(name:"MSKB", value:"4019473");
  script_xref(name:"MSKB", value:"4019474");
  script_xref(name:"IAVB", value:"2017-B-0055");

  script_name(english:"Security and Quality Rollup for .NET Framework (May 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a software framework installed that is
affected by a security feature bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft .NET Framework installed on the remote
Windows host is missing a security update. It is, therefore, affected
by a security bypass vulnerability in the Microsoft .NET Framework and
.NET Core components due to a failure to completely validate
certificates. An unauthenticated, remote attacker can exploit this to
present a certificate that is marked invalid for a specific use, but
the component uses it for that purpose, resulting in a bypass of the
Enhanced Key Usage taggings.");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/releasenotedetail/bc365363-f51e-e711-80da-000d3a32fc99
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?891ed5ca");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0248
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3805e39");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft .NET Framework
2.0 SP2, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2, and 4.7");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = "MS17-05";
kbs = make_list(
  '4019115', # 2008 SP2 Cumulative Rollup All .Net
  '4019109', # 2008 SP2 Security Only Rollup All .Net
  '4019112', # 7 SP1 / 2008 R2 SP1 Cumulative Rollup All .Net
  '4019108', # 7 SP1 / 2008 R2 SP1 Security Only Rollup All .Net
  '4019113', # Server 2012 Cumulative Rollup All .Net
  '4019110', # Server 2012 Security Only Rollup All .Net
  '4019114', # 8.1 / 2012 R2 Cumulative Rollup All .Net
  '4019111', # 8.1 / 2012 R2 Security Only Rollup All .Net
  '4019474', # 10 RTM Cumulative Rollup All .Net
  '4019473', # 10 1511 Cumulative Rollup All .Net
  '4019471', # 10 1607 Cumulative Rollup All .Net
  '4016871'  # 10 1703 Cumulative Rollup All .Net
  );

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);
else if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];

if(smb_check_dotnet_rollup(rollup_date:"05_2017", dotnet_ver:version))
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, hotfix_get_dotnet_audit_report(app:app, version:version));
}

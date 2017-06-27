#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99365);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id("CVE-2017-0160");
  script_bugtraq_id(97447);
  script_osvdb_id(155341);
  script_xref(name:"IAVB", value:"2017-B-0045");
  script_xref(name:"MSKB", value:"4014545");
  script_xref(name:"MSKB", value:"4014546");
  script_xref(name:"MSKB", value:"4014547");
  script_xref(name:"MSKB", value:"4014548");
  script_xref(name:"MSKB", value:"4014549");
  script_xref(name:"MSKB", value:"4014550");
  script_xref(name:"MSKB", value:"4014551");
  script_xref(name:"MSKB", value:"4014552");
  script_xref(name:"MSKB", value:"4014553");
  script_xref(name:"MSKB", value:"4014555");
  script_xref(name:"MSKB", value:"4014556");
  script_xref(name:"MSKB", value:"4014557");
  script_xref(name:"MSKB", value:"4014558");
  script_xref(name:"MSKB", value:"4014559");
  script_xref(name:"MSKB", value:"4014560");
  script_xref(name:"MSKB", value:"4014561");
  script_xref(name:"MSKB", value:"4014562");
  script_xref(name:"MSKB", value:"4014563");
  script_xref(name:"MSKB", value:"4014564");
  script_xref(name:"MSKB", value:"4014565");
  script_xref(name:"MSKB", value:"4014566");
  script_xref(name:"MSKB", value:"4014567");
  script_xref(name:"MSKB", value:"4014571");
  script_xref(name:"MSKB", value:"4014572");
  script_xref(name:"MSKB", value:"4014573");
  script_xref(name:"MSKB", value:"4014574");
  script_xref(name:"MSKB", value:"4015217");
  script_xref(name:"MSKB", value:"4015219");
  script_xref(name:"MSKB", value:"4015221");
  script_xref(name:"MSKB", value:"4015583");

  script_name(english:"Security and Quality Rollup for .NET Framework (April 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a software framework installed that is
affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft .NET Framework installed on the remote
Windows host is missing a security update. It is, therefore, affected
by an arbitrary code execution vulnerability due to a failure to
properly validate input before loading libraries. A local attacker can
exploit this to execute arbitrary code with elevated privileges.");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/releasenotedetail/42b8fa28-9d09-e711-80d9-000d3a32fc99
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af87bdc8");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0160
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75fb2a89");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft .NET Framework
2.0 SP2, 3.5, 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2, and 4.7");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

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
bulletin = "MS17-04";
kbs = make_list(
  '4014545',
  '4014546',
  '4014547',
  '4014548',
  '4014549',
  '4014550',
  '4014551',
  '4014552',
  '4014553',
  '4014555',
  '4014556',
  '4014557',
  '4014558',
  '4014559',
  '4014560',
  '4014561',
  '4014562',
  '4014563',
  '4014564',
  '4014565',
  '4014566',
  '4014567',
  '4014571',
  '4014572',
  '4014573',
  '4014574',
  '4015217',
  '4015219',
  '4015221',
  '4015583'
  );

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

app = 'Microsoft .NET Framework';
get_install_count(app_name:app, exit_if_zero:TRUE);
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];

if(smb_check_dotnet_rollup(rollup_date:"04_2017", dotnet_ver:version))
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, hotfix_get_dotnet_audit_report(app:app, version:version));
}

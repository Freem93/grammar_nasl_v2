#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59043);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-0160", "CVE-2012-0161");
  script_bugtraq_id(53356, 53357);
  script_osvdb_id(81733, 81734);
  script_xref(name:"MSFT", value:"MS12-035");
  script_xref(name:"IAVA", value:"2012-A-0080");

  script_name(english:"MS12-035: Vulnerabilities in .NET Framework Could Allow Remote Code Execution (2693777)");
  script_summary(english:"Check file versions");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The .NET Framework install on the remote Windows host could allow
arbitrary code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the .NET Framework installed on the remote host is
affected by multiple vulnerabilities in the serialization process.
Untrusted data is treated as trusted which could result in arbitrary
code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS12-035");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for .NET Framework 1.0, 1.1,
2.0, 3.0, 3.5, and 4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-035';
kbs = make_list('2604042', '2604044', '2604078', '2604092', '2604094', '2604105', '2604110', '2604111', '2604114', '2604115', '2604121');
if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
assembly_dir_30 = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0\All Assemblies In");
assembly_dir_35 = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.5\All Assemblies In");
RegCloseKey(handle:hklm);
close_registry();

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

# .NET Framework 1.0 SP3 on XP SP3 Tablet and XP SP3 Media Center
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", arch:"x86", sp:3, file:"mscorlib.dll", version:"1.0.3705.6098", dir:"\Microsoft.NET\Framework\v1.0.3705");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2604042');
vuln += missing;

# .NET Framework 1.1 on XP, Windows Server 2003 64-bit, Vista, and Server 2008
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", arch:"x86", sp:3, file:"mscorlib.dll", version:"1.1.4322.2494", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"mscorlib.dll", version:"1.1.4322.2494", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"6.0",             sp:2, file:"mscorlib.dll", version:"1.1.4322.2494", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2604044');
vuln += missing;

# .NET Framework 1.1 on Windows Server 2003 SP2
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"mscorlib.dll", version:"1.1.4322.2494", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2604078');
vuln += missing;

# .NET Framework 2.0 SP2 on Windows XP / Server 2003
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"2.0.50727.5710", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"2.0.50727.3634", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.5710", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.3634", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2604092");
vuln += missing;

# .NET Framework 2.0 SP2 on Windows Vista SP2 / Server 2008 SP2
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.5710", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.4223", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2604094");
vuln += missing;

# .NET Framework 3.0 SP2 on Windows XP / Server 2003
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"WindowsBase.dll", version:"3.0.6920.4021", min_version:"3.0.6920.0", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"WindowsBase.dll", version:"3.0.6920.5810", min_version:"3.0.6920.5000", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"WindowsBase.dll", version:"3.0.6920.4021", min_version:"3.0.6920.0", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"WindowsBase.dll", version:"3.0.6920.5810", min_version:"3.0.6920.5000", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2604110");
  vuln += missing;
}

# .NET Framework 3.0 SP2 on Windows Vista SP2 / Server 2008 SP2
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"WindowsBase.dll", version:"3.0.6920.4206", min_version:"3.0.6920.0", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"WindowsBase.dll", version:"3.0.6920.5738", min_version:"3.0.6920.5000", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2604105");
  vuln += missing;
}

# .NET Framework 3.5 SP1 on Windows XP / Server 2003 / Vista / Server 2008
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.AddIn.dll", version:"3.5.30729.3676", min_version:"3.5.30729.0", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.AddIn.dll", version:"3.5.30729.5766", min_version:"3.5.30729.5000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.AddIn.dll", version:"3.5.30729.3676", min_version:"3.5.30729.0", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.AddIn.dll", version:"3.5.30729.5766", min_version:"3.5.30729.5000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.AddIn.dll", version:"3.5.30729.3676", min_version:"3.5.30729.0", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.AddIn.dll", version:"3.5.30729.5766", min_version:"3.5.30729.5000", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2604111");
  vuln += missing;
}

# .NET Framework 3.5.1 on Windows 7 / Server 2008 R2
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"mscorlib.dll", version:"2.0.50727.5723", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"mscorlib.dll", version:"2.0.50727.4971", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2604114");
vuln += missing;

# .NET Framework 3.5.1 on Windows 7 SP1 / Server 2008 R2 SP1
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.5710", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.5456", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2604115");
vuln += missing;

# .NET Framework 4 on all supported versions of Windows
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"mscorlib.dll", version:"4.0.30319.269", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", file:"mscorlib.dll", version:"4.0.30319.544", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"mscorlib.dll", version:"4.0.30319.269", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"mscorlib.dll", version:"4.0.30319.544", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", file:"mscorlib.dll", version:"4.0.30319.269", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", file:"mscorlib.dll", version:"4.0.30319.544", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"mscorlib.dll", version:"4.0.30319.269", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"mscorlib.dll", version:"4.0.30319.544", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2604121");
vuln += missing;

if (vuln > 0)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}


#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56452);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2011-1253");
  script_bugtraq_id(49999);
  script_osvdb_id(76214);
  script_xref(name:"MSFT", value:"MS11-078");

  script_name(english:"MS11-078: Vulnerability in .NET Framework and Microsoft Silverlight Could Allow Remote Code Execution (2604930)");
  script_summary(english:"Checks version of mscorlib.dll");

  script_set_attribute(attribute:"synopsis", value:
"The version of the .NET Framework installed on the remote host allows
arbitrary code execution.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of the Microsoft .NET
Framework or Silverlight 4 that improperly restricts inheritance within
classes.  A remote attacker could exploit this issue by tricking a user
into viewing a specially crafted web page, resulting in arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-078");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for the .NET Framework on
Windows XP, 2003, Vista, 2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "silverlight_detect.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-078';
kbs = make_list("2512827", "2572067", "2572069", "2572073", "2572075", "2572076", "2572077", "2572078");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

if (hotfix_check_server_core() != 1)
{
  # Silverlight on non-Server Core installations
  ver = get_kb_item("SMB/Silverlight/Version");
  fix = '4.0.60831.0';

  # The advisory says only Silverlight 4 is vulnerable
  if (!isnull(ver) && ver =~ '^4' && ver_compare(ver:ver, fix:fix) == -1)
  {
    path = get_kb_item( "SMB/Silverlight/Path" );
    report +=
      '\n  Product           : Microsoft Silverlight' +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix + '\n';
    hotfix_add_report(report, bulletin:bulletin, kb:'2512827');
    vuln++;
  }
}

# .NET Framework 1.1 on XP, Windows Server 2003 64-bit, Vista, and Server 2008
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", arch:"x86", sp:3, file:"mscorlib.dll", version:"1.1.4322.2490", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"mscorlib.dll", version:"1.1.4322.2490", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"6.0",             sp:2, file:"mscorlib.dll", version:"1.1.4322.2490", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2572067');
vuln += missing;

# .NET Framework 1.1 on Windows Server 2003 SP2
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"mscorlib.dll", version:"1.1.4322.2490", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2572069');
vuln += missing;

# .NET Framework 2.0 SP2 on Windows XP / Server 2003
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"2.0.50727.5681", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"2.0.50727.3625", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.5681", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.3625", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2572073");
vuln += missing;

# .NET Frameework 2.0 SP2 on Windows Vista SP2 / Server 2008 SP2
missing = 0;
if (hotfix_check_server_core() != 1)
{
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.5681", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.4216", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2572075");
vuln += missing;

# .NET Framework 3.5.1 on Windows 7 / Server 2008 R2
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"mscorlib.dll", version:"2.0.50727.5681", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"mscorlib.dll", version:"2.0.50727.4963", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2572076");
vuln += missing;

# .NET Framework 3.5.1 on Windows 7 SP1 / Server 2008 R2 SP1
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.5681", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.5448", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2572077");
vuln += missing;

# .NET Framework 4 on all supported versions of Windows
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"mscorlib.dll", version:"4.0.30319.239", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", file:"mscorlib.dll", version:"4.0.30319.488", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"mscorlib.dll", version:"4.0.30319.239", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"mscorlib.dll", version:"4.0.30319.488", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
if (hotfix_check_server_core() != 1)
{
  missing += hotfix_is_vulnerable(os:"6.0", file:"mscorlib.dll", version:"4.0.30319.239", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.0", file:"mscorlib.dll", version:"4.0.30319.488", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
}
missing += hotfix_is_vulnerable(os:"6.1", file:"mscorlib.dll", version:"4.0.30319.239", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"mscorlib.dll", version:"4.0.30319.488", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2572078");
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

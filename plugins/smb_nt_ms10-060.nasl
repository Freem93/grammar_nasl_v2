#
# (C) Tenable Network Security, Inc.
#

# Nessus 2.x can't handle long titles
if (NASL_LEVEL < 3000) exit(1);

include("compat.inc");


if (description)
{
  script_id(48297);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-0019", "CVE-2010-1898");
  script_bugtraq_id(42138, 42295);
  script_osvdb_id(66992, 66993);
  script_xref(name:"MSFT", value:"MS10-060");

  script_name(english:"MS10-060: Vulnerabilities in the Microsoft .NET Common Language Runtime and in Microsoft Silverlight Could Allow Remote Code Execution (2265906)");
  script_summary(english:"Checks version of mscorlib.dll / Silverlight version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Microsoft .NET Common Language Runtime and/or Microsoft
Silverlight have multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of the Microsoft .NET
Framework and/or Microsoft Silverlight affected by multiple
vulnerabilities :

  - Silverlight improperly handles pointers in an unspecified
    manner.  A remote attacker could exploit this by tricking
    a user into viewing a web page with maliciously crafted
    Silverlight content. (CVE-2010-0019)

  - An unspecified vulnerability in the .NET framework can
    allow a specially crafted .NET or Silverlight application
    to access memory, resulting in arbitrary unmanaged
    code execution. (CVE-2010-1898)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-060");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for .NET Framework 2.0, 3.5,
and Silverlight."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "silverlight_detect.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-060';

kbs = make_list(
  "978464",
  "982926",
  "983582",
  "983583",
  "983587",
  "983588",
  "983589",
  "983590"
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Check Silverlight unless server core is installed
silverlight_vuln = FALSE;
if (hotfix_check_server_core() != 1)
{
  ver = get_kb_item("SMB/Silverlight/Version");
  fix = '3.0.50611.0';

  if (!isnull(ver) && ver_compare(ver:ver, fix:fix) == -1)
  {
    path = get_kb_item( "SMB/Silverlight/Path" );
    report +=
      '\n  Product           : Microsoft Silverlight' +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fix               : ' + fix + '\n';
    if (ver =~ '^[0-2]\\.')
    {
      hotfix_add_report(report, bulletin:bulletin, kb:'982926');
    }
    else if (ver =~ '^3\\.')
    {
      hotfix_add_report(report, bulletin:bulletin, kb:'978464');
    }
    silverlight_vuln = TRUE;
  }
}

if (
  # Server core is not affected _only for the following versions_
  (
    hotfix_check_server_core() != 1 &&

    (
      # 2.0 SP1 and 3.5 on Vista SP1 and Server 2008
      hotfix_is_vulnerable(os:"6.0", sp:1, file:"mscorlib.dll", version:"2.0.50727.1882", min_version:"2.0.50727.1500", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983587') ||

      # 2.0 SP2 and 3.5 SP1 on Vista SP1 and Server 2008
      hotfix_is_vulnerable(os:"6.0", sp:1, file:"mscorlib.dll", version:"2.0.50727.3615", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983588') ||
      hotfix_is_vulnerable(os:"6.0", sp:1, file:"mscorlib.dll", version:"2.0.50727.4454", min_version:"2.0.50727.4400", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983588') ||

      # 2.0 SP2 and 3.5 SP1 on Vista SP2 and Server 2008 SP2
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.4206", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983589') ||
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.4454", min_version:"2.0.50727.4400", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983589')
    )
  ) ||

  # 3.5
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"mscorlib.dll", version:"2.0.50727.3615", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983582') ||
  hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"mscorlib.dll", version:"2.0.50727.4455", min_version:"2.0.50727.4400", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983582') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"mscorlib.dll", version:"2.0.50727.3615", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983582') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"mscorlib.dll", version:"2.0.50727.4455", min_version:"2.0.50727.4400", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983582') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"mscorlib.dll", version:"2.0.50727.1882", min_version:"2.0.50727.1500", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983582') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"mscorlib.dll", version:"2.0.50727.3615", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983582') || # not listed in KB, but this is what we see in the lab
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"mscorlib.dll", version:"2.0.50727.4455", min_version:"2.0.50727.4400", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983582') ||

  # 3.5.1
  hotfix_is_vulnerable(os:"6.1", file:"mscorlib.dll", version:"2.0.50727.4952", min_version:"2.0.50727.4800", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983590') ||
  hotfix_is_vulnerable(os:"6.1", file:"mscorlib.dll", version:"2.0.50727.5018", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'983590') ||

  # Even if .NET is patched, the plugin should still fire if a vulnerable version of silverlight was detected
  silverlight_vuln
)
{
  set_kb_item(name:"SMB/Missing/MS10-060", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

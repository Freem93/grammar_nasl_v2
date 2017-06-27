#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55119);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2011-0664");
  script_bugtraq_id(48212);
  script_osvdb_id(72931);
  script_xref(name:"MSFT", value:"MS11-039");

  script_name(english:"MS11-039: Vulnerability in .NET Framework and Microsoft Silverlight Could Allow Remote Code Execution (2514842)");
  script_summary(english:"Checks version of system.dll / Silverlight");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Microsoft .NET Framework and/or Microsoft Silverlight install on
the remote host has a code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of the Microsoft .NET
Framework and/or Microsoft Silverlight affected by a code execution
vulnerability.  A specially crafted .NET application could access memory
unsafely, resulting in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-039");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for .NET Framework 2.0, 3.5,
and Silverlight."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS11-039';
kbs = make_list("2478656", "2478657", "2478658", "2478659", "2478660", "2478661", "2478662", "2478663", "2512827");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;


# Silverlight on non-Server Core installations
if (hotfix_check_server_core() != 1)
{
  ver = get_kb_item("SMB/Silverlight/Version");
  fix = '4.0.60531.0';

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
    vuln = TRUE;
  }
}

# 3.5 on XP, 2k3
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.dll", version:"2.0.50727.1889", min_version:"2.0.50727.1433", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.dll", version:"2.0.50727.1889", min_version:"2.0.50727.1433", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2478656');
vuln += missing;

# 3.5 SP1 and 2.0 SP2 on XP, 2k3
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.dll", version:"2.0.50727.3620", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", file:"System.dll", version:"2.0.50727.5071", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.dll", version:"2.0.50727.3620", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.dll", version:"2.0.50727.5071", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2478658');
vuln += missing;

# 2.0 SP1 and 3.5 on Vista SP1 and 2008
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:1, file:"System.dll", version:"2.0.50727.1889", min_version:"2.0.50727.1000", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2478657');
vuln += missing;

# 2.0 SP2 and 3.5 SP1 on Vista SP1 and 2008
missing = 0;
if (hotfix_check_server_core() != 1) # 2008 Server Core is not affected
{
  missing += hotfix_is_vulnerable(os:"6.0", sp:1, file:"System.dll", version:"2.0.50727.3620", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.0", sp:1, file:"System.dll", version:"2.0.50727.5071", min_version:"2.0.50727.4400", dir:"\Microsoft.NET\Framework\v2.0.50727");
}
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2478659');
vuln += missing;

# 2.0 SP2 and 3.5 SP1 on Vista SP2, 2k8 SP2
missing = 0;
if (hotfix_check_server_core() != 1) # 2008 Server Core is not affected
{
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"2.0.50727.4212", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"2.0.50727.5071", min_version:"2.0.50727.4400", dir:"\Microsoft.NET\Framework\v2.0.50727");
}
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2478660');
vuln += missing;

# 3.5.1 on Windows 7 and 2008 R2
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.dll", version:"2.0.50727.5071", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.dll", version:"2.0.50727.4957", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2478661');
vuln += missing;

# 3.5.1 on Windows 7 SP1 and 2008 R2 SP1
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"2.0.50727.5650", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"2.0.50727.5442", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2478662');
vuln += missing;

# 4.0 on XP, 2k3, Vista, 2k8, 7, 2008 R2
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.dll", version:"4.0.30319.232", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", file:"System.dll", version:"4.0.30319.447", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.dll", version:"4.0.30319.232", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.dll", version:"4.0.30319.447", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
if (hotfix_check_server_core() != 1) # 2008 Server Core is not affected
{
  missing += hotfix_is_vulnerable(os:"6.0", file:"System.dll", version:"4.0.30319.232", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.0", file:"System.dll", version:"4.0.30319.232", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
}
missing += hotfix_is_vulnerable(os:"6.1", file:"System.dll", version:"4.0.30319.232", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"System.dll", version:"4.0.30319.447", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2478663');
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

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57950);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-0014", "CVE-2012-0015");
  script_bugtraq_id(51938, 51940);
  script_osvdb_id(79260, 79261);
  script_xref(name:"MSFT", value:"MS12-016");

  script_name(english:"MS12-016: Vulnerabilities in .NET Framework and Microsoft Silverlight Could Allow Remote Code Execution (2651026)");
  script_summary(english:"Checks version of Silverlight.exe / system.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The .NET Framework install on the remote Windows host could allow
arbitrary code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the .NET Framework installed on the remote host
reportedly is affected by the following vulnerabilities :

  - The .NET Framework and Silverlight do not properly use
    unmanaged objects, which could allow a malicious .NET
    Framework application to access memory in an unsafe
    manner. (CVE-2012-0014)

  - The .NET Framework does not properly calculate a buffer
    length when processing malicious input, which could
    lead to heap corruption. (CVE-2012-0015)

An attacker may be able to leverage these vulnerabilities to execute
arbitrary code on the affected system if a user on it can be tricked
into viewing a specially crafted web page using a web browser that can
run XAML Browser Applications (XBAPs) or Silverlight applications."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-016");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for .NET Framework 2.0, 3.5.1,
and 4 as well as Silverlight 4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "silverlight_detect.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS12-016';
kbs = make_list(
  "2668562",
  "2633869",
  "2638804",
  "2633870",
  "2633873",
  "2633879",
  "2633877",
  "2633874",
  "2633880"
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


vuln = 0;

# Silverlight 4.x
ver = get_kb_item("SMB/Silverlight/Version");
fix = '4.1.10111';

if (!isnull(ver) && ver =~ '^4\\.' && ver_compare(ver:ver, fix:fix) == -1)
{
  path = get_kb_item("SMB/Silverlight/Path");
  report +=
    '\n  Product           : Microsoft Silverlight' +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  hotfix_add_report(report, bulletin:bulletin, kb:"2668562");
  vuln++;
}

# .NET Framework 2.0 SP2 on Windows XP SP3 / Server 2003 SP2
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.dll", version:"2.0.50727.5704", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.dll", version:"2.0.50727.3631", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.dll", version:"2.0.50727.5704", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.dll", version:"2.0.50727.3631", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2633880");
vuln += missing;

# .NET Framework 2.0 SP2 on Windows Vista SP2 / Server 2008 SP2
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"2.0.50727.5703", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"2.0.50727.4220", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2633874");
vuln += missing;

# .NET Framework 3.5.1 on Windows 7 / Server 2008 R2
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.dll", version:"2.0.50727.5703", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.dll", version:"2.0.50727.4968", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2633879");
vuln += missing;

# .NET Framework 3.5.1 on Windows 7 SP1 / Server 2008 R2 SP1
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"2.0.50727.5703", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"2.0.50727.5453", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2633873");
vuln += missing;

# .NET Framework 4.0 on all supported versions of Windows
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.dll", version:"4.0.30319.258", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", file:"System.dll", version:"4.0.30319.523", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.dll", version:"4.0.30319.258", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.dll", version:"4.0.30319.523", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", file:"System.dll", version:"4.0.30319.258", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", file:"System.dll", version:"4.0.30319.523", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"System.dll", version:"4.0.30319.258", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"System.dll", version:"4.0.30319.523", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2633870");
vuln += missing;

# # .NET Framework 4.5 Developer Preview on Windows Vista, 2008, 7, and 2008 R2.
# missing = 0;
# missing += hotfix_is_vulnerable(os:"6.0", file:"System.dll", version:"4.0.30319.17081", min_version:"4.0.30319.10000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# missing += hotfix_is_vulnerable(os:"6.0", file:"System.dll", version:"4.0.30319.17175", min_version:"4.0.30319.17000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# missing += hotfix_is_vulnerable(os:"6.1", file:"System.dll", version:"4.0.30319.17081", min_version:"4.0.30319.10000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# missing += hotfix_is_vulnerable(os:"6.1", file:"System.dll", version:"4.0.30319.17175", min_version:"4.0.30319.17000", dir:"\Microsoft.NET\Framework\v4.0.30319");
#
# if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2638804");
# vuln += missing;

# nb: we're not covering here KBs 2633869 or 2633877 as they apply to
#     Windows Developer Preview (Windows 8).

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

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58657);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-0163");
  script_bugtraq_id(52921, 53204);
  script_osvdb_id(81133);
  script_xref(name:"EDB-ID", value:"18777");
  script_xref(name:"MSFT", value:"MS12-025");

  script_name(english:"MS12-025: Vulnerability in .NET Framework Could Allow Remote Code Execution (2671605)");
  script_summary(english:"Checks version of system.drawing.dll");

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
reportedly is affected by a code execution vulnerability because of
the way .NET Framework validates parameters when passing data to a
function.

An attacker may be able to leverage these vulnerabilities to execute
arbitrary code on the affected system if a user can be tricked into
viewing a specially crafted web page using a web browser that can run
XAML Browser Applications (XBAPs).  The vulnerability could also be
exploited by uploading a specially crafted ASP.NET page to a server
system running IIS and then executing that page."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.akitasecurity.nl/advisory.html?id=AK20110801");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-025");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for .NET Framework 1.0,
1.1, 2.0, 3.5.1, and 4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
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


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-025';
kbs = make_list(
  '2656368',
  '2656369',
  '2656370',
  '2656372',
  '2656373',
  '2656374',
  '2656376',
  '2656378'
);
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

# .NET Framework 1.0 on XP Media Center Editio
#missing = 0;
#missing += hotfix_is_vulnerable(os:"5.1", arch:"x86", sp:3, file:"System.drawing.dll", version:"1.0.3705.6100", dir:"\Microsoft.NET\Framework\v1.1.4322");
#if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2656378');
#vuln += missing;

# .NET Framework 1.1 on XP, Windows Server 2003 64-bit, Vista, and Server 2008
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", arch:"x86", sp:3, file:"System.drawing.dll", version:"1.1.4322.2497", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"System.drawing.dll", version:"1.1.4322.2497", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"6.0",             sp:2, file:"System.drawing.dll", version:"1.1.4322.2497", dir:"\Microsoft.NET\Framework\v1.1.4322");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2656370');
vuln += missing;


# .NET Framework 2.0 SP2 on Windows XP SP3 / Server 2003 SP2
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.drawing.dll", version:"2.0.50727.5729", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.drawing.dll", version:"2.0.50727.3639", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.drawing.dll", version:"2.0.50727.5729", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.drawing.dll", version:"2.0.50727.3639", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656369");
vuln += missing;

# .NET Framework 2.0 SP2 on Windows Vista SP2 / Server 2008 SP2
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.drawing.dll", version:"2.0.50727.5729", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.drawing.dll", version:"2.0.50727.4230", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656374");
vuln += missing;

# .NET Framework 3.5.1 on Windows 7 / Server 2008 R2
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.drawing.dll", version:"2.0.50727.5729", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.drawing.dll", version:"2.0.50727.4980", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656372");
vuln += missing;

# .NET Framework 3.5.1 on Windows 7 SP1 / Server 2008 R2 SP1
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.drawing.dll", version:"2.0.50727.5729", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.drawing.dll", version:"2.0.50727.5462", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656373");
vuln += missing;

# .NET Framework 4.0 on all supported versions of Windows
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.drawing.dll", version:"4.0.30319.282", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", file:"System.drawing.dll", version:"4.0.30319.568", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.drawing.dll", version:"4.0.30319.282", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.drawing.dll", version:"4.0.30319.568", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", file:"System.drawing.dll", version:"4.0.30319.282", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", file:"System.drawing.dll", version:"4.0.30319.568", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"System.drawing.dll", version:"4.0.30319.282", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"System.drawing.dll", version:"4.0.30319.568", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656368");
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

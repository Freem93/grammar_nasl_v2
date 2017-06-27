#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57414);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id(
    "CVE-2011-3414",
    "CVE-2011-3415",
    "CVE-2011-3416",
    "CVE-2011-3417"
  );
  script_bugtraq_id(51186, 51201, 51202, 51203);
  script_osvdb_id(78054, 78055, 78056, 78057);
  script_xref(name:"CERT", value:"903934");
  script_xref(name:"MSFT", value:"MS11-100");

  script_name(english:"MS11-100: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (2638420)");
  script_summary(english:"Checks version of System.Web.dll / System.web.Extensions.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of ASP.NET Framework installed on the remote host is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of the Microsoft ASP.NET
Framework that has multiple vulnerabilities.  These include:

  - A flaw exists in the way ASP.NET generates hash tables
    for user-supplied values.  By sending a small number of
    specially crafted posts to an ASP.NET server, an
    attacker can take advantage of this flaw to cause a
    denial of service condition.  (CVE-2011-3414)

  - The Framework does not properly validate return URLs
    during the forms authentication process, which could
    allow an attacker to redirect a victim to a malicious
    website. (CVE-2011-3415)

  - ASP.NET forms authentication contains a vulnerability
    that could allow an attacker that already has a
    registered user on an application to gain the
    privileges of another known user. (CVE-2011-3416)

  - An elevation of privilege vulnerability exists in the
    way that ASP.NET Framework handles cached content when
    Forms Authentication is used with sliding expiry.  An
    attacker can take advantage of this vulnerability to
    execute code in the context of a target user by
    tricking the user into visiting a specially crafted
    link. (CVE-2011-3417)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nruns.com/_downloads/advisory28122011.pdf");
  # https://www.sec-consult.com/files/20120328-1_asp.net_authentication_bypass_v1.0.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f313f636");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-100");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for the .NET Framework on
Windows XP, 2003, Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS11-100';
kbs = make_list('2656351', '2656356', '2657424', '2656352', '2656362', '2656355', '2656358', '2656353');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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
ass_dir = hotfix_get_programfilesdir() + "\Reference Assemblies\Microsoft\Framework";

# .NET Framework 1.1 on XP, Windows Server 2003 64-bit, Vista, and Server 2008
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", arch:"x86", sp:3, file:"System.Web.dll", version:"1.1.4322.2494", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"System.Web.dll", version:"1.1.4322.2494", dir:"\Microsoft.NET\Framework\v1.1.4322");
if (hotfix_check_server_core() != 1)
{
  missing += hotfix_is_vulnerable(os:"6.0",             sp:2, file:"System.Web.dll", version:"1.1.4322.2494", dir:"\Microsoft.NET\Framework\v1.1.4322");
}
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2656353');
vuln += missing;

# .NET Framework 1.1 on Windows Server 2003 SP2
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"system.web.dll", version:"1.1.4322.2494", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2656358');
vuln += missing;

# .NET Framework 2.0 SP2 on Windows XP / Server 2003
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.dll", version:"2.0.50727.5710", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.dll", version:"2.0.50727.3634", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"2.0.50727.5710", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"2.0.50727.3634", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656352");
vuln += missing;

# .NET Framework 2.0 SP2 on Windows Vista SP2 / Server 2008 SP2
missing = 0;
if (hotfix_check_server_core() != 1)
{
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.web.dll", version:"2.0.50727.5710", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.web.dll", version:"2.0.50727.4223", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656362");
vuln += missing;

# .NET 3.5 SP1 on XP, 2k3, Vista, 2k8
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.Extensions.dll", version:"3.5.30729.3678", min_version:"3.5.30729.0", path:ass_dir + "\v3.5");
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.Extensions.dll", version:"3.5.30729.5769", min_version:"3.5.30729.5000", path:ass_dir + "\v3.5");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.Extensions.dll", version:"3.5.30729.3678", min_version:"3.5.30729.0", path:ass_dir + "\v3.5");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.Extensions.dll", version:"3.5.30729.5769", min_version:"3.5.30729.5000", path:ass_dir + "\v3.5");
if (hotfix_check_server_core() != 1)
{
  missing += hotfix_is_vulnerable(os:"6.0", file:"System.Web.Extensions.dll", version:"3.5.30729.3678", min_version:"3.5.30729.0", path:ass_dir + "\v3.5");
  missing += hotfix_is_vulnerable(os:"6.0", file:"System.Web.Extensions.dll", version:"3.5.30729.5769", min_version:"3.5.30729.5000", path:ass_dir + "\v3.5");
}
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2657424');
vuln += missing;

# .NET Framework 3.5.1 on Windows 7 / Server 2008 R2
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"system.web.dll", version:"2.0.50727.5710", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"system.web.dll", version:"2.0.50727.4971", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656355");
vuln += missing;

# .NET Framework 3.5.1 on Windows 7 SP1 / Server 2008 R2 SP1
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.dll", version:"2.0.50727.5456", min_version:"2.0.50727.5400", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.dll", version:"2.0.50727.5710", min_version:"2.0.50727.5700", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656356");
vuln += missing;

# .NET Framework 4 on all supported versions of Windows
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.dll", version:"4.0.30319.272", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", file:"System.Web.dll", version:"4.0.30319.547", min_version:"4.0.30319.500", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.dll", version:"4.0.30319.272", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.Web.dll", version:"4.0.30319.547", min_version:"4.0.30319.500", dir:"\Microsoft.NET\Framework\v4.0.30319");
if (hotfix_check_server_core() != 1)
{
  missing += hotfix_is_vulnerable(os:"6.0", file:"System.Web.dll", version:"4.0.30319.272", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.0", file:"System.Web.dll", version:"4.0.30319.547", min_version:"4.0.30319.500", dir:"\Microsoft.NET\Framework\v4.0.30319");
}
missing += hotfix_is_vulnerable(os:"6.1", file:"System.Web.dll", version:"4.0.30319.272", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"System.Web.dll", version:"4.0.30319.547", min_version:"4.0.30319.500", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656351");
vuln += missing;

if(vuln > 0)
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

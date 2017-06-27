#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55124);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2011-1271");
  script_bugtraq_id(47834);
  script_osvdb_id(72932);
  script_xref(name:"MSFT", value:"MS11-044");
  script_xref(name:"IAVA", value:"2011-A-0082");

  script_name(english:"MS11-044: Vulnerability in .NET Framework Could Allow Remote Code Execution (2538814)");
  script_summary(english:"Checks version of mscorlib.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of the .NET Framework installed on the remote host allows
arbitrary code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The JIT compiler included with the version of the .NET Framework
installed on the remote host incorrectly validates certain values within
an object.

An attacker may be able to leverage this vulnerability to run arbitrary
code as the logged in user or the user account of ASP.NET on the
affected system under either of the following scenarios :

  - Tricking a user on the affected host into viewing a
    specially crafted web page using a web browser that can
    run XAML Browser Applications (XBAPs).

  - Uploading a malicious ASP.NET application to be hosted
    on the affected host.

  - Bypassing Code Access Security (CAS) restrictions in a
    Windows .NET application."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-044");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for the .NET Framework on
Windows XP, 2003, Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS11-044';
kbs = make_list(
  '2518863',
  '2518864',
  '2518865',
  '2518866',
  '2518867',
  '2518869',
  '2518870',
  '2530095'
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


vuln = 0;

# .NET Framework 4
if (
  hotfix_is_vulnerable(file:"mscorlib.dll", version:"4.0.30319.454", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319",   bulletin:bulletin, kb:'2518870') ||
  hotfix_is_vulnerable(file:"mscorlib.dll", version:"4.0.30319.235", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319",   bulletin:bulletin, kb:'2518870')
) vuln++;

# NET Framework 3.5 SP1 and .NET Framework 2.0 Service Pack 2
if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.5662", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518869') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.5446", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518869') ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"mscorlib.dll", version:"2.0.50727.5662", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518867') ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"mscorlib.dll", version:"2.0.50727.4961", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518867') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.5662", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518866') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.4214", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518866') ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"mscorlib.dll", version:"2.0.50727.5662", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518865') ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"mscorlib.dll", version:"2.0.50727.3623", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518865') ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.5662", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518864') ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.3623", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518864') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"2.0.50727.5662", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518864') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"2.0.50727.3623", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518864')
) vuln++;

# NET Framework 3.5
if (
  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"mscorlib.dll", version:"2.0.50727.1891", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2518863') ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.1891", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2530095') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"2.0.50727.1891", min_version:"2.0.50727.0",    dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2530095')
) vuln++;

if (vuln)
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

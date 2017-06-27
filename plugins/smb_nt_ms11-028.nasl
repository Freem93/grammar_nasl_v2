#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53385);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/04/06 22:02:43 $");

  script_cve_id("CVE-2010-3958");
  script_bugtraq_id(47223);
  script_osvdb_id(71782);
  script_xref(name:"MSFT", value:"MS11-028");

  script_name(english:"MS11-028: Vulnerability in .NET Framework Could Allow Remote Code Execution (2484015)");
  script_summary(english:"Checks version of mscorjit.dll / clrjit.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of the .NET Framework installed on the remote host allows
arbitrary code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The x86 JIT compiler included with the version of the .NET Framework
installed on the remote host incorrectly compiles certain types of
function calls.

An attacker may be able to leverage this vulnerability to run arbitrary
code on the affected system under either of the following scenarios :

  - Tricking a user on the affected host into viewing a
    specially crafted web page using a web browser that can
    run XAML Browser Applications (XBAPs).

  - Uploading a malicious ASP.NET application to be hosted
    on the affected host.

  - Bypassing Code Access Security (CAS) restrictions in a
    Windows .NET application."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-028");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for the .NET Framework on
Windows XP, 2003, Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
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

# Windows Embedded is not supported by Nessus
# There are cases where this plugin is flagging embedded
# hosts improperly since this update does not apply
# to those machines
productname = get_kb_item("SMB/ProductName");
if ("Windows Embedded" >< productname)
  exit(0, "Nessus does not support bulletin / patch checks for Windows Embedded.");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-028';
kbs = make_list('2446704', '2446708', '2446709', '2446710', '2449741', '2449742');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
windows_version = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# nb: Server Core is not available for Itanium so this won't keep the
#     plugin from checking Windows 2008 installs on that architecture.
if (
  hotfix_check_server_core() == 1 &&
  windows_version == '6.0'
) exit(0, "Server Core installs for Windows 2008 are not affected.");


rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

# .NET Framework 4
if (
  hotfix_is_vulnerable(file:"clrjit.dll", version:"4.0.30319.431", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319",   bulletin:bulletin, kb:'2446708') ||
  hotfix_is_vulnerable(file:"clrjit.dll", version:"4.0.30319.225", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319",   bulletin:bulletin, kb:'2446708')
) vuln++;

# NET Framework 3.5.1
if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorjit.dll", version:"2.0.50727.5653", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2446710') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorjit.dll", version:"2.0.50727.5444", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2446710') ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"mscorjit.dll", version:"2.0.50727.5653", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2446709') ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"mscorjit.dll", version:"2.0.50727.4959", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2446709') ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorjit.dll", version:"2.0.50727.5653", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2449742') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorjit.dll", version:"2.0.50727.4211", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2449742') ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"mscorjit.dll", version:"2.0.50727.5653", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2449741') ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"mscorjit.dll", version:"2.0.50727.3619", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2449741') ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorjit.dll", version:"2.0.50727.5653", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2446704') ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorjit.dll", version:"2.0.50727.3620", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2446704') ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorjit.dll", version:"2.0.50727.5653", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2446704') ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorjit.dll", version:"2.0.50727.3620", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'2446704')
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

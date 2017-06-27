#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55799);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2011-1978");
  script_bugtraq_id(48991);
  script_osvdb_id(74404);
  script_xref(name:"MSFT", value:"MS11-069");

  script_name(english:"MS11-069: Vulnerability in .NET Framework Could Allow Information Disclosure (2567951)");
  script_summary(english:"Checks version of system.dll");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Framework install on the remote host is affected by
an improper validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of the Microsoft .NET
Framework that improperly validates the trust level within the
System.Net.Sockets namespace.  A remote attacker could exploit this
issue by tricking a user into viewing a specially crafted XML file,
resulting in information disclosure or partial denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-069");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 2.0,
3.5.1, and 4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS11-069';
kbs = make_list("2539631", "2539633", "2539634", "2539635", "2539636");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


vuln = 0;


# .NET Framework 2.0 SP2 on Windows XP SP3 / Server 2003 SP2
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.dll", version:"2.0.50727.5668", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.dll", version:"2.0.50727.3624", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.dll", version:"2.0.50727.5668", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.dll", version:"2.0.50727.3624", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2539631");
vuln += missing;

# .NET Framework 2.0 SP2 on Windows Vista SP2 / Server 2008 SP2
missing = 0;
if (hotfix_check_server_core() != 1)
{
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"2.0.50727.5668", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"2.0.50727.4215", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2539633");
vuln += missing;

# .NET Framework 3.5.1 on Windows 7 / Server 2008 R2
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.dll", version:"2.0.50727.5668", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.dll", version:"2.0.50727.4962", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2539634");
vuln += missing;

# .NET Framework 3.5.1 on Windows 7 SP1 / Server 2008 R2 SP1
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"2.0.50727.5668", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"2.0.50727.5447", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2539635");
vuln += missing;

# .NET Framework 4 on all supported versions of Windows
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"System.dll", version:"4.0.30319.236", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", file:"System.dll", version:"4.0.30319.463", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.dll", version:"4.0.30319.236", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", file:"System.dll", version:"4.0.30319.463", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
if (hotfix_check_server_core() != 1)
{
  missing += hotfix_is_vulnerable(os:"6.0", file:"System.dll", version:"4.0.30319.236", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.0", file:"System.dll", version:"4.0.30319.463", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.1", file:"System.dll", version:"4.0.30319.236", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.1", file:"System.dll", version:"4.0.30319.463", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2539636");
vuln += missing;

if (vuln > 0)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

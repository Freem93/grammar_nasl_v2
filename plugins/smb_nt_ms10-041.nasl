#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46848);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/06/30 19:55:38 $");

  script_cve_id("CVE-2009-0217");
  script_bugtraq_id(35671);
  script_osvdb_id(56243);
  script_xref(name:"CERT", value:"466161");
  script_xref(name:"MSFT", value:"MS10-041");
  script_xref(name:"IAVB", value:"2010-B-0046");

  script_name(english:"MS10-041: Vulnerability in Microsoft .NET Framework Could Allow Tampering (981343)");
  script_summary(english:"Checks version of System.Security.dll");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to tamper with signed XML content without being
detected on the remote web server.");
  script_set_attribute(attribute:"description", value:
"A data tampering vulnerability exists in the Microsoft .NET Framework
that could allow an attacker to tamper with signed XML content without
being detected.  In custom applications, the security impact depends
on the specific usage scenario.  Scenarios in which signed XML
messages are transmitted over a secure channel (such as SSL) are not
affected by this vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-041");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 3.0, 3.5,
and 4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS10-041';
kbs = make_list("979904", "979906", "979907", "979909", "979910", "979911", "979913", "979916", "982865");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 1.0
  hotfix_is_vulnerable(os:"5.1", file:"System.Security.dll", version:"1.0.3705.6074", min_version:"1.0.0.0", dir:"\Microsoft.NET\Framework\v1.0.3705", bulletin:bulletin, kb:'979904') ||

  # 1.1 SP1
  hotfix_is_vulnerable(os:"5.0", file:"System.Security.dll", version:"1.1.4322.2460", min_version:"1.1.0.0", dir:"\Microsoft.NET\Framework\v1.1.4322", bulletin:bulletin, kb:'979906') ||
  hotfix_is_vulnerable(os:"5.1", file:"System.Security.dll", version:"1.1.4322.2460", min_version:"1.1.0.0", dir:"\Microsoft.NET\Framework\v1.1.4322", bulletin:bulletin, kb:'979906') ||
  hotfix_is_vulnerable(os:"5.2", file:"System.Security.dll", version:"1.1.4322.2460", min_version:"1.1.0.0", dir:"\Microsoft.NET\Framework\v1.1.4322", arch:"x86", bulletin:bulletin, kb:'979907') ||
  hotfix_is_vulnerable(os:"5.2", file:"System.Security.dll", version:"1.1.4322.2463", min_version:"1.1.0.0", dir:"\Microsoft.NET\Framework\v1.1.4322", arch:"x64", bulletin:bulletin, kb:'979906') ||
  (hotfix_check_server_core() == 0 &&
  hotfix_is_vulnerable(os:"6.0", file:"System.Security.dll", version:"1.1.4322.2463", min_version:"1.1.0.0", dir:"\Microsoft.NET\Framework\v1.1.4322", bulletin:bulletin, kb:'979906')) ||

  # 3.5
  hotfix_is_vulnerable(os:"5.0", file:"System.Security.dll", version:"2.0.50727.1879", min_version:"2.0.0.1800", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'982865') ||
  hotfix_is_vulnerable(os:"5.1", file:"System.Security.dll", version:"2.0.50727.1879", min_version:"2.0.0.1800", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'982865') ||
  hotfix_is_vulnerable(os:"5.2", file:"System.Security.dll", version:"2.0.50727.1879", min_version:"2.0.0.1800", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'982865') ||
  (hotfix_check_server_core() == 0 &&
  hotfix_is_vulnerable(os:"6.0", file:"System.Security.dll", version:"2.0.50727.1878", min_version:"2.0.0.1800", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'982865')) ||

  # 3.5 SP1
  hotfix_is_vulnerable(os:"5.0", file:"System.Security.dll", version:"2.0.50727.3613", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'979909') ||
  hotfix_is_vulnerable(os:"5.0", file:"System.Security.dll", version:"2.0.50727.4434", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'979909') ||
  hotfix_is_vulnerable(os:"5.1", file:"System.Security.dll", version:"2.0.50727.3613", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'979909') ||
  hotfix_is_vulnerable(os:"5.1", file:"System.Security.dll", version:"2.0.50727.4434", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'979909') ||
  hotfix_is_vulnerable(os:"5.2", file:"System.Security.dll", version:"2.0.50727.3613", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'979909') ||
  hotfix_is_vulnerable(os:"5.2", file:"System.Security.dll", version:"2.0.50727.4434", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'979909') ||

  # (vista sp1)
  (hotfix_check_server_core() == 0 && (
  hotfix_is_vulnerable(os:"6.0", file:"System.Security.dll", version:"2.0.50727.3613", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'979911') ||
  # vista sp2
  hotfix_is_vulnerable(os:"6.0", file:"System.Security.dll", version:"2.0.50727.4204", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'979910') ||
  hotfix_is_vulnerable(os:"6.0", file:"System.Security.dll", version:"2.0.50727.4434", min_version:"2.0.50727.4400", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'979910'))) ||
  # win7
  hotfix_is_vulnerable(os:"6.1", file:"System.Security.dll", version:"2.0.50727.4951", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'979916') ||
  hotfix_is_vulnerable(os:"6.1", file:"System.Security.dll", version:"2.0.50727.5007", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727", bulletin:bulletin, kb:'979916')
)
{
  set_kb_item(name:"SMB/Missing/MS10-041", value:TRUE);
  hotfix_security_warning();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

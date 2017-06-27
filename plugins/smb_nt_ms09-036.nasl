#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40555);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id("CVE-2009-1536");
  script_bugtraq_id(35985);
  script_osvdb_id(56905);
  script_xref(name:"MSFT", value:"MS09-036");
  script_xref(name:"IAVB", value:"2009-B-0036");

  script_name(english:"MS09-036: Vulnerability in ASP.NET in Microsoft Windows Could Allow Denial of Service (970957)");
  script_summary(english:"Checks version of System.web.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote .Net Framework is susceptible to a denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the .NET Framework component of
Microsoft Windows that is suspectible to a denial of service attack due
to the way ASP.NET manages request scheduling.  Using specially crafted
anonymous HTTP requests, an anonymous, remote attacker can cause the web
server to become unresponsive until the associated application pool is
restarted.

Note that the vulnerable code in the .NET Framework is exposed only
through IIS 7.0 when operating in integrated mode.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-036");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 2.0 and
3.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS09-036';
kbs = make_list('972591', '972592');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (hotfix_check_iis_installed() <= 0) audit(AUDIT_NOT_INST, "IIS");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

path = rootfile + "\Microsoft.Net\Framework\v2.0.50727";

if (
  hotfix_check_fversion(path:path, file:"System.web.dll", version:"2.0.50727.4049", min_version:"2.0.50727.4000", bulletin:bulletin, kb:'972592') == HCF_OLDER ||
  hotfix_check_fversion(path:path, file:"System.web.dll", version:"2.0.50727.3601", min_version:"2.0.50727.3000", bulletin:bulletin, kb:'972592') == HCF_OLDER ||

  hotfix_check_fversion(path:path, file:"System.web.dll", version:"2.0.50727.1871", min_version:"2.0.50727.0", bulletin:bulletin, kb:'972591') == HCF_OLDER
)
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

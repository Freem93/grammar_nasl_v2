#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57275);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2011-1983");
  script_bugtraq_id(50956);
  script_osvdb_id(77659);
  script_xref(name:"MSFT", value:"MS11-089");

  script_name(english:"MS11-089: Vulnerability in Microsoft Office Could Allow Remote Code Execution (2590602)");
  script_summary(english:"Checks the version of Msptls.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Office."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Office installed on the remote host has a
use-after-free vulnerability.  A remote attacker could exploit this by
tricking a user into opening a specially crafted Word file, resulting
in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS11-089");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office 2007 SP2, 2007 SP3,
2010, and 2010 SP1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS11-089';
kbs = make_list('2589320', '2596785');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


office_vers = hotfix_check_office_version();
if (isnull(office_vers)) exit(0, "The host is not affected since Microsoft Office is not installed.");

common = hotfix_get_officecommonfilesdir();
if (!common) exit(1, 'hotfix_get_officecommonfilesdir() failed.');

share = hotfix_path2share(path:common);

vuln = 0;
# - Office 2010
if (office_vers["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && office_sp <= 1)
  {
    if (typeof(common) == 'array') dir = common['14.0'] + "\Microsoft Shared\Office14";
    else dir = common + "\Microsoft Shared\Office14";
    if (hotfix_is_vulnerable(path:dir, file:"Msptls.dll", version:"14.0.6112.5000", min_version:"14.0.0.0", bulletin:bulletin, kb:"2589320")) vuln++;
  }
}
# - Office 2007
if (office_vers["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && (office_sp == 2 || office_sp == 3))
  {
    if (typeof(common) == 'array') dir = common['12.0'] + "\Microsoft Shared\Office12";
    else dir = common + "\Microsoft Shared\Office12";
    if (hotfix_is_vulnerable(path:dir, file:"Msptls.dll", version:"12.0.6654.5000", min_version:"12.0.0.0", bulletin:bulletin, kb:"2596785")) vuln++;
  }
}
if (vuln)
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

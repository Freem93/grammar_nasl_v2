#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89747);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/14 17:43:16 $");

  script_cve_id(
    "CVE-2016-0102",
    "CVE-2016-0105",
    "CVE-2016-0109",
    "CVE-2016-0110",
    "CVE-2016-0111",
    "CVE-2016-0116",
    "CVE-2016-0123",
    "CVE-2016-0124",
    "CVE-2016-0125",
    "CVE-2016-0129",
    "CVE-2016-0130"
  );
  script_bugtraq_id(
    84018,
    84019,
    84020,
    84021,
    84022,
    84025,
    84029,
    84114,
    84115,
    84116,
    84117
  );
  script_osvdb_id(
    135507,
    135510,
    135514,
    135515,
    135516,
    135520,
    135521,
    135522,
    135523,
    135524,
    135525
  );
  script_xref(name:"MSFT", value:"MS16-024");

  script_name(english:"MS16-024: Cumulative Security Update for Microsoft Edge (3142019)");
  script_summary(english:"Checks the file version of edgehtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote host is missing
Cumulative Security Update 3142019. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. An attacker
    can exploit these vulnerabilities by convincing a user
    to visit a specially crafted website, resulting in
    execution of arbitrary code in the context of the
    current user. (CVE-2016-0102, CVE-2016-0105,
    CVE-2016-0109, CVE-2016-0110, CVE-2016-0111,
    CVE-2016-0116, CVE-2016-0123, CVE-2016-0124,
    CVE-2016-0129, CVE-2016-0130)

  - An information disclosure vulnerability exists due to
    improper handling of the referrer policy. An attacker
    can exploit this vulnerabilities by convincing a user
    to visit a specially crafted website, resulting in the
    disclosure of sensitive information about the request
    context or the browsing history of a user.
    (CVE-2016-0125)

Note that CVE-2016-0116, CVE-2016-0124, and CVE-2016-0129 do
not affect Windows 10, and they are only applicable to the
Windows Server versions.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-024");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS16-024';
kbs = make_list('3140745', '3140768');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# Server core is not affected
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
# Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10586.162", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3140768") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10240.16724", dir:"\system32", bulletin:bulletin, kb:"3140745")
)
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

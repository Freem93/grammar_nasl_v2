#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88643);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/14 17:43:16 $");

  script_cve_id(
    "CVE-2016-0060",
    "CVE-2016-0061",
    "CVE-2016-0062",
    "CVE-2016-0077",
    "CVE-2016-0080",
    "CVE-2016-0084"
  );
  script_bugtraq_id(
    82629,
    82653,
    82669,
    82671
  );
  script_osvdb_id(
    134293,
    134294,
    134295,
    134303,
    134304,
    134305
  );
  script_xref(name:"MSFT", value:"MS16-011");

  script_name(english:"MS16-011: Cumulative Security Update for Microsoft Edge (3134225)");
  script_summary(english:"Checks the file version of edgehtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote host is missing
Cumulative Security Update 3134225. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. An attacker
    can exploit these vulnerabilities by convincing a user
    to visit a specially crafted website, resulting in
    execution of arbitrary code in the context of the
    current user. (CVE-2016-0060, CVE-2016-0061,
    CVE-2016-0062, CVE-2016-0084)

  - A spoofing vulnerability exists due to improper parsing
    of HTTP responses. An unauthenticated, remote attacker
    can exploit this, via a specially crafted URL, to
    redirect a user to a malicious website. (CVE-2016-0077)

  - An information disclosure vulnerability exists due to
    improper handling of exceptions when dispatching certain
    window messages. An unauthenticated, remote attacker can
    exploit this, via a specially crafted website, to bypass
    the Address Space Layout Randomization (ASLR) feature,
    resulting in the ability to predict memory offsets in a
    call stack. (CVE-2016-0080)
");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-011");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

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

bulletin = 'MS16-011';
kbs = make_list('3135173', '3135174');

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
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10586.103", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3135173") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10240.16683", dir:"\system32", bulletin:bulletin, kb:"3135174")
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

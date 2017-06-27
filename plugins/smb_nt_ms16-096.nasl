#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92820);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/14 17:43:16 $");

  script_cve_id(
    "CVE-2016-3289",
    "CVE-2016-3293",
    "CVE-2016-3296",
    "CVE-2016-3319",
    "CVE-2016-3322",
    "CVE-2016-3326",
    "CVE-2016-3327",
    "CVE-2016-3329"
  );
  script_bugtraq_id(
    92282,
    92283,
    92284,
    92285,
    92286,
    92287,
    92293,
    92305
  );
  script_osvdb_id(
    142720,
    142721,
    142722,
    142723,
    142724,
    142725,
    142730,
    142731
  );
  script_xref(name:"MSFT", value:"MS16-096");

  script_name(english:"MS16-096: Cumulative Security Update for Microsoft Edge (3177358)");
  script_summary(english:"Checks the file version of edgehtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is
missing Cumulative Security Update 3177358. It is, therefore, affected
by multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to a failure to properly access objects in memory. A
    remote attacker can exploit these vulnerabilities by
    convincing a user to visit a specially crafted website,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2016-3289,
    CVE-2016-3293, CVE-2016-3319, CVE-2016-3322)

  - A remote code execution vulnerability exists in the
    Chakra JavaScript engine due to improper handling of
    objects in memory. A remote attacker can exploit this
    vulnerability by convincing a user to visit a specially
    crafted website or open a specially crafted Office
    document, resulting in the execution of arbitrary code
    in the context of the current user. (CVE-2016-3296)

  - Multiple information disclosure vulnerabilities exist
    due to improper handling of objects in  memory. A remote
    attacker can exploit these vulnerabilities by convincing
    a user to visit a specially crafted website, resulting
    in the disclosure of sensitive information.
    (CVE-2016-3326, CVE-2016-3327)

  - An information disclosure vulnerability exists due to
    improper handling of page content. A remote attacker can
    exploit this vulnerability by convincing a user to visit
    a specially crafted website, resulting in the disclosure
    of specific files on a user's system. (CVE-2016-3329)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-096");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/09");

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

bulletin = 'MS16-096';
kbs = make_list('3176492', '3176493', '3176495');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

# Server core is not affected
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.14393.51", os_build:"14393", dir:"\system32", bulletin:bulletin, kb:"3176495") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10586.545", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3176493") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10240.17071", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3176492")
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

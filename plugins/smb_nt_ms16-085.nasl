#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92016);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/14 17:43:16 $");

  script_cve_id(
    "CVE-2016-3244",
    "CVE-2016-3246",
    "CVE-2016-3248",
    "CVE-2016-3259",
    "CVE-2016-3260",
    "CVE-2016-3264",
    "CVE-2016-3265",
    "CVE-2016-3269",
    "CVE-2016-3271",
    "CVE-2016-3273",
    "CVE-2016-3274",
    "CVE-2016-3276",
    "CVE-2016-3277"
  );
  script_bugtraq_id(
    91573,
    91576,
    91578,
    91580,
    91581,
    91586,
    91591,
    91593,
    91595,
    91596,
    91598,
    91599,
    91602
  );
  script_osvdb_id(
    141389,
    141390,
    141391,
    141393,
    141394,
    141395,
    141396,
    141397,
    141398,
    141399,
    141400,
    141401,
    141402
  );
  script_xref(name:"MSFT", value:"MS16-085");

  script_name(english:"MS16-085: Cumulative Security Update for Microsoft Edge (3169999)");
  script_summary(english:"Checks the file version of edgehtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is
missing Cumulative Security Update 3169999. It is, therefore, affected
by multiple vulnerabilities :

  - A security feature bypass vulnerability exists due to a
    failure to properly implement Address Space Layout
    Randomization (ASLR). An unauthenticated, remote
    attacker can exploit this, by convincing a user to visit
    a website that hosts crafted content, to bypass the ASLR
    security feature, resulting in the ability to predict
    memory offsets in a call stack. (CVE-2016-3244)

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit these, via a
    crafted website or email, to corrupt memory, resulting in
    the execution of arbitrary code within the context of the
    current user. (CVE-2016-3246, CVE-2016-3264)

  - Multiple remote code execution vulnerabilities exist in
    the Chakra JavaScript engine due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit these, by convincing a user to visit a
    specially crafted website or open a specially crafted
    Microsoft Office document that hosts the Edge rendering
    engine, to corrupt memory, resulting in the execution of
    arbitrary code within the context of the current user.
    (CVE-2016-3248, CVE-2016-3259, CVE-2016-3260,
    CVE-2016-3265, CVE-2016-3269)

  - An information disclosure vulnerability exists in
    VBScript due to improper disclosure of the contents of
    its memory. An unauthenticated, remote attacker who has
    knowledge of the memory address where an object was
    created can exploit this issue to disclose potentially
    sensitive information. (CVE-2016-3271)

  - An information disclosure vulnerability exists in the
    Microsoft Browser XSS Filter due to improper validation
    of content. An unauthenticated, remote attacker can
    exploit this, via a website that hosts content with
    specially crafted JavaScript, to disclose potentially
    sensitive information. (CVE-2016-3273)

  - Multiple spoofing vulnerabilities exist due to improper
    parsing of HTTP or HTML content. An unauthenticated,
    remote attacker can exploit these to redirect a user
    to a malicious website having spoofed contents.
    (CVE-2016-3274, CVE-2016-3276)

  - An unspecified information disclosure vulnerability
    exists due to improper handling of objects in memory
    that allows an unauthenticated, remote attacker to
    disclose potentially sensitive information.
    (CVE-2016-3277)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-085");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");

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

bulletin = 'MS16-085';
kbs = make_list('3172985', '3163912');

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
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10586.494", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3172985") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"edgehtml.dll", version:"11.0.10240.17024", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3163912")
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

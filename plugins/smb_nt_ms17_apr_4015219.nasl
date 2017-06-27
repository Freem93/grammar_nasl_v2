#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99282);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_cve_id(
    "CVE-2013-6629",
    "CVE-2017-0058",
    "CVE-2017-0093",
    "CVE-2017-0156",
    "CVE-2017-0158",
    "CVE-2017-0160",
    "CVE-2017-0162",
    "CVE-2017-0163",
    "CVE-2017-0165",
    "CVE-2017-0166",
    "CVE-2017-0167",
    "CVE-2017-0178",
    "CVE-2017-0179",
    "CVE-2017-0180",
    "CVE-2017-0181",
    "CVE-2017-0182",
    "CVE-2017-0183",
    "CVE-2017-0184",
    "CVE-2017-0185",
    "CVE-2017-0186",
    "CVE-2017-0188",
    "CVE-2017-0189",
    "CVE-2017-0191",
    "CVE-2017-0192",
    "CVE-2017-0202",
    "CVE-2017-0203",
    "CVE-2017-0205",
    "CVE-2017-0208",
    "CVE-2017-0210",
    "CVE-2017-0211"
  );
  script_bugtraq_id(
    63676,
    97416,
    97419,
    97420,
    97426,
    97427,
    97428,
    97435,
    97437,
    97438,
    97441,
    97442,
    97443,
    97444,
    97445,
    97446,
    97447,
    97452,
    97455,
    97460,
    97461,
    97462,
    97465,
    97466,
    97467,
    97473,
    97475,
    97507,
    97512,
    97514
  );
  script_osvdb_id(
    99711,
    155335,
    155338,
    155339,
    155341,
    155342,
    155343,
    155345,
    155346,
    155347,
    155350,
    155351,
    155352,
    155353,
    155354,
    155355,
    155356,
    155362,
    155365,
    155368,
    155369,
    155370,
    155371,
    155372,
    155373,
    155374,
    155375,
    155376,
    155377,
    155378
  );
  script_xref(name:"MSKB", value:"4015219");
  script_xref(name:"IAVA", value:"2017-A-0110");
  script_xref(name:"IAVA", value:"2017-A-0111");

  script_name(english:"KB4015219: Windows 10 Version 1511 April 2017 Cumulative Update");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows 10 version 1511 host is missing security update
KB4015219. It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    open-source libjpeg image processing library due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive information that can be utilized to
    bypass ASLR security protections. (CVE-2013-6629)

  - Multiple information disclosure vulnerabilities exist in
    the win32k component due to improper handling of kernel
    information. A local attacker can exploit these
    vulnerabilities, via a specially crafted application, to
    disclose sensitive information. (CVE-2017-0058,
    CVE-2017-0188)

  - A remote code execution vulnerability exists in
    Microsoft Edge due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, by convincing a user to visit a
    malicious website, to execute arbitrary code.
    (CVE-2017-0093)

  - A privilege escalation vulnerability exists in the
    Microsoft Graphics Component due to improper handling of
    objects in memory. A local attacker can exploit this,
    via a specially crafted application, to execute
    arbitrary code with elevated privileges. (CVE-2017-0156)

  - A flaw exists in the VBScript engine due to improper
    handling of objects in memory. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a malicious website or open a specially crafted
    document file, to execute arbitrary code.
    (CVE-2017-0158)

  - A privilege escalation vulnerability exists in the
    Microsoft .NET framework due to improper validation of
    input when loading libraries. A local attacker can
    exploit this to gain elevated privileges.
    (CVE-2017-0160)

  - Multiple flaws exist in Windows Hyper-V Network Switch
    due to improper validation of input from the guest
    operating system. A local attacker can exploit these,
    via a specially crafted application on the guest, to
    execute arbitrary code on the host system.
    (CVE-2017-0162, CVE-2017-0163, CVE-2017-0180,
    CVE-2017-0181)

  - A privilege escalation vulnerability exists due to
    improper sanitization of handles stored in memory. A
    local attacker can exploit this to gain elevated
    privileges. (CVE-2017-0165)

  - A flaw exists in LDAP due to buffer request lengths not
    being properly calculated. An unauthenticated, remote
    attacker can exploit this, via specially crafted traffic
    sent to a Domain Controller, to run processes with
    elevated privileges. (CVE-2017-0166)

  - A flaw exists in the Windows kernel due to improper
    handling of objects in memory. A local attacker can
    exploit this, via a specially crafted application, to
    disclose sensitive information. (CVE-2017-0167)

  - Multiple denial of service vulnerabilities exist in
    Hyper-V due to improper validation of input from a
    privileged user on a guest operating system. A local
    attacker on the guest can exploit these, via a specially
    crafted application, to cause the host system to crash.
    (CVE-2017-0178, CVE-2017-0179, CVE-2017-0184)

  - Multiple denial of service vulnerabilities exist in
    Windows Hyper-V Network Switch due to improper
    validation of input from the guest operating system. A
    local attacker on the guest can exploit these
    vulnerabilities, via a specially crafted application, to
    crash the host system. (CVE-2017-0182, CVE-2017-0183,
    CVE-2017-0185, CVE-2017-0186)

  - A privilege escalation vulnerability exists in the
    Windows kernel-mode driver due to improper handling of
    objects in memory. A local attacker can exploit this,
    via a specially crafted application, to execute
    arbitrary code in kernel mode. (CVE-2017-0189)

  - A flaw exists in Windows due to improper handling of
    objects in memory that allows an attacker to cause a
    denial of service condition. (CVE-2017-0191)

  - An information disclosure vulnerability exists in the
    Adobe Type Manager Font Driver (ATMFD.dll) due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted document
    or visit a malicious web page, to disclose sensitive
    information. (CVE-2017-0192)

  - A memory corruption issue exists in Internet Explorer
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a malicious website, to
    execute arbitrary code. (CVE-2017-0202)

  - A security feature bypass vulnerability exists in
    Microsoft Edge due to improper handling of CSP
    documents. An unauthenticated, remote attacker can
    exploit this, via a specially crafted CSP document, to
    bypass security features. (CVE-2017-0203)

  - A memory corruption issue exists in Microsoft Edge due
    to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a malicious website, to
    execute arbitrary code. (CVE-2017-0205)

  - An information disclosure vulnerability exists in
    Microsoft Edge in the Chakra scripting engine due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive information. (CVE-2017-0208)

  - A privilege escalation vulnerability exists in Internet
    Explorer due to a failure to properly enforce
    cross-domain policies. An unauthenticated, remote
    attacker can exploit this to inject arbitrary content
    and gain elevated privileges. (CVE-2017-0210)

  - A privilege escalation vulnerability exists in Microsoft
    Windows OLE due to an unspecified failure in
    integrity-level checks. An authenticated, remote
    attacker can exploit this to run an application with
    limited privileges at a medium integrity level. Note
    that this vulnerability by itself does not allow
    arbitrary code execution but can be used in conjunction
    other vulnerabilities. (CVE-2017-0211)");
  # https://support.microsoft.com/en-us/help/4015219/windows-10-update-kb4015219
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?381f5d88");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4015219.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS17-04';
kbs = make_list('4015219');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 10 (1511)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10586",
                   rollup_date: "04_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4015219))
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}

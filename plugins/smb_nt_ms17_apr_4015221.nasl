#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99287);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_cve_id(
    "CVE-2013-6629",
    "CVE-2017-0058",
    "CVE-2017-0156",
    "CVE-2017-0158",
    "CVE-2017-0160",
    "CVE-2017-0162",
    "CVE-2017-0163",
    "CVE-2017-0165",
    "CVE-2017-0166",
    "CVE-2017-0167"
  );
  script_bugtraq_id(
    63676,
    97446,
    97447,
    97455,
    97461,
    97462,
    97465,
    97467,
    97473,
    97507
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
    155347
  );
  script_xref(name:"MSKB", value:"4015221");

  script_name(english:"KB4015221: Windows 10 Version 1507 April 2017 Cumulative Update");
  script_summary(english:"Checks for rollup.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows 10 Version 1507 host is missing security update
KB4015221. It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    open-source libjpeg image processing library due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive information that can be utilized to
    bypass ASLR security protections. (CVE-2013-6629)

  - An information disclosure vulnerability exists in the
    win32k component due to improper handling of kernel
    information. A local attacker can exploit these
    vulnerabilities, via a specially crafted application, to
    disclose sensitive information. (CVE-2017-0058)

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
    (CVE-2017-0162, CVE-2017-0163)

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
    disclose sensitive information. (CVE-2017-0167)");
  # https://support.microsoft.com/en-us/help/4015221/windows-10-update-kb4015221
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9fef1d2");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4015221.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Windows : Microsoft Bulletins");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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
kbs = make_list('4015221');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("2016" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (
  # 10 (1507)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date: "04_2017",
                   bulletin:bulletin,
                   rollup_kb_list:kbs)
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

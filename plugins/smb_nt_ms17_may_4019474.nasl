#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100061);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_cve_id(
   "CVE-2017-0064",
   "CVE-2017-0077",
   "CVE-2017-0190",
   "CVE-2017-0212",
   "CVE-2017-0213",
   "CVE-2017-0214",
   "CVE-2017-0222",
   "CVE-2017-0226",
   "CVE-2017-0227",
   "CVE-2017-0228",
   "CVE-2017-0229",
   "CVE-2017-0231",
   "CVE-2017-0233",
   "CVE-2017-0234",
   "CVE-2017-0236",
   "CVE-2017-0238",
   "CVE-2017-0240",
   "CVE-2017-0241",
   "CVE-2017-0246",
   "CVE-2017-0248",
   "CVE-2017-0258",
   "CVE-2017-0259",
   "CVE-2017-0263",
   "CVE-2017-0267",
   "CVE-2017-0268",
   "CVE-2017-0269",
   "CVE-2017-0270",
   "CVE-2017-0271",
   "CVE-2017-0272",
   "CVE-2017-0273",
   "CVE-2017-0274",
   "CVE-2017-0275",
   "CVE-2017-0276",
   "CVE-2017-0277",
   "CVE-2017-0278",
   "CVE-2017-0279",
   "CVE-2017-0280"
 );
  script_bugtraq_id(
    98099,
    98102,
    98103,
    98108,
    98112,
    98113,
    98114,
    98117,
    98121,
    98127,
    98139,
    98164,
    98173,
    98179,
    98203,
    98208,
    98217,
    98229,
    98234,
    98237,
    98258,
    98259,
    98260,
    98261,
    98263,
    98264,
    98265,
    98266,
    98267,
    98268,
    98270,
    98271,
    98272,
    98273,
    98274,
    98281,
    98298
  );
  script_osvdb_id(
    157225,
    157226,
    157229,
    157230,
    157231,
    157232,
    157233,
    157234,
    157235,
    157236,
    157237,
    157238,
    157239,
    157240,
    157241,
    157242,
    157243,
    157246,
    157247,
    157248,
    157252,
    157257,
    157259,
    157260,
    157261,
    157263,
    157265,
    157266,
    157267,
    157269,
    157271,
    157272,
    157273,
    157274,
    157275,
    157276,
    157277
  );
  script_xref(name:"MSKB", value:"4019474");
  script_xref(name:"IAVA", value:"2017-A-0141");
  script_xref(name:"IAVA", value:"2017-A-0142");
  script_xref(name:"IAVA", value:"2017-A-0146");
  script_xref(name:"IAVA", value:"2017-A-0147");
  script_xref(name:"IAVA", value:"2017-A-0148");

  script_name(english:"KB4019474: Windows 10 Version 1507 May 2017 Cumulative Update");
  script_summary(english:"Checks for rollup.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows 10 version 1507 host is missing security update
KB4019474. It is, therefore, affected by multiple vulnerabilities :

  - A security bypass vulnerability exists in Internet
    Explorer due to an unspecified flaw. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a specially crafted website, to bypass mixed
    content warnings and load insecure content (HTTP) from
    secure locations (HTTPS). (CVE-2017-0064)

  - An elevation of privilege vulnerability exists in
    Windows in the Microsoft DirectX graphics kernel
    subsystem (dxgkrnl.sys) due to improper handling of
    objects in memory. A local attacker can exploit this,
    via a specially crafted application, to execute
    arbitrary code in an elevated context. (CVE-2017-0077)

  - An information disclosure vulnerability exists in the
    Windows Graphics Device Interface (GDI) due to improper
    handling of objects in memory. A local attacker can
    exploit this, via a specially crafted application, to
    disclose sensitive information. (CVE-2017-0190)

  - An elevation of privilege vulnerability exists in
    Windows Hyper-V due to improper validation of vSMB
    packet data. An unauthenticated, adjacent attacker can
    exploit this to gain elevated privileges.
    (CVE-2017-0212)

  - An elevation of privilege vulnerability exists in the
    Windows COM Aggregate Marshaler due to an unspecified
    flaw. A local attacker can exploit this, via a specially
    crafted application, to execute arbitrary code with
    elevated privileges. (CVE-2017-0213)

  - An elevation of privilege vulnerability exists in
    Windows due to improper validation of user-supplied
    input when loading type libraries. A local attacker can
    exploit this, via a specially crafted application, to
    gain elevated privileges. (CVE-2017-0214)

  - A remote code execution vulnerability exists in
    Microsoft Internet Explorer due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, by convincing a user to visit a
    specially crafted website, to execute arbitrary code in
    the context of the current user. (CVE-2017-0222)

  - A remote code execution vulnerability exists in
    Microsoft Internet Explorer due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, by convincing a user to visit a
    specially crafted website, to execute arbitrary code in
    the context of the current user. (CVE-2017-0226)

  - A remote code execution vulnerability exists in
    Microsoft Edge in the scripting engines due to improper
    handling of objects in memory. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a specially crafted website or open a specially
    crafted Microsoft Office document, to execute arbitrary
    code in the context of the current user. (CVE-2017-0227)

  - A remote code execution vulnerability exists in
    Microsoft browsers in the JavaScript engines due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website
    or open a specially crafted Microsoft Office document,
    to execute arbitrary code in the context of the current
    user. (CVE-2017-0228)

  - A remote code execution vulnerability exists in
    Microsoft browsers in the JavaScript engines due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website
    or open a specially crafted Microsoft Office document,
    to execute arbitrary code in the context of the current
    user. (CVE-2017-0229)

  - A spoofing vulnerability exists in Microsoft browsers
    due to improper rendering of the SmartScreen filter. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted URL, to redirect users to a malicious
    website that appears to be a legitimate website.
    (CVE-2017-0231)

  - An elevation of privilege vulnerability exists in
    Microsoft Edge due to improper sandboxing. An
    unauthenticated, remote attacker can exploit this to
    break out of the Edge AppContainer sandbox and gain
    elevated privileges. (CVE-2017-0233)

  - A remote code execution vulnerability exists in
    Microsoft Edge in the Chakra JavaScript engine due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website
    or open a specially crafted Microsoft Office document,
    to execute arbitrary code in the context of the current
    user. (CVE-2017-0234)

  - A remote code execution vulnerability exists in
    Microsoft Edge in the Chakra JavaScript engine due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website
    or open a specially crafted Office document, to
    execute arbitrary code in the context of the current
    user. (CVE-2017-0236)

  - A remote code execution vulnerability exists in
    Microsoft browsers in the JavaScript scripting engines
    due to improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website
    or open a specially crafted Office document, to
    execute arbitrary code in the context of the current
    user. (CVE-2017-0238)

  - A remote code execution vulnerability exists in
    Microsoft Edge in the scripting engines due to improper
    handling of objects in memory. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a specially crafted website or to open a
    specially crafted Office document, to execute arbitrary
    code in the context of the current user. (CVE-2017-0240)

  - An elevation of privilege vulnerability exists in
    Microsoft Edge due to improper rendering of a
    domain-less page in the URL. An unauthenticated, remote
    attacker can exploit this, by convincing a user to visit
    a specially crafted website, to cause the user to
    perform actions in the context of the Intranet Zone and
    access functionality that is not typically available to
    the browser when browsing in the context of the Internet
    Zone. (CVE-2017-0241)

  - An elevation of privilege vulnerability exists in the
    win32k component due to improper handling of objects in
    memory. A local attacker can exploit this, via a
    specially crafted application, to execute arbitrary code
    with elevated permissions. Note that an attacker can
    also cause a denial of service condition on Windows 7
    x64 or later systems. (CVE-2017-0246)

  - A security bypass vulnerability exists in the Microsoft
    .NET Framework and .NET Core components due to a failure
    to completely validate certificates. An attacker can
    exploit this to present a certificate that is marked
    invalid for a specific use, but the component uses it
    for that purpose, resulting in a bypass of the Enhanced
    Key Usage taggings. (CVE-2017-0248)

  - An information disclosure vulnerability exists in the
    Windows kernel due to improper initialization of objects
    in memory. A local attacker can exploit this, via a
    specially crafted application, to disclose sensitive
    information. (CVE-2017-0258)

  - An information disclosure vulnerability exists in the
    Windows kernel due to improper initialization of objects
    in memory. A local attacker can exploit this, via a
    specially crafted application, to disclose sensitive
    information. (CVE-2017-0259)

  - An elevation of privilege vulnerability exists in the
    Windows kernel-mode driver due to improper handling of
    objects in memory. A local attacker can exploit this,
    via a specially crafted application, to run arbitrary
    code in kernel mode. (CVE-2017-0263)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0267)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0268)

  - A denial of service vulnerability exists in Microsoft
    Server Message Block (SMB) when handling a specially
    crafted request to the server. An unauthenticated,
    remote attacker can exploit this, via a crafted SMB
    request, to cause the system to stop responding.
    (CVE-2017-0269)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0270)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0271)

  - A remote code execution vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to execute arbitrary code on a target server.
    (CVE-2017-0272)

  - A denial of service vulnerability exists in Microsoft
    Server Message Block (SMB) when handling a specially
    crafted request to the server. An unauthenticated,
    remote attacker can exploit this, via a crafted SMB
    request, to cause the system to stop responding.
    (CVE-2017-0273)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0274)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0275)

  - An information disclosure vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to disclose sensitive information.
    (CVE-2017-0276)

  - A remote code execution vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to execute arbitrary code on a target server.
    (CVE-2017-0277)

  - A remote code execution vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to execute arbitrary code on a target server.
    (CVE-2017-0278)

  - A remote code execution vulnerability exists in the
    Microsoft Server Message Block 1.0 (SMBv1) server when
    handling certain requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    packet, to execute arbitrary code on a target server.
    (CVE-2017-0279)

  - A denial of service vulnerability exists in Microsoft
    Server Message Block (SMB) when handling a specially
    crafted request to the server. An unauthenticated,
    remote attacker can exploit this, via a crafted SMB
    request, to cause the system to stop responding.
    (CVE-2017-0280) ");
  # https://support.microsoft.com/en-us/help/4019474/windows-10-update-kb4019474
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01ec841b");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4019474.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS17-05';
kbs = make_list(
  '4019474' # 10 1507
);

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
                   rollup_date: "05_2017",
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

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100054);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_cve_id(
    "CVE-2017-0213",
    "CVE-2017-0214",
    "CVE-2017-0220",
    "CVE-2017-0222",
    "CVE-2017-0226",
    "CVE-2017-0238",
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
    98102,
    98103,
    98111,
    98127,
    98139,
    98237,
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
    98274
  );
  script_osvdb_id(
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
    157242,
    157243,
    157244,
    157246,
    157247,
    157248,
    157257,
    157259,
    157274
  );
  script_xref(name:"MSKB", value:"4019214");
  script_xref(name:"IAVA", value:"2017-A-0141");
  script_xref(name:"IAVA", value:"2017-A-0147");
  script_xref(name:"IAVA", value:"2017-A-0148");
  script_xref(name:"MSKB", value:"4019216");

  script_name(english:"KB4019214: Windows Server 2012 Standard May 2017 Cumulative Update");
  script_summary(english:"Checks the version of Quartz.dll or the installed rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update KB4019214. It is,
therefore, affected by the following vulnerabilities :

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

  - An information disclosure vulnerability exists in the
    Windows kernel due to improper handling of objects in
    memory. A local attacker can exploit this, via a
    specially crafted application, to disclose sensitive
    information. (CVE-2017-0220)

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
    Microsoft browsers in the JavaScript scripting engines
    due to improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website
    or open a specially crafted Office document, to
    execute arbitrary code in the context of the current
    user. (CVE-2017-0238)

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
    (CVE-2017-0280)");
  # https://support.microsoft.com/en-us/help/4019214/windows-server-2012-update-kb4019214
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ae1f0e3");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4019214.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/09");

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

bulletin = 'MS17-05';
kbs = make_list(
  '4019214', # 2012 Monthly Rollup
  '4019216'  # 2012 Security Rollup
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( smb_check_rollup(os:"6.2", sp:0, rollup_date: "05_2017", bulletin:bulletin, rollup_kb_list:[4019214,4019216]) )
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

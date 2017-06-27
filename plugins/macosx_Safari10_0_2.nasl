#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95919);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/13 17:57:45 $");

  script_cve_id(
    "CVE-2016-4692",
    "CVE-2016-4743",
    "CVE-2016-7586",
    "CVE-2016-7587",
    "CVE-2016-7589",
    "CVE-2016-7592",
    "CVE-2016-7598",
    "CVE-2016-7599",
    "CVE-2016-7610",
    "CVE-2016-7611",
    "CVE-2016-7623",
    "CVE-2016-7632",
    "CVE-2016-7635",
    "CVE-2016-7639",
    "CVE-2016-7640",
    "CVE-2016-7641",
    "CVE-2016-7642",
    "CVE-2016-7645",
    "CVE-2016-7646",
    "CVE-2016-7648",
    "CVE-2016-7649",
    "CVE-2016-7650",
    "CVE-2016-7652",
    "CVE-2016-7654",
    "CVE-2016-7656"
  );
  script_bugtraq_id(
    94907,
    94908,
    94909,
    94913,
    94915
  );
  script_osvdb_id(
    148669,
    148670,
    148671,
    148672,
    148673,
    148674,
    148675,
    148676,
    148677,
    148678,
    148679,
    148680,
    148681,
    148682,
    148683,
    148684,
    148685,
    148686,
    148687,
    148688,
    148689,
    148690,
    148691,
    148692
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-12-13-2");

  script_name(english:"macOS : Apple Safari < 10.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote macOS or Mac OS X 
host is prior to 10.0.2. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple remote code execution vulnerabilities exist in
    WebKit due to improper validation of user-supplied
    input and improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit these
    vulnerabilities, by convincing a user to visit a
    specially crafted website, to corrupt memory and execute
    arbitrary code. (CVE-2016-4692, CVE-2016-7635,
    CVE-2016-7652)

  - Multiple information disclosure vulnerabilities exist
    in WebKit due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    these, by convincing a user to visit a specially crafted
    website, to disclose memory contents. (CVE-2016-4743,
    CVE-2016-7656)

  - An information disclosure vulnerability exists in WebKit
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to disclose user information. (CVE-2016-7586)

  - Multiple remote code execution vulnerabilities exist in
    WebKit due to improper validation of user-supplied
    input and improper state management. An unauthenticated,
    remote attacker can exploit these vulnerabilities, by
    convincing a user to visit a specially crafted website,
    to corrupt memory and execute arbitrary code.
    (CVE-2016-7587, CVE-2016-7589:, CVE-2016-7610,
    CVE-2016-7611, CVE-2016-7639, CVE-2016-7640,
    CVE-2016-7641, CVE-2016-7642, CVE-2016-7645,
    CVE-2016-7646, CVE-2016-7648, CVE-2016-7649,
    CVE-2016-7654)

  - An information disclosure vulnerability exists in WebKit
    due to improper handling of JavaScript prompts. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to corrupt memory and execute arbitrary code.
    (CVE-2016-7592)

  - An information disclosure vulnerability exists in WebKit
    due to the use of uninitialized memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to disclose memory contents. (CVE-2016-7598)

  - An information disclosure vulnerability exists that is
    triggered when handling HTTP redirections. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted website,
    to disclose user information. (CVE-2016-7599)

  - An information disclosure vulnerability exists in WebKit
    due to improper validation of user-supplied input and
    blob URLs. An unauthenticated, remote attacker can
    exploit this, via a specially crafted blob URL, to
    disclose user information. (CVE-2016-7623)

  - A remote code execution vulnerability exists in WebKit
    due to improper validation of user-supplied
    input and improper state management. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a specially crafted website, to cause a denial
    of service condition or the execution of arbitrary code.
    (CVE-2016-7632)

  - A cross-site scripting (XSS) vulnerability exists in
    Safari Reader due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, by convincing a user to follow a
    specially crafted link, to execute arbitrary script code
    in a user's browser session. (CVE-2016-7650)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207421");
  # https://lists.apple.com/archives/security-announce/2016/Dec/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df6b83c6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 10.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
vcf::apple::check_macos_restrictions(restrictions:['10.10', '10.11', '10.12']);

app_info = vcf::apple::get_safari_info();
constraints = [{ "fixed_version" : "10.0.2" }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{"xss":TRUE});

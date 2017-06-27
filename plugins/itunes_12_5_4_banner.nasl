#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95825);
  script_version("$Revision: 1.5 $");
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
    "CVE-2016-7652",
    "CVE-2016-7654",
    "CVE-2016-7656"
  );
  script_bugtraq_id(
    94907,
    94908,
    94909
  );
  script_osvdb_id(
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
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-12-13-3");

  script_name(english:"Apple iTunes < 12.5.4 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes running on the remote host is prior to
12.5.4 It is, therefore, affected by multiple vulnerabilities :

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

  - A remote code execution vulnerability exists in WebKit
    due to improper validation of user-supplied
    input and improper state management. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a specially crafted website, to cause a denial
    of service condition or the execution of arbitrary code.
    (CVE-2016-7632)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207427");
  # http://lists.apple.com/archives/security-announce/2016/Dec/msg00005.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbeabf43");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("iTunes/sharing");
  script_require_ports("Services/www", 3689);

  exit(0);
}

include("vcf.inc");
include("http.inc");

port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);
get_kb_item_or_exit("iTunes/" + port + "/enabled");

if (get_kb_item_or_exit("iTunes/" + port + "/type") != 'Windows')
  audit(AUDIT_OS_NOT, "Windows");

kb_base = "iTunes/"+port+"/";
app_info = vcf::get_app_info(app:"iTunes", port:port, kb_ver:kb_base+"version", kb_source:kb_base+"source", service:TRUE);

constraints = [{ "fixed_version" : "12.5.4" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

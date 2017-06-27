#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94914);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id(
    "CVE-2016-4728",
    "CVE-2016-4758",
    "CVE-2016-4759",
    "CVE-2016-4760",
    "CVE-2016-4762",
    "CVE-2016-4763",
    "CVE-2016-4764",
    "CVE-2016-4765",
    "CVE-2016-4766",
    "CVE-2016-4767",
    "CVE-2016-4768",
    "CVE-2016-4769"
  );
  script_bugtraq_id(
    93062,
    93064,
    93066,
    93067
  );
  script_osvdb_id(
    144532,
    144533,
    144534,
    144535,
    144536,
    144537,
    144547,
    144598,
    144599,
    144600,
    144601,
    146845
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-09-20-7");

  script_name(english:"Apple iTunes < 12.5.1 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.5.1. It is, therefore, affected by multiple
vulnerabilities :

  - A remote code execution vulnerability exists due to
    improper handling of error prototypes. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a maliciously crafted
    website, to execute arbitrary code. (CVE-2016-4728)

  - An information disclosure vulnerability exists in WebKit
    due to a permission issue caused by improper handling of
    the location variable. An unauthenticated, remote
    attacker can exploit this, by convincing a user to visit
    a maliciously crafted website, to disclose sensitive
    information. (CVE-2016-4758)

  - Multiple memory corruption errors exist in WebKit due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these
    issues, by convincing a user to visit a maliciously
    crafted website, to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-4759,
    CVE-2016-4762, CVE-2016-4764, CVE-2016-4765,
    CVE-2016-4766, CVE-2016-4767, CVE-2016-4768,
    CVE-2016-4769)

  - A rebinding flaw exists in WebKit due to a failure to
    restrict HTTP/0.9 responses to default ports and
    cancel resource loads if a document is loaded with a 
    different HTTP protocol version. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a maliciously crafted website, to access
    non-HTTP services. (CVE-2016-4760)

  - A security bypass vulnerability exists in WebKit in the
    WKWebView component due to a failure to properly verify
    X.509 certificates from HTTPS servers. A
    man-in-the-middle attacker can exploit this, via a
    specially crafted certificate, to spoof servers and
    disclose or manipulate network traffic. (CVE-2016-4763)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207158");
  # http://lists.apple.com/archives/security-announce/2016/Sep/msg00012.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fe85f7b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Ensure this is Windows
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_id = 'iTunes Version';
install = get_single_install(app_name:app_id, exit_if_unknown_ver:TRUE);

version = install["version"];
path = install["path"];

fixed_version = "12.5.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  order = make_list('Version source', 'Installed version', 'Fixed version');
  report = make_array(
    order[0], path,
    order[1], version,
    order[2], fixed_version
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "iTunes", version, path);

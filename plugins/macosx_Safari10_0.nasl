#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93721);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2016-4611",
    "CVE-2016-4618",
    "CVE-2016-4728",
    "CVE-2016-4729",
    "CVE-2016-4730",
    "CVE-2016-4731",
    "CVE-2016-4733",
    "CVE-2016-4734",
    "CVE-2016-4735",
    "CVE-2016-4737",
    "CVE-2016-4751",
    "CVE-2016-4758",
    "CVE-2016-4759",
    "CVE-2016-4760",
    "CVE-2016-4762",
    "CVE-2016-4763",
    "CVE-2016-4765",
    "CVE-2016-4766",
    "CVE-2016-4767",
    "CVE-2016-4768",
    "CVE-2016-4769"
  );
  script_bugtraq_id(
    93053,
    93057,
    93058,
    93062,
    93064,
    93065,
    93066,
    93067
  );
  script_osvdb_id(
    144527,
    144528,
    144529,
    144530,
    144531,
    144532,
    144533,
    144534,
    144535,
    144536,
    144537,
    144538,
    144539,
    144546,
    144547,
    144596,
    144597,
    144598,
    144599,
    144600,
    144601
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-09-20-2");

  script_name(english:"Mac OS X : Apple Safari < 10.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X or macOS
host is prior to 10.0. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption issues exist in WebKit that
    allow an unauthenticated, remote attacker to cause a
    denial of service condition or execute arbitrary code
    via specially a crafted website. (CVE-2016-4611,
    CVE-2016-4729, CVE-2016-4730, CVE-2016-4731,
    CVE-2016-4734, CVE-2016-4735, CVE-2016-4737,
    CVE-2016-4759, CVE-2016-4762, CVE-2016-4766,
    CVE-2016-4767, CVE-2016-4768, CVE-2016-4769)

  - A cross-site scripting (XSS) vulnerability exists in the
    Reader feature due to improper validation of
    user-supplied input before returning it to users. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to follow a specially crafted link, to
    execute arbitrary script code in a user's browser
    session. (CVE-2016-4618)

  - A flaw exists in WebKit due to improper handling of
    error prototypes. An unauthenticated, remote attacker
    can exploit this, via a specially crafted website, to
    execute arbitrary code. (CVE-2016-4728)

  - Multiple flaws exist in WebKit due to improper state
    management. An unauthenticated, remote attacker
    can exploit this, via a specially crafted website, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-4733, CVE-2016-4765)

  - An address bar spoofing vulnerability exists due to a
    state management flaw related to sessions in tabs. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted website, to spoof an address in the
    address bar. (CVE-2016-4751)

  - A flaw exists in WebKit due to improper handling of the
    location variable. An unauthenticated, remote attacker
    can exploit this, via a crafted website, to disclose
    sensitive information. (CVE-2016-4758)

  - A flaw exists in WebKit that allows an unauthenticated,
    remote attacker to conduct DNS rebinding attacks against
    non-HTTP Safari sessions by leveraging HTTP/0.9 support.
    (CVE-2016-4760)

  - A flaw exists in WebKit in the WKWebView component due
    to improper validation of X.509 certificates from HTTPS
    servers. A man-in-the-middle attacker can exploit this,
    via a crafted certificate, to disclose sensitive
    information. (CVE-2016-4763)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207157");
  # http://lists.apple.com/archives/security-announce/2016/Sep/msg00007.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c557615");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 10.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X / macOS");

if (!ereg(pattern:"Mac OS X 10\.1([0-2])([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.10 / 10.11 or macOS 10.12");

installed = get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
path    = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "10.0";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fixed_version
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:0, severity:SECURITY_HOLE, xss:TRUE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);

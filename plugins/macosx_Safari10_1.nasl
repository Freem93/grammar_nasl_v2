#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99167);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/05 19:25:56 $");

  script_cve_id(
    "CVE-2016-9642",
    "CVE-2016-9643",
    "CVE-2017-2364",
    "CVE-2017-2367",
    "CVE-2017-2376",
    "CVE-2017-2377",
    "CVE-2017-2378",
    "CVE-2017-2385",
    "CVE-2017-2386",
    "CVE-2017-2389",
    "CVE-2017-2394",
    "CVE-2017-2395",
    "CVE-2017-2396",
    "CVE-2017-2405",
    "CVE-2017-2415",
    "CVE-2017-2419",
    "CVE-2017-2424",
    "CVE-2017-2433",
    "CVE-2017-2442",
    "CVE-2017-2444",
    "CVE-2017-2445",
    "CVE-2017-2446",
    "CVE-2017-2447",
    "CVE-2017-2453",
    "CVE-2017-2454",
    "CVE-2017-2455",
    "CVE-2017-2459",
    "CVE-2017-2460",
    "CVE-2017-2463",
    "CVE-2017-2464",
    "CVE-2017-2465",
    "CVE-2017-2466",
    "CVE-2017-2468",
    "CVE-2017-2469",
    "CVE-2017-2470",
    "CVE-2017-2471",
    "CVE-2017-2475",
    "CVE-2017-2476",
    "CVE-2017-2479",
    "CVE-2017-2480",
    "CVE-2017-2481",
    "CVE-2017-2491",
    "CVE-2017-2492"
  );
  script_bugtraq_id(
    94554,
    94559,
    95725,
    97129,
    97130,
    97131,
    97133,
    97136,
    97143,
    97176,
    98316
  );
  script_osvdb_id(
    147087,
    147873,
    150774,
    153849,
    154417,
    154419,
    154421,
    154422,
    154423,
    154424,
    154425,
    154426,
    154427,
    154428,
    154429,
    154430,
    154431,
    154432,
    154433,
    154434,
    154435,
    154436,
    154437,
    154438,
    154439,
    154440,
    154441,
    154442,
    154443,
    154444,
    154445,
    154446,
    154447,
    154448,
    154449,
    154450,
    154451,
    154452,
    154460,
    154557,
    154558,
    154559
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-03-27-2");

  script_name(english:"macOS : Apple Safari < 10.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote macOS or Mac OS X 
host is prior to 10.1. It is, therefore, affected by multiple
vulnerabilities :

  - An out-of-bounds read error exists in WebKit when
    handling certain JavaScript code. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the disclosure of memory contents.
    (CVE-2016-9642)

  - A denial of service vulnerability exists in WebKit when
    handling certain regular expressions. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted web page, to exhaust available memory
    resources. (CVE-2016-9643)

  - Multiple information disclosure vulnerabilities exist
    in WebKit when handling page loading due to improper
    validation of certain input. An unauthenticated, remote
    attacker can exploit these to disclose data
    cross-origin. (CVE-2017-2364, CVE-2017-2367)

  - An unspecified state management flaw exists that allows
    an unauthenticated, remote attacker to spoof the address
    bar. (CVE-2017-2376)

  - A denial of service vulnerability exists in the Web
    Inspector component when closing a window while the
    debugger is paused. An unauthenticated, remote attacker
    can exploit this to terminate the application.
    (CVE-2017-2377)

  - An unspecified flaw exists in WebKit when creating
    bookmarks using drag-and-drop due to improper validation
    of certain input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted link, to spoof
    bookmarks or potentially execute arbitrary code.
    (CVE-2017-2378)

  - An information disclosure vulnerability exists in the
    Login AutofFill component that allows a local attacker
    to access keychain items. (CVE-2017-2385)

  - Multiple information disclosure vulnerabilities exist
    in WebKit when handling unspecified exceptions or
    elements. An unauthenticated, remote attacker can
    exploit these, via specially crafted web content, to
    disclose data cross-origin. (CVE-2017-2386,
    CVE-2017-2479, CVE-2017-2480)

  - An unspecified flaw exists in the handling of HTTP
    authentication that allows an unauthenticated, remote
    attacker to disclose authentication sheets on arbitrary
    websites or cause a denial of service condition.
    (CVE-2017-2389)

  - Multiple memory corruption issues exist in WebKit that
    allow an unauthenticated, remote attacker to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2017-2394, CVE-2017-2395,
    CVE-2017-2396, CVE-2017-2433, CVE-2017-2454,
    CVE-2017-2455, CVE-2017-2459, CVE-2017-2460,
    CVE-2017-2464, CVE-2017-2465, CVE-2017-2466,
    CVE-2017-2468, CVE-2017-2469, CVE-2017-2470,
    CVE-2017-2476)

  - A memory corruption issue exists in WebKit within the
    Web Inspector component due to improper validation of
    certain input. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2017-2405)

  - An unspecified type confusion error exists that allows
    an unauthenticated remote attacker to execute arbitrary
    code by using specially crafted web content.
    (CVE-2017-2415)

  - A security bypass vulnerability exists in WebKit that
    allows an unauthenticated, remote attacker to bypass the
    Content Security Policy by using specially crafted web
    content. (CVE-2017-2419)

  - An unspecified flaw exists in WebKit when handling
    OpenGL shaders that allows an unauthenticated, remote
    attacker to disclose process memory content by using
    specially crafted web content. (CVE-2017-2424)

  - An information disclosure vulnerability exists in WebKit
    JavaScript Bindings when handling page loading due to
    unspecified logic flaws. An unauthenticated, remote
    attacker can exploit this, via specially crafted web
    content, to disclose data cross-origin. (CVE-2017-2442)

  - A memory corruption issue exists in WebKit within the
    CoreGraphics component due to improper validation of
    certain input. An unauthenticated, remote attacker can
    exploit this, via specially crafted web content, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-2444)

  - A universal cross-site scripting (XSS) vulnerability
    exists in WebKit when handling frame objects due to
    improper validation of certain input. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted web content, to execute arbitrary
    script code in a user's browser session. (CVE-2017-2445)

  - A flaw exists in WebKit due to non-strict mode functions
    that are called from built-in strict mode scripts not
    being properly restricted from calling sensitive native
    functions. An unauthenticated, remote attacker can
    exploit this, via specially crafted web content, to
    execute arbitrary code. (CVE-2017-2446)

  - An out-of-bounds read error exists in WebKit when
    handling the bound arguments array of a bound function.
    An unauthenticated, remote attacker can exploit this,
    via specially crafted web content, to disclose memory
    contents. (CVE-2017-2447)

  - An unspecified flaw exists in FaceTime prompt handling
    due to improper validation of certain input. An
    unauthenticated, remote attacker can exploit this to
    spoof user interface elements. (CVE-2017-2453)

  - A use-after-free error exists in WebKit when handling
    RenderBox objects. An unauthenticated, remote attacker
    can exploit this, via specially crafted web content, to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2017-2463)

  - An unspecified use-after-free error exists in WebKit
    that allows an unauthenticated, remote attacker, via
    specially crafted web content, to dereference already
    freed memory, resulting in the execution of arbitrary
    code. (CVE-2017-2471)

  - A universal cross-site scripting (XSS) vulnerability
    exists in WebKit when handling frames due to improper
    validation of certain input. An unauthenticated, remote
    attacker can exploit this, via specially crafted web
    content, to execute arbitrary script code in a user's
    browser session. (CVE-2017-2475)

  - A use-after-free error exists in WebKit when handling
    ElementData objects. An unauthenticated, remote attacker
    can exploit this, via specially crafted web content, to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2017-2481)

  - A use-after-free error exists in JavaScriptCore when
    handling the String.replace() method. An
    unauthenticated, remote attacker can exploit this to
    deference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2017-2491)

  - A universal cross-site scripting (XSS) vulnerability
    exists in JavaScriptCore due to an unspecified prototype
    flaw. An unauthenticated, remote attacker can exploit
    this, via a specially crafted web page, to execute
    arbitrary code in a user's browser session.
    (CVE-2017-2492)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207600");
  # https://lists.apple.com/archives/security-announce/2017/Mar/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6d82a85");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X or macOS");

if (!ereg(pattern:"Mac OS X 10\.(10|11|12)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X Yosemite 10.10 / Mac OS X El Capitan 10.11 / macOS Sierra 10.12");

installed = get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
path      = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version   = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "10.1";

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
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);

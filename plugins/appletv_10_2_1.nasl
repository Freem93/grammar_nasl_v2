#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100256);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/17 19:02:23 $");

  script_cve_id(
    "CVE-2017-2499",
    "CVE-2017-2501",
    "CVE-2017-2502",
    "CVE-2017-2504",
    "CVE-2017-2505",
    "CVE-2017-2507",
    "CVE-2017-2513",
    "CVE-2017-2515",
    "CVE-2017-2518",
    "CVE-2017-2519",
    "CVE-2017-2520",
    "CVE-2017-2521",
    "CVE-2017-2524",
    "CVE-2017-2525",
    "CVE-2017-2530",
    "CVE-2017-2531",
    "CVE-2017-2536",
    "CVE-2017-2549",
    "CVE-2017-6979",
    "CVE-2017-6980",
    "CVE-2017-6984",
    "CVE-2017-6987",
    "CVE-2017-6989"
  );
  script_osvdb_id(
    157532,
    157534,
    157535,
    157536,
    157538,
    157539,
    157544,
    157545,
    157547,
    157549,
    157550,
    157552,
    157553,
    157554,
    157560,
    157561,
    157562,
    157563,
    157566,
    157590,
    157600,
    157604,
    157667
  );

  script_name(english:"Apple TV < 10.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device
is prior to 10.2.1. It is, therefore, affected by multiple
vulnerabilities :

  - A memory corruption issue exists in the WebKit Web
    Inspector component that allows an unauthenticated,
    remote attacker to execute arbitrary code.
    (CVE-2017-2499)

  - An unspecified race condition exists in the Kernel
    component that allows a local attacker to execute
    arbitrary code with kernel-level privileges.
    (CVE-2017-2501)

  - An information disclosure vulnerability exists in the
    CoreAudio component due to improper sanitization of
    certain input. A local attacker can exploit this to read
    the contents of restricted memory. (CVE-2017-2502)

  - A universal cross-site scripting (XSS) vulnerability
    exists in WebKit due to a logic flaw when handling
    WebKit Editor commands. An unauthenticated, remote
    attacker can exploit this, via a specially crafted web
    page, to execute arbitrary script code in a user's
    browser session. (CVE-2017-2504)

  - Multiple memory corruption issues exist in WebKit due to
    improper validation of certain input. An
    unauthenticated, remote attacker can exploit these to
    execute arbitrary code. (CVE-2017-2505, CVE-2017-2515,
    CVE-2017-2521, CVE-2017-2530, CVE-2017-2531,
    CVE-2017-6980, CVE-2017-6984)

  - Multiple information disclosure vulnerabilities exist
    in the Kernel component due to improper sanitization of
    certain input. A local attacker can exploit these to
    read the contents of restricted memory. (CVE-2017-2507,
    CVE-2017-6987)

  - A use-after-free error exists in the SQLite component
    when handling SQL queries. An unauthenticated, remote
    attacker can exploit this to deference already freed
    memory, resulting in the execution of arbitrary code.
    (CVE-2017-2513)

  - Multiple buffer overflow conditions exist in the SQLite
    component due to the improper validation of certain
    input. An unauthenticated, remote attacker can exploit
    these, via a specially crafted SQL query, to execute
    arbitrary code. (CVE-2017-2518, CVE-2017-2520)

  - A memory corruption issue exists in the SQLite component
    when handling SQL queries. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    query, to execute arbitrary code. (CVE-2017-2519)

  - An unspecified memory corruption issue exists in the
    TextInput component when parsing specially crafted data.
    An unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-2524)

  - A use-after-free error exists in WebKit when handling
    RenderLayer objects. An unauthenticated, remote attacker
    can exploit this, via a specially crafted web page, to
    deference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2017-2525)

  - Multiple unspecified flaws exist in WebKit that allow
    an unauthenticated, remote attacker to corrupt memory
    and execute arbitrary code by using specially crafted
    web content. (CVE-2017-2536)

  - A universal cross-site scripting (XSS) vulnerability
    exists in WebKit due to a logic error when handling
    frame loading. An unauthenticated, remote attacker can
    exploit this, via a specially crafted web page, to
    execute arbitrary code in a user's browser session.
    (CVE-2017-2549)

  - An unspecified flaw exists in the IOSurface component
    that allows a local attacker to corrupt memory and
    execute arbitrary code with kernel-level privileges.
    (CVE-2017-6979)

  - An unspecified flaw exists in the AVEVideoEncoder
    component that allows a local attacker, via a specially
    crafted application, to corrupt memory and execute
    arbitrary code with kernel-level privileges.
    (CVE-2017-6989)

Note that only 4th generation models are affected by these
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207801");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 10.2.1 or later. Note that this update is
only available for 4th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("appletv_version.nasl");
  script_require_keys("AppleTV/Version", "AppleTV/Model", "AppleTV/URL", "AppleTV/Port");
  script_require_ports("Services/www", 7000);

  exit(0);
}

include("audit.inc");
include("appletv_func.inc");

url = get_kb_item('AppleTV/URL');
if (empty_or_null(url)) exit(0, 'Cannot determine Apple TV URL.');
port = get_kb_item('AppleTV/Port');
if (empty_or_null(port)) exit(0, 'Cannot determine Apple TV port.');

build = get_kb_item('AppleTV/Version');
if (empty_or_null(build)) audit(AUDIT_UNKNOWN_DEVICE_VER, 'Apple TV');

model = get_kb_item('AppleTV/Model');
if (empty_or_null(model)) exit(0, 'Cannot determine Apple TV model.');

fixed_build = "14W585a";
tvos_ver = '10.2.1';
gen = 4;

appletv_check_version(
  build          : build,
  fix            : fixed_build,
  fix_tvos_ver   : tvos_ver,
  model          : model,
  gen            : gen,
  port           : port,
  url            : url,
  severity       : SECURITY_HOLE,
  xss            : TRUE
);

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99264);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/05 19:25:56 $");

  script_cve_id(
    "CVE-2016-3619",
    "CVE-2016-9642",
    "CVE-2016-9643",
    "CVE-2017-2367",
    "CVE-2017-2379",
    "CVE-2017-2386",
    "CVE-2017-2390",
    "CVE-2017-2394",
    "CVE-2017-2395",
    "CVE-2017-2396",
    "CVE-2017-2401",
    "CVE-2017-2406",
    "CVE-2017-2407",
    "CVE-2017-2415",
    "CVE-2017-2416",
    "CVE-2017-2417",
    "CVE-2017-2428",
    "CVE-2017-2430",
    "CVE-2017-2432",
    "CVE-2017-2435",
    "CVE-2017-2439",
    "CVE-2017-2440",
    "CVE-2017-2441",
    "CVE-2017-2444",
    "CVE-2017-2445",
    "CVE-2017-2446",
    "CVE-2017-2447",
    "CVE-2017-2448",
    "CVE-2017-2450",
    "CVE-2017-2451",
    "CVE-2017-2454",
    "CVE-2017-2455",
    "CVE-2017-2456",
    "CVE-2017-2458",
    "CVE-2017-2459",
    "CVE-2017-2460",
    "CVE-2017-2461",
    "CVE-2017-2462",
    "CVE-2017-2464",
    "CVE-2017-2465",
    "CVE-2017-2466",
    "CVE-2017-2467",
    "CVE-2017-2468",
    "CVE-2017-2469",
    "CVE-2017-2470",
    "CVE-2017-2472",
    "CVE-2017-2473",
    "CVE-2017-2474",
    "CVE-2017-2475",
    "CVE-2017-2476",
    "CVE-2017-2478",
    "CVE-2017-2481",
    "CVE-2017-2482",
    "CVE-2017-2483",
    "CVE-2017-2485",
    "CVE-2017-2487",
    "CVE-2017-2490",
    "CVE-2017-2491",
    "CVE-2017-2492"
  );
  script_bugtraq_id(
    85919,
    94554,
    94559,
    97130,
    97131,
    97132,
    97134,
    97137,
    97143,
    97146,
    97301,
    98316
  );
  script_osvdb_id(
    136738,
    147087,
    147873,
    153849,
    154417,
    154418,
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
    154444,
    154445,
    154446,
    154447,
    154449,
    154460,
    154467,
    154468,
    154480,
    154482,
    154483,
    154484,
    154485,
    154486,
    154487,
    154488,
    154489,
    154491,
    154492,
    154493,
    154496,
    154497,
    154501,
    154502,
    154505,
    154506,
    154507,
    154510,
    154511,
    154512,
    154513,
    154514,
    154517,
    154518,
    154519,
    154759
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-03-27-6");

  script_name(english:"Apple TV < 10.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apple TV device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apple TV on the remote device
is prior to 10.2. It is, therefore, affected by multiple
vulnerabilities :

  - An out-of-bounds read error exists in LibTIFF in the
    DumpModeEncode() function within file tif_dumpmode.c.
    An unauthenticated, remote attacker can exploit this
    to crash a process linked against the library or
    disclose memory contents. (CVE-2016-3619)

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

  - An information disclosure vulnerability exists in WebKit
    when handling page loading due to improper validation of
    certain input. An unauthenticated, remote attacker can
    exploit this to disclose data cross-origin.
    (CVE-2017-2367)

  - A buffer overflow condition exists in the Carbon
    component when handling specially crafted DFONT files
    due to improper validation of certain input. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted file, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2017-2379)

  - An information disclosure vulnerability exists in WebKit
    when handling unspecified exceptions. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted web content, to disclose data
    cross-origin. (CVE-2017-2386)

  - A flaw exists in the libarchive component due to the
    insecure creation of temporary files. A local attacker
    can exploit this, by using a symlink attack against an
    unspecified file, to cause unexpected changes to be made
    to file system permissions. (CVE-2017-2390)

  - Multiple memory corruption issues exist in WebKit that
    allow an unauthenticated, remote attacker to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2017-2394, CVE-2017-2395,
    CVE-2017-2396, CVE-2017-2454, CVE-2017-2455,
    CVE-2017-2459, CVE-2017-2460, CVE-2017-2464,
    CVE-2017-2465, CVE-2017-2466, CVE-2017-2468,
    CVE-2017-2469, CVE-2017-2470, CVE-2017-2476)

  - A memory corruption issue exists in the Kernel component
    due to improper validation of certain input. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to run a specially crafted
    application, to cause a denial of service condition or
    the execution or arbitrary code. (CVE-2017-2401)

  - Multiple memory corruption issues exist in the FontParser
    component when handling font files due to improper
    validation of certain input. An unauthenticated, remote
    attacker can exploit these to cause a denial condition
    or the execution of arbitrary code. (CVE-2017-2406,
    CVE-2017-2407, CVE-2017-2487)

  - An unspecified type confusion error exists in WebKit
    that allows an unauthenticated, remote attacker to
    execute arbitrary code by using specially crafted web
    content. (CVE-2017-2415)

  - A memory corruption issue exists in the ImageIO
    component, specifically in the GIFReadPlugin::init()
    function, when handling image files due to improper
    validation of certain input. An unauthenticated, remote
    attacker can exploit this, via a specially crafted image
    file, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2017-2416)

  - An infinite recursion condition exists in the
    CoreGraphics component when handling image files. An
    unauthenticated, remote can exploit this, via a
    specially crafted image file, to cause a denial of
    service condition. (CVE-2017-2417)

  - An unspecified flaw exists related to nghttp2 and
    LibreSSL. An unauthenticated, remote attacker can
    exploit this, by convincing a user to access a malicious
    HTTP/2 server, to have an unspecified impact on
    confidentiality, integrity, and availability.
    (CVE-2017-2428)

  - A type confusion error exists in the Audio component
    when parsing specially crafted M4A audio files due to
    improper validation of certain input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted file, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2017-2430)

  - An integer overflow condition exists in the ImageIO
    component when handling JPEG files due to improper
    validation of certain input. An unauthenticated, remote
    attacker can exploit this, via a specially crafted file,
    to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2017-2432)

  - A memory corruption issue exists in the CoreText
    component when handling font files due to improper
    validation of certain input. An unauthenticated, remote
    attacker can exploit this, via a specially crafted file,
    to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2017-2435)

  - An out-of-bounds read error exists in the FontParser
    component when handling font files. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted file, to disclose process memory.
    (CVE-2017-2439)

  - An integer overflow condition exists in the Kernel
    component due to improper validation of certain input.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to run a specially crafted
    application, to execute arbitrary code with kernel-level
    privileges. (CVE-2017-2440)

  - A use-after-free error exists in libc++abi when
    demangling C++ applications. An unauthenticated, remote
    attacker can exploit this, by convincing a user to run a
    specially crafted application, to execute arbitrary
    code. (CVE-2017-2441)

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

  - An unspecified flaw exists in the Security component due
    to improper validation of OTR packets under certain
    conditions. A man-in-the-middle attacker can exploit
    this to disclose and optionally manipulate transmitted
    data by spoofing the TLS/SSL server via a packet that
    appears to be valid. (CVE-2017-2448)

  - An out-of-bounds read error exists in CoreText component
    when handling font files. An unauthenticated, remote
    attacker can exploit this, via a specially crafted file,
    to disclose process memory. (CVE-2017-2450)

  - A buffer overflow condition exists in the Security
    component due to improper validation of certain input.
    An unauthenticated, remote attacker can exploit this,
    by convincing a user to run a specially crafted
    application, to execute arbitrary code with root
    root privileges. (CVE-2017-2451)

  - A race condition exists in the Kernel component when
    handling memory using the 'mach_msg' system call. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to run a specially crafted
    application, to cause a heap-based buffer overflow,
    resulting in a denial of service condition or the
    execution of arbitrary code with root privileges.
    CVE-2017-2456)

  - An buffer overflow condition exists in the Keyboards
    component due to improper validation of certain input.
    An unauthenticated, remote attacker can exploit this, by
    convincing a user to run a specially crafted
    application, to cause a denial of service condition or
    the execution of arbitrary code. (CVE-2017-2458)

  - A denial of service vulnerability exists in the
    CoreText component when handling specially crafted text
    messages due to improper validation of certain input. An
    unauthenticated, remote attacker can exploit this to
    exhaust available resources on the system.
    (CVE-2017-2461)

  - A heap buffer overflow condition exists in the Audio
    component when parsing specially crafted M4A audio files
    due to improper validation of certain input. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted file, to execute arbitrary code.
    (CVE-2017-2462)

  - An memory corruption issue exists in the ImageIO
    component when handling specially crafted files due to
    improper validation of certain input. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted file, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2017-2467)

  - A use-after-free error exists in the Kernel component in
    the XNU port actions extension due to improper handling
    of port references in error cases. An local attacker can
    exploit this to deference already freed memory,
    resulting in the execution of arbitrary code with
    kernel-level privileges. (CVE-2017-2472)

  - A signedness error exists in the Kernel component in the
    SIOCSIFORDER IOCTL due to improper validation of certain
    input. A local attacker can exploit this to cause an
    out-of-bounds read and memory corruption, resulting in
    a denial of service condition or the execution of
    arbitrary code with kernel-level privileges.
    (CVE-2017-2473)

  - A off-by-one overflow condition exists in the Kernel
    component in the SIOCSIFORDER IOCTL due to improper
    validation of certain input. A local attacker can exploit
    this to cause a heap-based buffer overflow, resulting in
    the execution of arbitrary code with kernel-level
    privileges. (CVE-2017-2474)

  - A universal cross-site scripting (XSS) vulnerability
    exists in WebKit when handling frames due to improper
    validation of certain input. An unauthenticated, remote
    attacker can exploit this, via specially crafted web
    content, to execute arbitrary script code in a user's
    browser session. (CVE-2017-2475)

  - A race condition exists in the Kernel component in the
    necp_open() function when closing files descriptors due
    to improper handling of proc_fd locks. A local attacker
    can exploit this to dereference already freed memory,
    resulting in the execution of arbitrary code with
    kernel-level privileges. (CVE-2017-2478)

  - A use-after-free error exists in WebKit when handling
    ElementData objects. An unauthenticated, remote attacker
    can exploit this, via specially crafted web content, to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2017-2481)

  - A heap buffer overflow condition exists in the Kernel
    component within the Berkeley Packet Filter (BPF)
    BIOCSBLEN IOCTL due to improper validation of certain
    input when reattaching to an interface. A local attacker
    can exploit this to cause a denial of service condition
    or the execution of arbitrary code with kernel-level
    privileges. (CVE-2017-2482)

  - An off-by-one error exists in the Kernel component,
    specifically in the audit_pipe_open() function, when
    handling auditpipe devices due to improper validation of
    certain input. A local attacker can exploit this to
    corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code with
    kernel-level privileges. (CVE-2017-2483)

  - An unspecified memory corruption issue exists in the
    Security component when parsing X.509 certificates due
    to improper validation of certain input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-2485)

  - A double-free error exists in the Kernel component due
    to FSEVENTS_DEVICE_FILTER_64 IOCTL not properly locking
    devices. A local attacker can exploit this to corrupt
    memory, resulting in the execution of arbitrary code
    with elevated privileges. (CVE-2017-2490)

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
    (CVE-2017-2492)

Note that only 4th generation models are affected by these
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207601");
  # https://lists.apple.com/archives/security-announce/2017/Mar/msg00007.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1dbb626");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV version 10.2 or later. Note that this update is
only available for 4th generation models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/10");

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

fixed_build = "14W265";
tvos_ver = '10.2';
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

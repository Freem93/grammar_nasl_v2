#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100270);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/18 13:50:47 $");

  script_cve_id(
    "CVE-2017-2494",
    "CVE-2017-2497",
    "CVE-2017-2501",
    "CVE-2017-2502",
    "CVE-2017-2503",
    "CVE-2017-2507",
    "CVE-2017-2509",
    "CVE-2017-2512",
    "CVE-2017-2513",
    "CVE-2017-2516",
    "CVE-2017-2518",
    "CVE-2017-2519",
    "CVE-2017-2520",
    "CVE-2017-2524",
    "CVE-2017-2527",
    "CVE-2017-2533",
    "CVE-2017-2534",
    "CVE-2017-2535",
    "CVE-2017-2537",
    "CVE-2017-2540",
    "CVE-2017-2541",
    "CVE-2017-2542",
    "CVE-2017-2543",
    "CVE-2017-2545",
    "CVE-2017-2546",
    "CVE-2017-2548",
    "CVE-2017-6977",
    "CVE-2017-6978",
    "CVE-2017-6979",
    "CVE-2017-6981",
    "CVE-2017-6983",
    "CVE-2017-6985",
    "CVE-2017-6986",
    "CVE-2017-6987",
    "CVE-2017-6988",
    "CVE-2017-6990",
    "CVE-2017-6991"
  );
  script_bugtraq_id(
    98483
  );
  script_osvdb_id(
    153955,
    157547,
    157548,
    157549,
    157550,
    157551,
    157552,
    157553,
    157554,
    157556,
    157557,
    157558,
    157560,
    157561,
    157562,
    157563,
    157564,
    157565,
    157567,
    157568,
    157570,
    157571,
    157572,
    157574,
    157575,
    157576,
    157577,
    157578,
    157579,
    157580,
    157581,
    157583,
    157597,
    157598,
    157599,
    157606,
    157607
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-05-15-1");
  script_xref(name:"IAVA", value:"2017-A-0150");

  script_name(english:"macOS 10.12.x < 10.12.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of macOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS that is 10.12.x prior to
10.12.5. It is, therefore, affected by multiple vulnerabilities :

  - Multiple memory corruption issues exist in the Kernel
    component that allow a local attacker to gain
    kernel-level privileges. (CVE-2017-2494, CVE-2017-2546)

  - A state management flaw exists in the iBooks component
    due to improper handling of URLs. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted book, to open arbitrary websites without user
    permission. (CVE-2017-2497)

  - A local privilege escalation vulnerability exists in the
    Kernel component due to a race condition. A local
    attacker can exploit this to execute arbitrary code with
    kernel-level privileges. (CVE-2017-2501)

  - An information disclosure vulnerability exists in the
    CoreAudio component due to improper sanitization of
    user-supplied input. A local attacker can exploit this
    to read the contents of restricted memory.
    (CVE-2017-2502)

  - A memory corruption issue exists in the Intel graphics
    driver component that allows a local attacker to execute
    arbitrary code with kernel-level privileges.
    CVE-2017-2503)

  - Multiple information disclosure vulnerabilities exist
    in the Kernel component due to improper sanitization of
    user-supplied input. A local attacker can exploit these
    to read the contents of restricted memory.
    (CVE-2017-2507, CVE-2017-2509, CVE-2017-2516,
    CVE-2017-6987)

  - A memory corruption issue exists in the Sandbox
    component that allows an unauthenticated, remote
    attacker to escape an application sandbox.
    (CVE-2017-2512)

  - A use-after-free error exists in the SQLite component
    when handling SQL queries. An unauthenticated, remote
    attacker can exploit this to deference already freed
    memory, resulting in the execution of arbitrary code.
    (CVE-2017-2513)

  - Multiple buffer overflow conditions exist in the SQLite
    component due to the improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit these, via a specially crafted SQL query, to
    execute arbitrary code. (CVE-2017-2518, CVE-2017-2520)

  - A memory corruption issue exists in the SQLite component
    when handling SQL queries. An unauthenticated, remote
    attacker can exploit this, via a specially crafted SQL
    query, to execute arbitrary code. (CVE-2017-2519)

  - An unspecified memory corruption issue exists in the
    TextInput component when parsing specially crafted data.
    An unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2017-2524)

  - A flaw exists in the CoreAnimation component when
    handling specially crafted data. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2017-2527)

  - A race condition exists in the DiskArbitration feature
    that allow a local attacker to gain system-level
    privileges. (CVE-2017-2533)

  - An unspecified flaw exists in the Speech Framework that
    allows a local attacker to escape an application
    sandbox. (CVE-2017-2534)

  - A resource exhaustion issue exists in the Security
    component due to improper validation of user-supplied
    input. A local attacker can exploit this to exhaust
    resources and escape an application sandbox.
    (CVE-2017-2535)

  - Multiple memory corruption issues exist in the
    WindowServer component that allow a local attacker to
    execute arbitrary code with system-level privileges.
    (CVE-2017-2537, CVE-2017-2548)

  - An information disclosure vulnerability exists in
    WindowServer component in the _XGetConnectionPSN()
    function due to improper validation of user-supplied
    input. A local attacker can exploit this to read the
    contents of restricted memory. (CVE-2017-2540)

  - A stack-based buffer overflow condition exists in the
    WindowServer component in the _XGetWindowMovementGroup()
    function due to improper validation of user-supplied
    input. A local attacker can exploit this to execute
    arbitrary code with the privileges of WindowServer.
    (CVE-2017-2541)

  - Multiple memory corruption issues exist in the
    Multi-Touch component that allow a local attacker to
    execute arbitrary code with kernel-level privileges.
    (CVE-2017-2542, CVE-2017-2543)

  - A use-after-free error exists in the IOGraphic component
    that allows a local attacker to execute arbitrary code
    with kernel-level privileges. (CVE-2017-2545)

  - A flaw exists in the Speech Framework, specifically
    within the speechsynthesisd service, due to improper
    validation of unsigned dynamic libraries (.dylib) before
    being loaded. A local attacker can exploit this to
    bypass the application's sandbox and execute arbitrary
    code with elevated privileges. (CVE-2017-6977)

  - A memory corruption issue exists in the Accessibility
    Framework that allows a local attacker to execute
    arbitrary code with system-level privileges.
    (CVE-2017-6978)

  - A race condition exists in the IOSurface component that
    allows a local attacker to execute arbitrary code with
    kernel-level privileges. (CVE-2017-6979)

  - A logic error exists in the iBooks component due to
    improper path validation for symlinks. A local attacker
    can exploit this to execute arbitrary code with root
    privileges. (CVE-2017-6981)

  - Multiple memory corruption issues exist in SQLite due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit these, by
    convincing a user to visit a specially crafted website,
    to execute arbitrary code. (CVE-2017-6983,
    CVE-2017-6991)

  - A memory corruption issue exists in the NVIDIA graphics
    drivers that allows a local attacker to execute
    arbitrary code with kernel-level privileges.
    (CVE-2017-6985)

  - A memory corruption issue exists in the iBooks component
    that allows an unauthenticated, remote attacker to
    escape an application's sandbox. (CVE-2017-6986)

  - A certificate validation flaw exists in EAP-TLS within
    802.1X authentication when a certificate has changed.
    An unauthenticated, adjacent attacker can exploit this,
    via a malicious network with 802.1X authentication, to
    capture user network credentials. (CVE-2017-6988)

  - An information disclosure vulnerability exists in HFS
    component due to improper sanitization of user-supplied
    input. A local attacker can exploit this to read the
    contents of restricted memory. (CVE-2017-6990)");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS version 10.12.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207797");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2017/May/47");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "macOS / Mac OS X");

matches = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(matches)) exit(1, "Failed to parse the macOS / Mac OS X version ('" + os + "').");

version = matches[1];
if (version !~ "^10\.12($|[^0-9])") audit(AUDIT_OS_NOT, "Mac OS 10.12.x");

fixed_version = "10.12.5";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  security_report_v4(
    port:0,
    severity:SECURITY_HOLE,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS / Mac OS X", version);

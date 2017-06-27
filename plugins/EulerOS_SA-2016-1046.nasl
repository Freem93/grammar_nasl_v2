#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99809);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2016-5250",
    "CVE-2016-5257",
    "CVE-2016-5261",
    "CVE-2016-5270",
    "CVE-2016-5272",
    "CVE-2016-5274",
    "CVE-2016-5276",
    "CVE-2016-5277",
    "CVE-2016-5278",
    "CVE-2016-5280",
    "CVE-2016-5281",
    "CVE-2016-5284"
  );
  script_osvdb_id(
    142472,
    142473,
    144426,
    144614,
    144615,
    144616,
    144617,
    144618,
    144619,
    144620,
    144621,
    144623,
    144624,
    144625,
    144627,
    144628,
    144630,
    144634,
    144635,
    144636
  );

  script_name(english:"EulerOS 2.0 SP1 : firefox (EulerOS-SA-2016-1046)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the firefox package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Mozilla Firefox before 48.0 allows remote attackers to
    obtain sensitive information about the previously
    retrieved page via Resource Timing API
    calls.(CVE-2016-5250)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox before 49.0 and Firefox ESR
    45.x before 45.4 allow remote attackers to cause a
    denial of service (memory corruption and application
    crash) or possibly execute arbitrary code via unknown
    vectors.(CVE-2016-5257)

  - Integer overflow in the WebSocketChannel class in the
    WebSockets subsystem in Mozilla Firefox before 48.0
    allows remote attackers to execute arbitrary code or
    cause a denial of service (memory corruption) via
    crafted packets that trigger incorrect buffer-resize
    operations during buffering.(CVE-2016-5261)

  - Heap-based buffer overflow in the
    nsCaseTransformTextRunFactory::TransformString function
    in Mozilla Firefox before 49.0 and Firefox ESR 45.x
    before 45.4 allows remote attackers to cause a denial
    of service (boolean out-of-bounds write) or possibly
    have unspecified other impact via Unicode characters
    that are mishandled during text
    conversion.(CVE-2016-5270)

  - The nsImageGeometryMixin class in Mozilla Firefox
    before 49.0 and Firefox ESR 45.x before 45.4 does not
    properly perform a cast of an unspecified variable
    during handling of INPUT elements, which allows remote
    attackers to execute arbitrary code via a crafted web
    site.(CVE-2016-5272)

  - Use-after-free vulnerability in the
    nsFrameManager::CaptureFrameState function in Mozilla
    Firefox before 49.0 and Firefox ESR 45.x before 45.4
    allows remote attackers to execute arbitrary code by
    leveraging improper interaction between restyling and
    the Web Animations model implementation.(CVE-2016-5274)

  - Use-after-free vulnerability in the
    mozilla::a11y::DocAccessible::ProcessInvalidationList
    function in Mozilla Firefox before 49.0 and Firefox ESR
    45.x before 45.4 allows remote attackers to execute
    arbitrary code or cause a denial of service (heap
    memory corruption) via an aria-owns
    attribute.(CVE-2016-5276)

  - Use-after-free vulnerability in the
    nsRefreshDriver::Tick function in Mozilla Firefox
    before 49.0 and Firefox ESR 45.x before 45.4 allows
    remote attackers to execute arbitrary code or cause a
    denial of service (heap memory corruption) by
    leveraging improper interaction between timeline
    destruction and the Web Animations model
    implementation.(CVE-2016-5277)

  - Heap-based buffer overflow in the
    nsBMPEncoder::AddImageFrame function in Mozilla Firefox
    before 49.0 and Firefox ESR 45.x before 45.4 allows
    remote attackers to execute arbitrary code via a
    crafted image data that is mishandled during the
    encoding of an image frame to an image.(CVE-2016-5278)

  - Use-after-free vulnerability in the
    mozilla::nsTextNodeDirectionalityMap::RemoveElementFrom
    Map function in Mozilla Firefox before 49.0 and Firefox
    ESR 45.x before 45.4 allows remote attackers to execute
    arbitrary code via bidirectional text.(CVE-2016-5280)

  - Use-after-free vulnerability in the DOMSVGLength class
    in Mozilla Firefox before 49.0 and Firefox ESR 45.x
    before 45.4 allows remote attackers to execute
    arbitrary code by leveraging improper interaction
    between JavaScript code and an SVG
    document.(CVE-2016-5281)

  - Mozilla Firefox before 49.0 and Firefox ESR 45.x before
    45.4 rely on unintended expiration dates for Preloaded
    Public Key Pinning, which allows man-in-the-middle
    attackers to spoof add-on updates by leveraging
    possession of an X.509 server certificate for
    addons.mozilla.org signed by an arbitrary built-in
    Certification Authority.(CVE-2016-5284)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1046
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5dca1e4f");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["firefox-45.4.0-1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg, allowmaj:TRUE)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}

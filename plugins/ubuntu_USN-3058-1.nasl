#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3058-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93509);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2016-5141", "CVE-2016-5142", "CVE-2016-5143", "CVE-2016-5144", "CVE-2016-5145", "CVE-2016-5146", "CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5150", "CVE-2016-5153", "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5161", "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5167");
  script_osvdb_id(142525, 142526, 142527, 142528, 142529, 142531, 142532, 142533, 143643, 143645, 143646, 143649, 143650, 143651, 143654, 143657, 143658, 143688, 143718, 143720, 143723, 143724, 143726, 143727, 143737, 143744, 143746, 143747, 143752);
  script_xref(name:"USN", value:"3058-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : oxide-qt vulnerabilities (USN-3058-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue was discovered in Blink involving the provisional URL for an
initially empty document. An attacker could potentially exploit this
to spoof the currently displayed URL. (CVE-2016-5141)

A use-after-free was discovered in the WebCrypto implementation in
Blink. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit this to cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2016-5142)

It was discovered that the devtools subsystem in Blink mishandles
various parameters. An attacker could exploit this to bypass intended
access restrictions. (CVE-2016-5143, CVE-2016-5144)

It was discovered that Blink does not ensure that a taint property is
preserved after a structure-clone operation on an ImageBitmap object
derived from a cross-origin image. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to bypass same origin restrictions. (CVE-2016-5145)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash, or execute arbitrary code.
(CVE-2016-5146, CVE-2016-5167)

It was discovered that Blink mishandles deferred page loads. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to conduct cross-site scripting (XSS)
attacks. (CVE-2016-5147)

An issue was discovered in Blink related to widget updates. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to conduct cross-site scripting (XSS)
attacks. (CVE-2016-5148)

A use-after-free was discovered in Blink. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code. (CVE-2016-5150)

A use-after-free was discovered in Blink. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via application crash, or
execute arbitrary code. (CVE-2016-5153)

It was discovered that Chromium does not correctly validate access to
the initial document. An attacker could potentially exploit this to
spoof the currently displayed URL. (CVE-2016-5155)

A use-after-free was discovered in the event bindings in Blink. If a
user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via application crash, or execute arbitrary code. (CVE-2016-5156)

A type confusion bug was discovered in Blink. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code. (CVE-2016-5161)

An issue was discovered with the devtools implementation. An attacker
could potentially exploit this to conduct cross-site scripting (XSS)
attacks. (CVE-2016-5164)

An issue was discovered with the devtools implementation. An attacker
could potentially exploit this to conduct cross-site scripting (XSS)
attacks. (CVE-2016-5165).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liboxideqtcore0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016 Canonical, Inc. / NASL script (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(14\.04|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.17.7-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"liboxideqtcore0", pkgver:"1.17.7-0ubuntu0.16.04.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liboxideqtcore0");
}

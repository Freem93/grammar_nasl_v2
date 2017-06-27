#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2825-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87320);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/24 17:52:27 $");

  script_cve_id("CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768", "CVE-2015-6769", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772", "CVE-2015-6773", "CVE-2015-6777", "CVE-2015-6782", "CVE-2015-6784", "CVE-2015-6785", "CVE-2015-6786", "CVE-2015-6787", "CVE-2015-8478");
  script_osvdb_id(129198, 130244, 130971, 130972, 130973, 130974, 130975, 130976, 130977, 130978, 130981, 130986, 130988, 130989, 130990, 130991, 130992, 131009, 131010, 131011, 131012, 131013, 131014, 131029, 131030, 131031);
  script_xref(name:"USN", value:"2825-1");

  script_name(english:"Ubuntu 14.04 LTS / 15.04 / 15.10 : oxide-qt vulnerabilities (USN-2825-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple use-after-free bugs were discovered in the application cache
implementation in Chromium. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit these
to cause a denial of service via application crash, or execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2015-6765, CVE-2015-6766, CVE-2015-6767)

Several security issues were discovered in the DOM implementation in
Chromium. If a user were tricked in to opening a specially crafted
website, an attacker could potentially exploit these to bypass same
origin restrictions. (CVE-2015-6768, CVE-2015-6770)

A security issue was discovered in the provisional-load commit
implementation in Chromium. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to bypass same origin restrictions. (CVE-2015-6769)

An out-of-bounds read was discovered in the array map and filter
operations in V8 in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service via renderer crash.
(CVE-2015-6771)

It was discovered that the DOM implementation in Chromium does not
prevent javascript: URL navigation while a document is being detached.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to bypass same origin
restrictions. (CVE-2015-6772)

An out-of bounds read was discovered in Skia in some cirumstances. If
a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via renderer crash. (CVE-2015-6773)

A use-after-free was discovered in the DOM implementation in Chromium.
If a user were tricked in to opening a specially crafted website, an
attacker could potentially exploit this to cause a denial of service
via renderer crash or execute arbitrary code with the privileges of
the sandboxed render process. (CVE-2015-6777)

It was discovered that the Document::open function in Chromium did not
ensure that page-dismissal event handling is compatible with modal
dialog blocking. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to spoof
application UI content. (CVE-2015-6782)

It was discovered that the page serializer in Chromium mishandled MOTW
comments for URLs in some circumstances. An attacker could potentially
exploit this to inject HTML content. (CVE-2015-6784)

It was discovered that the Content Security Policy (CSP)
implementation in Chromium accepted an x.y hostname as a match for a
*.x.y pattern. An attacker could potentially exploit this to bypass
intended access restrictions. (CVE-2015-6785)

It was discovered that the Content Security Policy (CSP)
implementation in Chromium accepted blob:, data: and filesystem: URLs
as a match for a * pattern. An attacker could potentially exploit this
to bypass intended access restrictions. (CVE-2015-6786)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via application crash or execute arbitrary code with the
privileges of the user invoking the program. (CVE-2015-6787)

Multiple security issues were discovered in V8. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service via renderer crash or execute arbitrary code with the
privileges of the sandboxed render process. (CVE-2015-8478).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liboxideqtcore0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|15\.04|15\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.04 / 15.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.11.3-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.04", pkgname:"liboxideqtcore0", pkgver:"1.11.3-0ubuntu0.15.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"liboxideqtcore0", pkgver:"1.11.3-0ubuntu0.15.10.1")) flag++;

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

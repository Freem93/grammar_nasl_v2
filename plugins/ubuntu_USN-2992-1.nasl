#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2992-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91498);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2017/03/13 15:28:56 $");

  script_cve_id("CVE-2016-1673", "CVE-2016-1675", "CVE-2016-1677", "CVE-2016-1678", "CVE-2016-1679", "CVE-2016-1680", "CVE-2016-1682", "CVE-2016-1683", "CVE-2016-1684", "CVE-2016-1688", "CVE-2016-1689", "CVE-2016-1691", "CVE-2016-1692", "CVE-2016-1695", "CVE-2016-1697", "CVE-2016-1699", "CVE-2016-1702", "CVE-2016-1703");
  script_osvdb_id(120600, 121175, 129696, 130292, 130435, 130535, 130536, 130538, 130539, 130543, 130641, 130642, 130651, 135603, 137043, 139023, 139025, 139027, 139028, 139029, 139030, 139031, 139032, 139034, 139036, 139037, 139040, 139041, 139087, 139088, 139091, 139096, 139099, 139100, 139101, 139106, 139107, 139108, 139109, 139110, 139114, 139186, 139187, 139190, 139191, 139192, 139292, 139294, 139297, 139384, 139385, 139428, 139429, 139430, 139431, 139432, 139433, 140427);
  script_xref(name:"USN", value:"2992-1");

  script_name(english:"Ubuntu 14.04 LTS / 15.10 / 16.04 LTS : oxide-qt vulnerabilities (USN-2992-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An unspecified security issue was discovered in Blink. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit this to bypass same-origin restrictions.
(CVE-2016-1673)

An issue was discovered with Document reattachment in Blink in some
circumstances. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to bypass
same-origin restrictions. (CVE-2016-1675)

A type confusion bug was discovered in V8. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to obtain sensitive information. (CVE-2016-1677)

A heap overflow was discovered in V8. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service (application crash) or
execute arbitrary code. (CVE-2016-1678)

A use-after-free was discovered in the V8ValueConverter implementation
in Chromium in some circumstances. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service (application crash) or
execute arbitrary code. (CVE-2016-1679)

A use-after-free was discovered in Skia. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service (application crash) or
execute arbitrary code. (CVE-2016-1680)

A security issue was discovered in ServiceWorker registration in Blink
in some circumstances. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to bypass Content Security Policy (CSP) protections. (CVE-2016-1682)

An out-of-bounds memory access was discovered in libxslt. If a user
were tricked in to opening a specially crafted website, an attacker
could potentially exploit this to cause a denial of service
(application crash) or execute arbitrary code. (CVE-2016-1683)

An integer overflow was discovered in libxslt. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service (application
crash or resource consumption). (CVE-2016-1684)

An out-of-bounds read was discovered in the regular expression
implementation in V8. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit this to cause a
denial of service (application crash). (CVE-2016-1688)

A heap overflow was discovered in Chromium. If a user were tricked in
to opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service (application crash) or
execute arbitrary code. (CVE-2016-1689)

A heap overflow was discovered in Skia. If a user were tricked in to
opening a specially crafted website, an attacker could potentially
exploit this to cause a denial of service (application crash) or
execute arbitrary code. (CVE-2016-1691)

It was discovered that Blink permits cross-origin loading of
stylesheets by a service worker even when the stylesheet download has
an incorrect MIME type. If a user were tricked in to opening a
specially crafted website, an attacker could potentially exploit this
to bypass same-origin restrictions. (CVE-2016-1692)

Multiple security issues were discovered in Chromium. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to read uninitialized memory, cause a denial
of service (application crash) or execute arbitrary code.
(CVE-2016-1695, CVE-2016-1703)

It was discovered that Blink does not prevent frame navigation during
DocumentLoader detach operations. If a user were tricked in to opening
a specially crafted website, an attacker could potentially exploit
this to bypass same-origin restrictions. (CVE-2016-1697)

A parameter sanitization bug was discovered in the devtools subsystem
in Blink. An attacker could potentially exploit this to bypass
intended access restrictions. (CVE-2016-1699)

An out-of-bounds read was discovered in Skia. If a user were tricked
in to opening a specially crafted website, an attacker could
potentially exploit this to cause a denial of service (application
crash). (CVE-2016-1702).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected liboxideqtcore0 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liboxideqtcore0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2017 Canonical, Inc. / NASL script (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(14\.04|15\.10|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.10 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"liboxideqtcore0", pkgver:"1.15.7-0ubuntu0.14.04.1")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"liboxideqtcore0", pkgver:"1.15.7-0ubuntu0.15.10.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"liboxideqtcore0", pkgver:"1.15.7-0ubuntu0.16.04.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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

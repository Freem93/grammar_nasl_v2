#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3075-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93399);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/01 21:07:50 $");

  script_cve_id("CVE-2011-5326", "CVE-2014-9762", "CVE-2014-9763", "CVE-2014-9764", "CVE-2014-9771", "CVE-2016-3993", "CVE-2016-3994", "CVE-2016-4024");
  script_osvdb_id(122453, 133578, 133579, 133581, 136663, 136950, 137135, 137991);
  script_xref(name:"USN", value:"3075-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 16.04 LTS : imlib2 vulnerabilities (USN-3075-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jakub Wilk discovered an out of bounds read in the GIF loader
implementation in Imlib2. An attacker could use this to cause a denial
of service (application crash) or possibly obtain sensitive
information. (CVE-2016-3994)

Yuriy M. Kaminskiy discovered an off-by-one error when handling
coordinates in Imlib2. An attacker could use this to cause a denial of
service (application crash). (CVE-2016-3993)

Yuriy M. Kaminskiy discovered that integer overflows existed in Imlib2
when handling images with large dimensions. An attacker could use this
to cause a denial of service (memory exhaustion or application crash).
(CVE-2014-9771, CVE-2016-4024)

Kevin Ryde discovered that the ellipse drawing code in Imlib2 would
attempt to divide by zero when drawing a 2x1 ellipse. An attacker
could use this to cause a denial of service (application crash).
(CVE-2011-5326)

It was discovered that Imlib2 did not properly handled GIF images
without colormaps. An attacker could use this to cause a denial of
service (application crash). This issue only affected Ubuntu 12.04 LTS
and Ubuntu 14.04 LTS. (CVE-2014-9762)

It was discovered that Imlib2 did not properly handle some PNM images,
leading to a division by zero. An attacker could use this to cause a
denial of service (application crash). This issue only affected Ubuntu
12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-9763)

It was discovered that Imlib2 did not properly handle error conditions
when loading some GIF images. An attacker could use this to cause a
denial of service (application crash). This issue only affected Ubuntu
12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-9764).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libimlib2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libimlib2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/09");
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
if (! ereg(pattern:"^(12\.04|14\.04|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libimlib2", pkgver:"1.4.4-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libimlib2", pkgver:"1.4.6-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libimlib2", pkgver:"1.4.7-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libimlib2");
}

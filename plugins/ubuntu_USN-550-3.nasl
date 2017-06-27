#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-550-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29696);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_bugtraq_id(26650);
  script_xref(name:"USN", value:"550-3");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 / 7.10 : libcairo regression (USN-550-3)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-550-1 fixed vulnerabilities in Cairo. A bug in font glyph
rendering was uncovered as a result of the new memory allocation
routines. In certain situations, fonts containing characters with no
width or height would not render any more. This update fixes the
problem.

We apologize for the inconvenience.

Peter Valchev discovered that Cairo did not correctly decode PNG image
data. By tricking a user or automated system into processing a
specially crafted PNG with Cairo, a remote attacker could execute
arbitrary code with user privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcairo-directfb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcairo-directfb2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcairo2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcairo2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcairo2-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04|7\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04 / 7.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libcairo2", pkgver:"1.0.4-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcairo2-dev", pkgver:"1.0.4-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libcairo2-doc", pkgver:"1.0.4-0ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcairo-directfb2", pkgver:"1.2.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcairo-directfb2-dev", pkgver:"1.2.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcairo2", pkgver:"1.2.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcairo2-dev", pkgver:"1.2.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libcairo2-doc", pkgver:"1.2.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcairo-directfb2", pkgver:"1.4.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcairo-directfb2-dev", pkgver:"1.4.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcairo2", pkgver:"1.4.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcairo2-dev", pkgver:"1.4.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libcairo2-doc", pkgver:"1.4.2-0ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcairo-directfb2", pkgver:"1.4.10-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcairo-directfb2-dev", pkgver:"1.4.10-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcairo2", pkgver:"1.4.10-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcairo2-dev", pkgver:"1.4.10-1ubuntu4.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libcairo2-doc", pkgver:"1.4.10-1ubuntu4.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcairo-directfb2 / libcairo-directfb2-dev / libcairo2 / etc");
}

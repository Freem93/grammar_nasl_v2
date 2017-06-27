#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1033-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51340);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2010-3905");
  script_osvdb_id(70139);
  script_xref(name:"USN", value:"1033-1");

  script_name(english:"Ubuntu 10.10 : eucalyptus vulnerability (USN-1033-1)");
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
"It was discovered that Eucalyptus did not verify password resets from
the Admin UI correctly. An unauthenticated remote attacker could issue
password reset requests to gain admin privileges in the Eucalyptus
environment.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eucalyptus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eucalyptus-cc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eucalyptus-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eucalyptus-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eucalyptus-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eucalyptus-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eucalyptus-nc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eucalyptus-sc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:eucalyptus-walrus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uec-component-listener");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2010-2016 Canonical, Inc. / NASL script (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.10", pkgname:"eucalyptus", pkgver:"2.0+bzr1241-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"eucalyptus-cc", pkgver:"2.0+bzr1241-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"eucalyptus-cloud", pkgver:"2.0+bzr1241-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"eucalyptus-common", pkgver:"2.0+bzr1241-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"eucalyptus-gl", pkgver:"2.0+bzr1241-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"eucalyptus-java-common", pkgver:"2.0+bzr1241-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"eucalyptus-nc", pkgver:"2.0+bzr1241-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"eucalyptus-sc", pkgver:"2.0+bzr1241-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"eucalyptus-walrus", pkgver:"2.0+bzr1241-0ubuntu4.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"uec-component-listener", pkgver:"2.0+bzr1241-0ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eucalyptus / eucalyptus-cc / eucalyptus-cloud / eucalyptus-common / etc");
}

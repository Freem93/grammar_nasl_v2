#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-292-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27864);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/26 16:22:51 $");

  script_cve_id("CVE-2006-2362");
  script_osvdb_id(25711);
  script_xref(name:"USN", value:"292-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : binutils vulnerability (USN-292-1)");
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
"CVE-2006-2362

Jesus Olmos Gonzalez discovered a buffer overflow in the Tektronix Hex
Format (TekHex) backend of the BFD library, such as used by the
'strings' utility. By tricking an user or automated system into
processing a specially crafted file with 'strings' or a vulnerable
third-party application using the BFD library, this could be exploited
to crash the application, or possibly even execute arbitrary code with
the privileges of the user.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:binutils-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10|6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10 / 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"binutils", pkgver:"2.15-5ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"binutils-dev", pkgver:"2.15-5ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"binutils-doc", pkgver:"2.15-5ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"binutils-multiarch", pkgver:"2.15-5ubuntu2.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"binutils", pkgver:"2.16.1-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"binutils-dev", pkgver:"2.16.1-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"binutils-doc", pkgver:"2.16.1-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"binutils-multiarch", pkgver:"2.16.1-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"binutils-static", pkgver:"2.16.1-2ubuntu6.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"binutils", pkgver:"2.16.1cvs20060117-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"binutils-dev", pkgver:"2.16.1cvs20060117-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"binutils-doc", pkgver:"2.16.1cvs20060117-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"binutils-multiarch", pkgver:"2.16.1cvs20060117-1ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"binutils-static", pkgver:"2.16.1cvs20060117-1ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-dev / binutils-doc / binutils-multiarch / etc");
}

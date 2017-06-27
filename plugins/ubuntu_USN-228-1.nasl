#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-228-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20771);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2005-4077");
  script_xref(name:"USN", value:"228-1");

  script_name(english:"Ubuntu 4.10 / 5.04 / 5.10 : curl vulnerability (USN-228-1)");
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
"Stefan Esser discovered several buffer overflows in the handling of
URLs. By attempting to load an URL with a specially crafted invalid
hostname, a local attacker could exploit this to execute arbitrary
code with the privileges of the application that uses the cURL
library.

It is not possible to trick cURL into loading a malicious URL with an
HTTP redirect, so this vulnerability was usually not exploitable
remotely. However, it could be exploited locally to e. g. circumvent
PHP security restrictions.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl2-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-gssapi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10|5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10 / 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"curl", pkgver:"7.12.0.is.7.11.2-1ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcurl2", pkgver:"7.12.0.is.7.11.2-1ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcurl2-dbg", pkgver:"7.12.0.is.7.11.2-1ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcurl2-dev", pkgver:"7.12.0.is.7.11.2-1ubuntu0.3")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"libcurl2-gssapi", pkgver:"7.12.0.is.7.11.2-1ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"curl", pkgver:"7.12.3-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libcurl2", pkgver:"7.11.2-12ubuntu3.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libcurl2-dev", pkgver:"7.11.2-12ubuntu3.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libcurl3", pkgver:"7.12.3-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libcurl3-dbg", pkgver:"7.12.3-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libcurl3-dev", pkgver:"7.12.3-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libcurl3-gssapi", pkgver:"7.12.3-2ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"curl", pkgver:"7.14.0-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libcurl3", pkgver:"7.14.0-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libcurl3-dbg", pkgver:"7.14.0-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libcurl3-dev", pkgver:"7.14.0-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libcurl3-gssapi", pkgver:"7.14.0-2ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl2 / libcurl2-dbg / libcurl2-dev / libcurl2-gssapi / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-359-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27939);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2006-4980");
  script_osvdb_id(29366);
  script_xref(name:"USN", value:"359-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : python2.3, python2.4 vulnerability (USN-359-1)");
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
"Benjamin C. Wiley Sittler discovered that Python's repr() function did
not properly handle UTF-32/UCS-4 strings. If an application uses
repr() on arbitrary untrusted data, this could be exploited to execute
arbitrary code with the privileges of the python application.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-mpz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/16");
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

if (ubuntu_check(osver:"5.04", pkgname:"idle-python2.3", pkgver:"2.3.5-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"idle-python2.4", pkgver:"2.4.1-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3", pkgver:"2.3.5-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-dev", pkgver:"2.3.5-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-doc", pkgver:"2.3.5-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-examples", pkgver:"2.3.5-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-gdbm", pkgver:"2.3.5-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-mpz", pkgver:"2.3.5-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.3-tk", pkgver:"2.3.5-2ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4", pkgver:"2.4.1-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4-dbg", pkgver:"2.4.1-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4-dev", pkgver:"2.4.1-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4-doc", pkgver:"2.4.1-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4-examples", pkgver:"2.4.1-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4-gdbm", pkgver:"2.4.1-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4-minimal", pkgver:"2.4.1-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"python2.4-tk", pkgver:"2.4.1-0ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"idle-python2.3", pkgver:"2.3.5-8ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"idle-python2.4", pkgver:"2.4.2-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3", pkgver:"2.3.5-8ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3-dbg", pkgver:"2.3.5-8ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3-dev", pkgver:"2.3.5-8ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3-doc", pkgver:"2.3.5-8ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3-examples", pkgver:"2.3.5-8ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3-gdbm", pkgver:"2.3.5-8ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3-mpz", pkgver:"2.3.5-8ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3-tk", pkgver:"2.3.5-8ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4", pkgver:"2.4.2-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-dbg", pkgver:"2.4.2-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-dev", pkgver:"2.4.2-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-doc", pkgver:"2.4.2-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-examples", pkgver:"2.4.2-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-gdbm", pkgver:"2.4.2-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-minimal", pkgver:"2.4.2-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-tk", pkgver:"2.4.2-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"idle-python2.3", pkgver:"2.3.5-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"idle-python2.4", pkgver:"2.4.3-0ubuntu6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.3", pkgver:"2.3.5-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.3-dbg", pkgver:"2.3.5-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.3-dev", pkgver:"2.3.5-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.3-doc", pkgver:"2.3.5-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.3-examples", pkgver:"2.3.5-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.3-gdbm", pkgver:"2.3.5-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.3-mpz", pkgver:"2.3.5-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.3-tk", pkgver:"2.3.5-9ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4", pkgver:"2.4.3-0ubuntu6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-dbg", pkgver:"2.4.3-0ubuntu6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-dev", pkgver:"2.4.3-0ubuntu6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-doc", pkgver:"2.4.3-0ubuntu6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-examples", pkgver:"2.4.3-0ubuntu6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-gdbm", pkgver:"2.4.3-0ubuntu6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-minimal", pkgver:"2.4.3-0ubuntu6")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-tk", pkgver:"2.4.3-0ubuntu6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "idle-python2.3 / idle-python2.4 / python2.3 / python2.3-dbg / etc");
}

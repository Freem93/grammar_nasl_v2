#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-806-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40361);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:37:19 $");

  script_cve_id("CVE-2008-2315", "CVE-2008-4864", "CVE-2008-5031");
  script_bugtraq_id(31932, 31976, 33187);
  script_osvdb_id(47478, 50097);
  script_xref(name:"USN", value:"806-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 : python2.4, python2.5 vulnerabilities (USN-806-1)");
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
"It was discovered that Python incorrectly handled certain arguments in
the imageop module. If an attacker were able to pass specially crafted
arguments through the crop function, they could execute arbitrary code
with user privileges. For Python 2.5, this issue only affected Ubuntu
8.04 LTS. (CVE-2008-4864)

Multiple integer overflows were discovered in Python's stringobject
and unicodeobject expandtabs method. If an attacker were able to
exploit these flaws they could execute arbitrary code with user
privileges or cause Python applications to crash, leading to a denial
of service. (CVE-2008-5031).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:idle-python2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.5-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"idle-python2.4", pkgver:"2.4.3-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4", pkgver:"2.4.3-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-dbg", pkgver:"2.4.3-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-dev", pkgver:"2.4.3-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-doc", pkgver:"2.4.3-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-examples", pkgver:"2.4.3-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-gdbm", pkgver:"2.4.3-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-minimal", pkgver:"2.4.3-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-tk", pkgver:"2.4.3-0ubuntu6.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"idle-python2.4", pkgver:"2.4.5-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"idle-python2.5", pkgver:"2.5.2-2ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.4", pkgver:"2.4.5-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.4-dbg", pkgver:"2.4.5-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.4-dev", pkgver:"2.4.5-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.4-doc", pkgver:"2.4.5-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.4-examples", pkgver:"2.4.5-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.4-minimal", pkgver:"2.4.5-1ubuntu4.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.5", pkgver:"2.5.2-2ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.5-dbg", pkgver:"2.5.2-2ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.5-dev", pkgver:"2.5.2-2ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.5-doc", pkgver:"2.5.2-2ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.5-examples", pkgver:"2.5.2-2ubuntu6")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"python2.5-minimal", pkgver:"2.5.2-2ubuntu6")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"idle-python2.4", pkgver:"2.4.5-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python2.4", pkgver:"2.4.5-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python2.4-dbg", pkgver:"2.4.5-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python2.4-dev", pkgver:"2.4.5-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python2.4-doc", pkgver:"2.4.5-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python2.4-examples", pkgver:"2.4.5-5ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"python2.4-minimal", pkgver:"2.4.5-5ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "idle-python2.4 / idle-python2.5 / python2.4 / python2.4-dbg / etc");
}

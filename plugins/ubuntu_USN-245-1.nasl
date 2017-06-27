#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-245-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20792);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/26 16:22:50 $");

  script_cve_id("CVE-2006-0019");
  script_osvdb_id(22659);
  script_xref(name:"USN", value:"245-1");

  script_name(english:"Ubuntu 5.04 / 5.10 : kdelibs vulnerability (USN-245-1)");
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
"Maksim Orlovich discovered that kjs, the JavaScript interpreter engine
used by Konqueror and other parts of KDE, did not sufficiently verify
the validity of UTF-8 encoded URIs. Specially crafted URIs could
trigger a buffer overflow. By tricking an user into visiting a website
with malicious JavaScript code, a remote attacker could exploit this
to execute arbitrary code with user privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4c2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kdelibs4c2-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"kdelibs", pkgver:"3.4.0-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdelibs-bin", pkgver:"3.4.0-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdelibs-data", pkgver:"3.4.0-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdelibs4", pkgver:"3.4.0-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdelibs4-dev", pkgver:"3.4.0-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"kdelibs4-doc", pkgver:"3.4.0-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs", pkgver:"3.4.3-0ubuntu2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs-bin", pkgver:"3.4.3-0ubuntu2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs-data", pkgver:"3.4.3-0ubuntu2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs4-dev", pkgver:"3.4.3-0ubuntu2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs4-doc", pkgver:"3.4.3-0ubuntu2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs4c2", pkgver:"3.4.3-0ubuntu2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"kdelibs4c2-dbg", pkgver:"3.4.3-0ubuntu2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdelibs-bin / kdelibs-data / kdelibs4 / kdelibs4-dev / etc");
}

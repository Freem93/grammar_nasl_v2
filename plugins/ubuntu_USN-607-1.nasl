#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-607-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32187);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/01 21:21:51 $");

  script_cve_id("CVE-2007-6109", "CVE-2008-1694");
  script_osvdb_id(43372, 44566);
  script_xref(name:"USN", value:"607-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : emacs21, emacs22 vulnerabilities (USN-607-1)");
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
"It was discovered that Emacs did not account for precision when
formatting integers. If a user were tricked into opening a specially
crafted file, an attacker could cause a denial of service or possibly
other unspecified actions. This issue does not affect Ubuntu 8.04.
(CVE-2007-6109)

Steve Grubb discovered that the vcdiff script as included in Emacs
created temporary files in an insecure way when used with SCCS. Local
users could exploit a race condition to create or overwrite files with
the privileges of the user invoking the program. (CVE-2008-1694).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(59, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs21-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs21-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs21-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs21-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22-nox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"emacs21", pkgver:"21.4a-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"emacs21-bin-common", pkgver:"21.4a-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"emacs21-common", pkgver:"21.4a-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"emacs21-el", pkgver:"21.4a-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"emacs21-nox", pkgver:"21.4a-3ubuntu2.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs", pkgver:"21.4a+1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs-el", pkgver:"21.4a+1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs-nox", pkgver:"21.4a+1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs21", pkgver:"21.4a+1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs21-bin-common", pkgver:"21.4a+1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs21-common", pkgver:"21.4a+1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs21-el", pkgver:"21.4a+1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs21-nox", pkgver:"21.4a+1-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs", pkgver:"22.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs-el", pkgver:"21.4a+1-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs-nox", pkgver:"21.4a+1-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs21", pkgver:"21.4a+1-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs21-bin-common", pkgver:"21.4a+1-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs21-common", pkgver:"21.4a+1-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs21-el", pkgver:"21.4a+1-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs21-nox", pkgver:"21.4a+1-5ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs22", pkgver:"22.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs22-bin-common", pkgver:"22.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs22-common", pkgver:"22.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs22-el", pkgver:"22.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs22-gtk", pkgver:"22.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"emacs22-nox", pkgver:"22.1-0ubuntu5.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs", pkgver:"22.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs21", pkgver:"21.4a+1-5.3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs21-bin-common", pkgver:"21.4a+1-5.3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs21-common", pkgver:"21.4a+1-5.3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs21-el", pkgver:"21.4a+1-5.3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs21-nox", pkgver:"21.4a+1-5.3ubuntu1.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22", pkgver:"22.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22-bin-common", pkgver:"22.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22-common", pkgver:"22.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22-el", pkgver:"22.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22-gtk", pkgver:"22.1-0ubuntu10.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22-nox", pkgver:"22.1-0ubuntu10.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs / emacs-el / emacs-nox / emacs21 / emacs21-bin-common / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-919-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45377);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:45:43 $");

  script_cve_id("CVE-2010-0825");
  script_osvdb_id(63430);
  script_xref(name:"USN", value:"919-1");

  script_name(english:"Ubuntu 8.04 LTS / 8.10 / 9.04 / 9.10 : emacs22, emacs23 vulnerability (USN-919-1)");
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
"Dan Rosenberg discovered that the email helper in Emacs did not
correctly check file permissions. A local attacker could perform a
symlink race to read or append to another user's mailbox if it was
stored under a group-writable group-'mail' directory.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs22-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs23-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs23-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs23-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs23-lucid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs23-nox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/30");
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
if (! ereg(pattern:"^(8\.04|8\.10|9\.04|9\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 8.10 / 9.04 / 9.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"emacs", pkgver:"22.1-0ubuntu10.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22", pkgver:"22.1-0ubuntu10.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22-bin-common", pkgver:"22.1-0ubuntu10.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22-common", pkgver:"22.1-0ubuntu10.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22-el", pkgver:"22.1-0ubuntu10.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22-gtk", pkgver:"22.1-0ubuntu10.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"emacs22-nox", pkgver:"22.1-0ubuntu10.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"emacs", pkgver:"22.2-0ubuntu2.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"emacs22", pkgver:"22.2-0ubuntu2.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"emacs22-bin-common", pkgver:"22.2-0ubuntu2.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"emacs22-common", pkgver:"22.2-0ubuntu2.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"emacs22-el", pkgver:"22.2-0ubuntu2.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"emacs22-gtk", pkgver:"22.2-0ubuntu2.8.10.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"emacs22-nox", pkgver:"22.2-0ubuntu2.8.10.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"emacs", pkgver:"22.2-0ubuntu2.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"emacs22", pkgver:"22.2-0ubuntu2.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"emacs22-bin-common", pkgver:"22.2-0ubuntu2.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"emacs22-common", pkgver:"22.2-0ubuntu2.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"emacs22-el", pkgver:"22.2-0ubuntu2.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"emacs22-gtk", pkgver:"22.2-0ubuntu2.9.04.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"emacs22-nox", pkgver:"22.2-0ubuntu2.9.04.1")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs", pkgver:"23.1+1-4ubuntu2+22.2+0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs22", pkgver:"22.2-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs22-bin-common", pkgver:"22.2-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs22-common", pkgver:"22.2-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs22-el", pkgver:"22.2-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs22-gtk", pkgver:"22.2-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs22-nox", pkgver:"22.2-0ubuntu6.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs23", pkgver:"23.1+1-4ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs23-bin-common", pkgver:"23.1+1-4ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs23-common", pkgver:"23.1+1-4ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs23-el", pkgver:"23.1+1-4ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs23-lucid", pkgver:"23.1+1-4ubuntu3.2")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"emacs23-nox", pkgver:"23.1+1-4ubuntu3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs / emacs22 / emacs22-bin-common / emacs22-common / emacs22-el / etc");
}

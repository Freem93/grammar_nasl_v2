#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-504-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28108);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:29:18 $");

  script_cve_id("CVE-2007-2833");
  script_bugtraq_id(24570);
  script_osvdb_id(37512);
  script_xref(name:"USN", value:"504-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : emacs21 vulnerability (USN-504-1)");
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
"Hendrik Tews discovered that emacs21 did not correctly handle certain
GIF images. By tricking a user into opening a specially crafted GIF, a
remote attacker could cause emacs21 to crash, resulting in a denial of
service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs21-bin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs21-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs21-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:emacs21-nox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/29");
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
if (! ereg(pattern:"^(6\.06|6\.10|7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 6.10 / 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"emacs21", pkgver:"21.4a-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"emacs21-bin-common", pkgver:"21.4a-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"emacs21-common", pkgver:"21.4a-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"emacs21-el", pkgver:"21.4a-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"emacs21-nox", pkgver:"21.4a-3ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"emacs21", pkgver:"21.4a-6ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"emacs21-bin-common", pkgver:"21.4a-6ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"emacs21-common", pkgver:"21.4a-6ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"emacs21-el", pkgver:"21.4a-6ubuntu2.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"emacs21-nox", pkgver:"21.4a-6ubuntu2.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs", pkgver:"21.4a+1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs-el", pkgver:"21.4a+1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs-nox", pkgver:"21.4a+1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs21", pkgver:"21.4a+1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs21-bin-common", pkgver:"21.4a+1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs21-common", pkgver:"21.4a+1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs21-el", pkgver:"21.4a+1-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"emacs21-nox", pkgver:"21.4a+1-2ubuntu1.1")) flag++;

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

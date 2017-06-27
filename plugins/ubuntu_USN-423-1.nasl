#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-423-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28015);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:17 $");

  script_cve_id("CVE-2007-0901", "CVE-2007-0902");
  script_osvdb_id(33172, 33173);
  script_xref(name:"USN", value:"423-1");

  script_name(english:"Ubuntu 5.10 / 6.06 LTS / 6.10 : moin, moin1.3 vulnerabilities (USN-423-1)");
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
"A flaw was discovered in MoinMoin's debug reporting sanitizer which
could lead to a cross-site scripting attack. By tricking a user into
viewing a crafted MoinMoin URL, an attacker could execute arbitrary
JavaScript as the current MoinMoin user, possibly exposing the user's
authentication information for the domain where MoinMoin was hosted.
Only Ubuntu Breezy was vulnerable. (CVE-2007-0901)

An information leak was discovered in MoinMoin's debug reporting,
which could expose information about the versions of software running
on the host system. MoinMoin administrators can add 'show_traceback=0'
to their site configurations to disable debug tracebacks.
(CVE-2007-0902).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:moin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:moinmoin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-moinmoin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.3-moinmoin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.4-moinmoin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/12");
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
if (! ereg(pattern:"^(5\.10|6\.06|6\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.10 / 6.06 / 6.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.10", pkgname:"moin", pkgver:"1.2.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"moinmoin-common", pkgver:"1.3.4-6ubuntu1.5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python-moinmoin", pkgver:"1.3.4-6ubuntu1.5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.3-moinmoin", pkgver:"1.3.4-6ubuntu1.5.10")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"python2.4-moinmoin", pkgver:"1.3.4-6ubuntu1.5.10")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"moinmoin-common", pkgver:"1.5.2-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python-moinmoin", pkgver:"1.5.2-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"python2.4-moinmoin", pkgver:"1.5.2-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"moinmoin-common", pkgver:"1.5.3-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python-moinmoin", pkgver:"1.5.3-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"python2.4-moinmoin", pkgver:"1.5.3-1ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "moin / moinmoin-common / python-moinmoin / python2.3-moinmoin / etc");
}

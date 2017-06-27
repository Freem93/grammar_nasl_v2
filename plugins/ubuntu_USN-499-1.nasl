#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-499-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28102);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/30 15:10:04 $");

  script_cve_id("CVE-2006-5752", "CVE-2007-1863", "CVE-2007-3303", "CVE-2007-3304");
  script_osvdb_id(37050, 37052, 37079, 38939);
  script_xref(name:"USN", value:"499-1");

  script_name(english:"Ubuntu 6.06 LTS / 6.10 / 7.04 : apache2 vulnerabilities (USN-499-1)");
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
"Stefan Esser discovered that mod_status did not force a character set,
which could result in browsers becoming vulnerable to XSS attacks when
processing the output. If a user were tricked into viewing server
status output during a crafted server request, a remote attacker could
exploit this to modify the contents, or steal confidential data (such
as passwords), within the same domain. By default, mod_status is
disabled in Ubuntu. (CVE-2006-5752)

Niklas Edmundsson discovered that the mod_cache module could be made
to crash using a specially crafted request. A remote user could use
this to cause a denial of service if Apache was configured to use a
threaded worker. By default, mod_cache is disabled in Ubuntu.
(CVE-2007-1863)

A flaw was discovered in the signal handling of Apache. A local
attacker could trick Apache into sending SIGUSR1 to other processes.
The vulnerable code was only present in Ubuntu Feisty. (CVE-2007-3304).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-perchild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-mpm-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-prefork-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-threaded-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apache2.2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapr0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2017 Canonical, Inc. / NASL script (C) 2007-2017 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"6.06", pkgname:"apache2", pkgver:"2.0.55-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-common", pkgver:"2.0.55-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-doc", pkgver:"2.0.55-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-mpm-perchild", pkgver:"2.0.55-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-mpm-prefork", pkgver:"2.0.55-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-mpm-worker", pkgver:"2.0.55-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-prefork-dev", pkgver:"2.0.55-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-threaded-dev", pkgver:"2.0.55-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"apache2-utils", pkgver:"2.0.55-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libapr0", pkgver:"2.0.55-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libapr0-dev", pkgver:"2.0.55-4ubuntu2.2")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"apache2", pkgver:"2.0.55-4ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"apache2-common", pkgver:"2.0.55-4ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"apache2-doc", pkgver:"2.0.55-4ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"apache2-mpm-perchild", pkgver:"2.0.55-4ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"apache2-mpm-prefork", pkgver:"2.0.55-4ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"apache2-mpm-worker", pkgver:"2.0.55-4ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"apache2-prefork-dev", pkgver:"2.0.55-4ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"apache2-threaded-dev", pkgver:"2.0.55-4ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"apache2-utils", pkgver:"2.0.55-4ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libapr0", pkgver:"2.0.55-4ubuntu4.1")) flag++;
if (ubuntu_check(osver:"6.10", pkgname:"libapr0-dev", pkgver:"2.0.55-4ubuntu4.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"apache2", pkgver:"2.2.3-3.2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"apache2-doc", pkgver:"2.2.3-3.2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"apache2-mpm-event", pkgver:"2.2.3-3.2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"apache2-mpm-perchild", pkgver:"2.2.3-3.2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"apache2-mpm-prefork", pkgver:"2.2.3-3.2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"apache2-mpm-worker", pkgver:"2.2.3-3.2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"apache2-prefork-dev", pkgver:"2.2.3-3.2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"apache2-src", pkgver:"2.2.3-3.2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"apache2-threaded-dev", pkgver:"2.2.3-3.2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"apache2-utils", pkgver:"2.2.3-3.2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"apache2.2-common", pkgver:"2.2.3-3.2ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-common / apache2-doc / apache2-mpm-event / etc");
}

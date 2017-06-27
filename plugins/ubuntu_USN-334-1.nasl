#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-334-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27913);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2006-3083", "CVE-2006-3084");
  script_bugtraq_id(19427);
  script_osvdb_id(27869, 27870, 27871, 27872);
  script_xref(name:"USN", value:"334-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : krb5 vulnerabilities (USN-334-1)");
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
"Michael Calmer and Marcus Meissner discovered that several krb5 tools
did not check the return values from setuid() system calls. On systems
that have configured user process limits, it may be possible for an
attacker to cause setuid() to fail via resource starvation. In that
situation, the tools will not reduce their privilege levels, and will
continue operation as the root user.

By default, Ubuntu does not ship with user process limits.

Please note that these packages are not officially supported by Ubuntu
(they are in the 'universe' component of the archive).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-ftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-rsh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-telnetd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkadm55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkrb53");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/08");
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

if (ubuntu_check(osver:"5.04", pkgname:"krb5-admin-server", pkgver:"1.3.6-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-clients", pkgver:"1.3.6-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-doc", pkgver:"1.3.6-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-ftpd", pkgver:"1.3.6-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-kdc", pkgver:"1.3.6-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-rsh-server", pkgver:"1.3.6-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-telnetd", pkgver:"1.3.6-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"krb5-user", pkgver:"1.3.6-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkadm55", pkgver:"1.3.6-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkrb5-dev", pkgver:"1.3.6-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libkrb53", pkgver:"1.3.6-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krb5-admin-server", pkgver:"1.3.6-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krb5-clients", pkgver:"1.3.6-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krb5-doc", pkgver:"1.3.6-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krb5-ftpd", pkgver:"1.3.6-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krb5-kdc", pkgver:"1.3.6-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krb5-rsh-server", pkgver:"1.3.6-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krb5-telnetd", pkgver:"1.3.6-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"krb5-user", pkgver:"1.3.6-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkadm55", pkgver:"1.3.6-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkrb5-dev", pkgver:"1.3.6-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libkrb53", pkgver:"1.3.6-4ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-admin-server", pkgver:"1.4.3-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-clients", pkgver:"1.4.3-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-doc", pkgver:"1.4.3-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-ftpd", pkgver:"1.4.3-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-kdc", pkgver:"1.4.3-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-rsh-server", pkgver:"1.4.3-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-telnetd", pkgver:"1.4.3-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"krb5-user", pkgver:"1.4.3-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkadm55", pkgver:"1.4.3-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkrb5-dev", pkgver:"1.4.3-5ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libkrb53", pkgver:"1.4.3-5ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-admin-server / krb5-clients / krb5-doc / krb5-ftpd / krb5-kdc / etc");
}

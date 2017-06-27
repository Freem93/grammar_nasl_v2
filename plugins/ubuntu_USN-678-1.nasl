#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-678-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(37965);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/27 14:37:17 $");

  script_cve_id("CVE-2008-4989");
  script_xref(name:"USN", value:"678-1");

  script_name(english:"Ubuntu 6.06 LTS / 7.10 / 8.04 LTS / 8.10 : gnutls12, gnutls13, gnutls26 vulnerability (USN-678-1)");
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
"Martin von Gagern discovered that GnuTLS did not properly verify
certificate chains when the last certificate in the chain was
self-signed. If a remote attacker were able to perform a
man-in-the-middle attack, this flaw could be exploited to view
sensitive information. (CVE-2008-4989).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnutls-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnutls-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:guile-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls12-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls13-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls26-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutlsxx13");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.10|8\.04|8\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.10 / 8.04 / 8.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"gnutls-bin", pkgver:"1.2.9-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgnutls-dev", pkgver:"1.2.9-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgnutls12", pkgver:"1.2.9-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgnutls12-dbg", pkgver:"1.2.9-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gnutls-bin", pkgver:"1.6.3-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"gnutls-doc", pkgver:"1.6.3-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgnutls-dev", pkgver:"1.6.3-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgnutls13", pkgver:"1.6.3-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgnutls13-dbg", pkgver:"1.6.3-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"libgnutlsxx13", pkgver:"1.6.3-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gnutls-bin", pkgver:"2.0.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"gnutls-doc", pkgver:"2.0.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgnutls-dev", pkgver:"2.0.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgnutls13", pkgver:"2.0.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgnutls13-dbg", pkgver:"2.0.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libgnutlsxx13", pkgver:"2.0.4-1ubuntu2.2")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gnutls-bin", pkgver:"2.4.1-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"gnutls-doc", pkgver:"2.4.1-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"guile-gnutls", pkgver:"2.4.1-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgnutls-dev", pkgver:"2.4.1-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgnutls26", pkgver:"2.4.1-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libgnutls26-dbg", pkgver:"2.4.1-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls-bin / gnutls-doc / guile-gnutls / libgnutls-dev / etc");
}

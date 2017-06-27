#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-790-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39515);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:37:19 $");

  script_cve_id("CVE-2009-0688");
  script_xref(name:"USN", value:"790-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : cyrus-sasl2 vulnerability (USN-790-1)");
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
"James Ralston discovered that the Cyrus SASL base64 encoding function
could be used unsafely. If a remote attacker sent a specially crafted
request to a service that used SASL, it could lead to a loss of
privacy, or crash the application, resulting in a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cyrus-sasl2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cyrus-sasl2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules-gssapi-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules-gssapi-mit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsasl2-modules-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sasl2-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/25");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libsasl2", pkgver:"2.1.19.dfsg1-0.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsasl2-dev", pkgver:"2.1.19.dfsg1-0.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsasl2-modules", pkgver:"2.1.19.dfsg1-0.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsasl2-modules-gssapi-heimdal", pkgver:"2.1.19.dfsg1-0.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libsasl2-modules-sql", pkgver:"2.1.19.dfsg1-0.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"sasl2-bin", pkgver:"2.1.19.dfsg1-0.1ubuntu3.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cyrus-sasl2-dbg", pkgver:"2.1.22.dfsg1-18ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"cyrus-sasl2-doc", pkgver:"2.1.22.dfsg1-18ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsasl2", pkgver:"2.1.22.dfsg1-18ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsasl2-2", pkgver:"2.1.22.dfsg1-18ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsasl2-dev", pkgver:"2.1.22.dfsg1-18ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsasl2-modules", pkgver:"2.1.22.dfsg1-18ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsasl2-modules-gssapi-mit", pkgver:"2.1.22.dfsg1-18ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsasl2-modules-ldap", pkgver:"2.1.22.dfsg1-18ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsasl2-modules-otp", pkgver:"2.1.22.dfsg1-18ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libsasl2-modules-sql", pkgver:"2.1.22.dfsg1-18ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"sasl2-bin", pkgver:"2.1.22.dfsg1-18ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cyrus-sasl2-dbg", pkgver:"2.1.22.dfsg1-21ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"cyrus-sasl2-doc", pkgver:"2.1.22.dfsg1-21ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsasl2-2", pkgver:"2.1.22.dfsg1-21ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsasl2-dev", pkgver:"2.1.22.dfsg1-21ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsasl2-modules", pkgver:"2.1.22.dfsg1-21ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsasl2-modules-gssapi-mit", pkgver:"2.1.22.dfsg1-21ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsasl2-modules-ldap", pkgver:"2.1.22.dfsg1-21ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsasl2-modules-otp", pkgver:"2.1.22.dfsg1-21ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"libsasl2-modules-sql", pkgver:"2.1.22.dfsg1-21ubuntu2.1")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"sasl2-bin", pkgver:"2.1.22.dfsg1-21ubuntu2.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cyrus-sasl2-dbg", pkgver:"2.1.22.dfsg1-23ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"cyrus-sasl2-doc", pkgver:"2.1.22.dfsg1-23ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsasl2-2", pkgver:"2.1.22.dfsg1-23ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsasl2-dev", pkgver:"2.1.22.dfsg1-23ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsasl2-modules", pkgver:"2.1.22.dfsg1-23ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsasl2-modules-gssapi-mit", pkgver:"2.1.22.dfsg1-23ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsasl2-modules-ldap", pkgver:"2.1.22.dfsg1-23ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsasl2-modules-otp", pkgver:"2.1.22.dfsg1-23ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"libsasl2-modules-sql", pkgver:"2.1.22.dfsg1-23ubuntu3.1")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"sasl2-bin", pkgver:"2.1.22.dfsg1-23ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-sasl2-dbg / cyrus-sasl2-doc / libsasl2 / libsasl2-2 / etc");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-348-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27928);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/27 14:21:17 $");

  script_cve_id("CVE-2006-4790");
  script_bugtraq_id(20027);
  script_osvdb_id(28778);
  script_xref(name:"USN", value:"348-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : gnutls11, gnutls12 vulnerability (USN-348-1)");
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
"The GnuTLS library did not sufficiently check the padding of PKCS #1
v1.5 signatures if the exponent of the public key is 3 (which is
widely used for CAs). This could be exploited to forge signatures
without the need of the secret key.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnutls-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls11-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgnutls12-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/08");
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

if (ubuntu_check(osver:"5.04", pkgname:"gnutls-bin", pkgver:"1.0.16-13ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgnutls11", pkgver:"1.0.16-13ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgnutls11-dbg", pkgver:"1.0.16-13ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libgnutls11-dev", pkgver:"1.0.16-13ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"gnutls-bin", pkgver:"1.0.16-13.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgnutls11", pkgver:"1.0.16-13.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgnutls11-dbg", pkgver:"1.0.16-13.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libgnutls11-dev", pkgver:"1.0.16-13.1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"gnutls-bin", pkgver:"1.2.9-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgnutls-dev", pkgver:"1.2.9-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgnutls11", pkgver:"1.0.16-14ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgnutls11-dbg", pkgver:"1.0.16-14ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgnutls11-dev", pkgver:"1.0.16-14ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgnutls12", pkgver:"1.2.9-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libgnutls12-dbg", pkgver:"1.2.9-2ubuntu1.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls-bin / libgnutls-dev / libgnutls11 / libgnutls11-dbg / etc");
}

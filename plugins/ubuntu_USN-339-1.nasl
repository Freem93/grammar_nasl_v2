#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-339-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27918);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/02/17 15:06:27 $");

  script_cve_id("CVE-2006-4339", "CVE-2006-5201", "CVE-2006-7140");
  script_osvdb_id(28549);
  script_xref(name:"USN", value:"339-1");

  script_name(english:"Ubuntu 5.04 / 5.10 / 6.06 LTS : openssl vulnerability (USN-339-1)");
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
"Philip Mackenzie, Marius Schilder, Jason Waddle and Ben Laurie of
Google Security discovered that the OpenSSL library did not
sufficiently check the padding of PKCS #1 v1.5 signatures if the
exponent of the public key is 3 (which is widely used for CAs). This
could be exploited to forge signatures without the need of the secret
key.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libssl0.9.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2017 Canonical, Inc. / NASL script (C) 2007-2017 Tenable Network Security, Inc.");
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

if (ubuntu_check(osver:"5.04", pkgname:"libssl-dev", pkgver:"0.9.7e-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libssl0.9.7", pkgver:"0.9.7e-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"openssl", pkgver:"0.9.7e-3ubuntu0.3")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libssl-dev", pkgver:"0.9.7g-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"libssl0.9.7", pkgver:"0.9.7g-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"openssl", pkgver:"0.9.7g-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libssl-dev", pkgver:"0.9.8a-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libssl0.9.8", pkgver:"0.9.8a-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"libssl0.9.8-dbg", pkgver:"0.9.8a-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"openssl", pkgver:"0.9.8a-7ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssl-dev / libssl0.9.7 / libssl0.9.8 / libssl0.9.8-dbg / openssl");
}

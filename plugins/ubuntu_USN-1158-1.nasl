#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1158-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55414);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/26 16:14:08 $");

  script_cve_id("CVE-2009-2417", "CVE-2010-0734", "CVE-2011-2192");
  script_osvdb_id(56994, 62217, 73328, 73686);
  script_xref(name:"USN", value:"1158-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 : curl vulnerabilities (USN-1158-1)");
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
"Richard Silverman discovered that when doing GSSAPI authentication,
libcurl unconditionally performs credential delegation, handing the
server a copy of the client's security credential. (CVE-2011-2192)

Wesley Miaw discovered that when zlib is enabled, libcurl does not
properly restrict the amount of callback data sent to an application
that requests automatic decompression. This might allow an attacker to
cause a denial of service via an application crash or possibly execute
arbitrary code with the privilege of the application. This issue only
affected Ubuntu 8.04 LTS and Ubuntu 10.04 LTS. (CVE-2010-0734)

USN 818-1 fixed an issue with curl's handling of SSL certificates with
zero bytes in the Common Name. Due to a packaging error, the fix for
this issue was not being applied during the build. This issue only
affected Ubuntu 8.04 LTS. We apologize for the error. (CVE-2009-2417)

Scott Cantor discovered that curl did not correctly handle SSL
certificates with zero bytes in the Common Name. A remote attacker
could exploit this to perform a man in the middle attack to view
sensitive information or alter encrypted communications.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libcurl3, libcurl3-gnutls and / or libcurl3-nss
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcurl3-nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2016 Canonical, Inc. / NASL script (C) 2011-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libcurl3", pkgver:"7.18.0-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libcurl3-gnutls", pkgver:"7.18.0-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libcurl3", pkgver:"7.19.7-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libcurl3-gnutls", pkgver:"7.19.7-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcurl3", pkgver:"7.21.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libcurl3-gnutls", pkgver:"7.21.0-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libcurl3", pkgver:"7.21.3-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libcurl3-gnutls", pkgver:"7.21.3-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libcurl3-nss", pkgver:"7.21.3-1ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcurl3 / libcurl3-gnutls / libcurl3-nss");
}

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-612-8. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32431);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/27 14:29:19 $");

  script_bugtraq_id(29179);
  script_xref(name:"USN", value:"612-8");

  script_name(english:"Ubuntu 6.06 LTS / 7.04 / 7.10 / 8.04 LTS : openssl-blacklist update (USN-612-8)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"USN-612-3 addressed a weakness in OpenSSL certificate and key
generation in OpenVPN by introducing openssl-blacklist to aid in
detecting vulnerable private keys. This update enhances the
openssl-vulnkey tool to check X.509 certificates as well, and provides
the corresponding update for Ubuntu 6.06. While the OpenSSL in Ubuntu
6.06 was not vulnerable, openssl-blacklist is now provided for Ubuntu
6.06 for checking certificates and keys that may have been imported on
these systems.

This update also includes the complete RSA-1024 and RSA-2048
blacklists for all Ubuntu architectures, as well as support for other
future blacklists for non-standard bit lengths.

You can check for weak SSL/TLS certificates by installing
openssl-blacklist via your package manager, and using the
openssl-vulnkey command.

$ openssl-vulnkey /path/to/certificate_or_key

This command can be used on public certificates and private keys for
any X.509 certificate or RSA key, including ones for web servers, mail
servers, OpenVPN, and others. If in doubt, destroy the certificate and
key and generate new ones. Please consult the documentation for your
software when recreating SSL/TLS certificates. Also, if certificates
have been generated for use on other systems, they must be found and
replaced as well.

A weakness has been discovered in the random number generator used by
OpenSSL on Debian and Ubuntu systems. As a result of this weakness,
certain encryption keys are much more common than they should be, such
that an attacker could guess the key through a brute-force attack
given minimal knowledge of the system. This particularly affects the
use of encryption keys in OpenSSH, OpenVPN and SSL certificates.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl-blacklist package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openssl-blacklist");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2008-2016 Canonical, Inc. / NASL script (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.06|7\.04|7\.10|8\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 7.04 / 7.10 / 8.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"openssl-blacklist", pkgver:"0.1-0ubuntu0.6.06.1")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"openssl-blacklist", pkgver:"0.1-0ubuntu0.7.04.4")) flag++;
if (ubuntu_check(osver:"7.10", pkgname:"openssl-blacklist", pkgver:"0.1-0ubuntu0.7.10.4")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"openssl-blacklist", pkgver:"0.1-0ubuntu0.8.04.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl-blacklist");
}

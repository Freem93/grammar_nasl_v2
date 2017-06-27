#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1126-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55086);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/27 14:13:23 $");

  script_cve_id("CVE-2006-7243", "CVE-2010-4697", "CVE-2010-4698", "CVE-2011-0420", "CVE-2011-0421", "CVE-2011-0441", "CVE-2011-0708", "CVE-2011-1072", "CVE-2011-1092", "CVE-2011-1144", "CVE-2011-1148", "CVE-2011-1153", "CVE-2011-1464", "CVE-2011-1466", "CVE-2011-1467", "CVE-2011-1468", "CVE-2011-1469", "CVE-2011-1470", "CVE-2011-1471");
  script_bugtraq_id(44951, 45338, 45952, 46354, 46365, 46429, 46605, 46786, 46843, 46854, 46928, 46967, 46968, 46969, 46970, 46975, 46977);
  script_osvdb_id(70606, 70607, 70608, 71597, 71598, 72531, 72532, 72533, 73218, 73275, 73622, 73623, 73624, 73625, 73626, 73706, 73754, 73755, 75083);
  script_xref(name:"USN", value:"1126-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 / 11.04 : php5 vulnerabilities (USN-1126-1)");
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
"Stephane Chazelas discovered that the /etc/cron.d/php5 cron job for
PHP 5.3.5 allows local users to delete arbitrary files via a symlink
attack on a directory under /var/lib/php5/. (CVE-2011-0441)

Raphael Geisert and Dan Rosenberg discovered that the PEAR installer
allows local users to overwrite arbitrary files via a symlink attack
on the package.xml file, related to the (1) download_dir, (2)
cache_dir, (3) tmp_dir, and (4) pear-build-download directories.
(CVE-2011-1072, CVE-2011-1144)

Ben Schmidt discovered that a use-after-free vulnerability in the PHP
Zend engine could allow an attacker to cause a denial of service (heap
memory corruption) or possibly execute arbitrary code. (CVE-2010-4697)

Martin Barbella discovered a buffer overflow in the PHP GD extension
that allows an attacker to cause a denial of service (application
crash) via a large number of anti- aliasing steps in an argument to
the imagepstext function. (CVE-2010-4698)

It was discovered that PHP accepts the \0 character in a pathname,
which might allow an attacker to bypass intended access restrictions
by placing a safe file extension after this character. This issue is
addressed in Ubuntu 10.04 LTS, Ubuntu 10.10, and Ubuntu 11.04.
(CVE-2006-7243)

Maksymilian Arciemowicz discovered that the grapheme_extract function
in the PHP Internationalization extension (Intl) for ICU allow an
attacker to cause a denial of service (crash) via an invalid size
argument, which triggers a NULL pointer dereference. This issue
affected Ubuntu 10.04 LTS, Ubuntu 10.10, and Ubuntu 11.04.
(CVE-2011-0420)

Maksymilian Arciemowicz discovered that the _zip_name_locate function
in the PHP Zip extension does not properly handle a
ZIPARCHIVE::FL_UNCHANGED argument, which might allow an attacker to
cause a denial of service (NULL pointer dereference) via an empty ZIP
archive. This issue affected Ubuntu 8.04 LTS, Ubuntu 9.10, Ubuntu
10.04 LTS, Ubuntu 10.10, and Ubuntu 11.04. (CVE-2011-0421)

Luca Carettoni discovered that the PHP Exif extension performs an
incorrect cast on 64bit platforms, which allows a remote attacker to
cause a denial of service (application crash) via an image with a
crafted Image File Directory (IFD). (CVE-2011-0708)

Jose Carlos Norte discovered that an integer overflow in the PHP shmop
extension could allow an attacker to cause a denial of service (crash)
and possibly read sensitive memory function. (CVE-2011-1092)

Felipe Pena discovered that a use-after-free vulnerability in the
substr_replace function allows an attacker to cause a denial of
service (memory corruption) or possibly execute arbitrary code.
(CVE-2011-1148)

Felipe Pena discovered multiple format string vulnerabilities in the
PHP phar extension. These could allow an attacker to obtain sensitive
information from process memory, cause a denial of service (memory
corruption), or possibly execute arbitrary code. This issue affected
Ubuntu 10.04 LTS, Ubuntu 10.10, and Ubuntu 11.04.(CVE-2011-1153)

It was discovered that a buffer overflow occurs in the strval function
when the precision configuration option has a large value. The default
compiler options for Ubuntu 8.04 LTS, Ubuntu 9.10, Ubuntu 10.04 LTS,
Ubuntu 10.10, and Ubuntu 11.04 should reduce the vulnerability to a
denial of service. (CVE-2011-1464)

It was discovered that an integer overflow in the SdnToJulian function
in the PHP Calendar extension could allow an attacker to cause a
denial of service (application crash). (CVE-2011-1466)

Tomas Hoger discovered that an integer overflow in the
NumberFormatter::setSymbol function in the PHP Intl extension could
allow an attacker to cause a denial of service (application crash).
This issue affected Ubuntu 10.04 LTS, Ubuntu 10.10, and Ubuntu 11.04.
(CVE-2011-1467)

It was discovered that multiple memory leaks in the PHP OpenSSL
extension might allow a remote attacker to cause a denial of service
(memory consumption). This issue affected Ubuntu 10.04 LTS, Ubuntu
10.10, and Ubuntu 11.04. (CVE-2011-1468)

Daniel Buschke discovered that the PHP Streams component in PHP
handled types improperly, possibly allowing an attacker to cause a
denial of service (application crash). (CVE-2011-1469)

It was discovered that the PHP Zip extension could allow an attacker
to cause a denial of service (application crash) via a ziparchive
stream that is not properly handled by the stream_get_contents
function. This issue affected Ubuntu 8.04 LTS, Ubuntu 9.10, Ubuntu
10.04 LTS, Ubuntu 10.10, and Ubuntu 11.04. (CVE-2011-1470)

It was discovered that an integer signedness error in the PHP Zip
extension could allow an attacker to cause a denial of service (CPU
consumption) via a malformed archive file. This issue affected Ubuntu
8.04 LTS, Ubuntu 9.10, Ubuntu 10.04 LTS, Ubuntu 10.10, and Ubuntu
11.04. (CVE-2011-1470) (CVE-2011-1471).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-intl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/13");
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
if (! ereg(pattern:"^(6\.06|8\.04|9\.10|10\.04|10\.10|11\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 9.10 / 10.04 / 10.10 / 11.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"libapache2-mod-php5", pkgver:"5.1.2-1ubuntu3.22")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php-pear", pkgver:"5.1.2-1ubuntu3.22")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5", pkgver:"5.1.2-1ubuntu3.22")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cgi", pkgver:"5.1.2-1ubuntu3.22")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-cli", pkgver:"5.1.2-1ubuntu3.22")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-common", pkgver:"5.1.2-1ubuntu3.22")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-curl", pkgver:"5.1.2-1ubuntu3.22")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-dev", pkgver:"5.1.2-1ubuntu3.22")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"php5-gd", pkgver:"5.1.2-1ubuntu3.22")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"libapache2-mod-php5", pkgver:"5.2.4-2ubuntu5.15")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php-pear", pkgver:"5.2.4-2ubuntu5.15")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5", pkgver:"5.2.4-2ubuntu5.15")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cgi", pkgver:"5.2.4-2ubuntu5.15")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cli", pkgver:"5.2.4-2ubuntu5.15")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-common", pkgver:"5.2.4-2ubuntu5.15")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-curl", pkgver:"5.2.4-2ubuntu5.15")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-dev", pkgver:"5.2.4-2ubuntu5.15")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-gd", pkgver:"5.2.4-2ubuntu5.15")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"libapache2-mod-php5", pkgver:"5.2.10.dfsg.1-2ubuntu6.9")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php-pear", pkgver:"5.2.10.dfsg.1-2ubuntu6.9")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5", pkgver:"5.2.10.dfsg.1-2ubuntu6.9")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-cgi", pkgver:"5.2.10.dfsg.1-2ubuntu6.9")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-cli", pkgver:"5.2.10.dfsg.1-2ubuntu6.9")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-common", pkgver:"5.2.10.dfsg.1-2ubuntu6.9")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-curl", pkgver:"5.2.10.dfsg.1-2ubuntu6.9")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-dev", pkgver:"5.2.10.dfsg.1-2ubuntu6.9")) flag++;
if (ubuntu_check(osver:"9.10", pkgname:"php5-gd", pkgver:"5.2.10.dfsg.1-2ubuntu6.9")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.2-1ubuntu4.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php-pear", pkgver:"5.3.2-1ubuntu4.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5", pkgver:"5.3.2-1ubuntu4.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cgi", pkgver:"5.3.2-1ubuntu4.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cli", pkgver:"5.3.2-1ubuntu4.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-common", pkgver:"5.3.2-1ubuntu4.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-curl", pkgver:"5.3.2-1ubuntu4.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-dev", pkgver:"5.3.2-1ubuntu4.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-gd", pkgver:"5.3.2-1ubuntu4.8")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-intl", pkgver:"5.3.2-1ubuntu4.8")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libapache2-mod-php5", pkgver:"5.3.3-1ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php-pear", pkgver:"5.3.3-1ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5", pkgver:"5.3.3-1ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-cgi", pkgver:"5.3.3-1ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-cli", pkgver:"5.3.3-1ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-common", pkgver:"5.3.3-1ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-curl", pkgver:"5.3.3-1ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-dev", pkgver:"5.3.3-1ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-gd", pkgver:"5.3.3-1ubuntu9.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-intl", pkgver:"5.3.3-1ubuntu9.4")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.5-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php-pear", pkgver:"5.3.5-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5", pkgver:"5.3.5-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-cgi", pkgver:"5.3.5-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-cli", pkgver:"5.3.5-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-common", pkgver:"5.3.5-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-curl", pkgver:"5.3.5-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-dev", pkgver:"5.3.5-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-gd", pkgver:"5.3.5-1ubuntu7.1")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-intl", pkgver:"5.3.5-1ubuntu7.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / php-pear / php5 / php5-cgi / php5-cli / etc");
}

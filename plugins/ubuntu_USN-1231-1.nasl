#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1231-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56554);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/26 16:22:49 $");

  script_cve_id("CVE-2010-1914", "CVE-2010-2484", "CVE-2011-1657", "CVE-2011-1938", "CVE-2011-2202", "CVE-2011-2483", "CVE-2011-3182", "CVE-2011-3267");
  script_bugtraq_id(41991, 47950, 48259, 49241, 49249, 49252);
  script_osvdb_id(64662, 64663, 64664, 66804, 72644, 73113, 74739, 74742, 74743, 75200);
  script_xref(name:"USN", value:"1231-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.10 : php5 vulnerabilities (USN-1231-1)");
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
"Mateusz Kocielski, Marek Kroemeke and Filip Palian discovered that a
stack-based buffer overflow existed in the socket_connect function's
handling of long pathnames for AF_UNIX sockets. A remote attacker
might be able to exploit this to execute arbitrary code; however, the
default compiler options for affected releases should reduce the
vulnerability to a denial of service. This issue affected Ubuntu 10.04
LTS, Ubuntu 10.10 and Ubuntu 11.04. (CVE-2011-1938)

Krzysztof Kotowicz discovered that the PHP post handler function does
not properly restrict filenames in multipart/form-data POST requests.
This may allow remote attackers to conduct absolute path traversal
attacks and possibly create or overwrite arbitrary files. This issue
affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10 and Ubuntu
11.04. (CVE-2011-2202)

It was discovered that the crypt function for blowfish does not
properly handle 8-bit characters. This could make it easier for an
attacker to discover a cleartext password containing an 8-bit
character that has a matching blowfish crypt value. This issue
affected Ubuntu 10.04 LTS, Ubuntu 10.10 and Ubuntu 11.04.
(CVE-2011-2483)

It was discovered that PHP did not properly check the return values of
the malloc(3), calloc(3) and realloc(3) library functions in multiple
locations. This could allow an attacker to cause a denial of service
via a NULL pointer dereference or possibly execute arbitrary code.
This issue affected Ubuntu 8.04 LTS, Ubuntu 10.04 LTS, Ubuntu 10.10
and Ubuntu 11.04. (CVE-2011-3182)

Maksymilian Arciemowicz discovered that PHP did not properly implement
the error_log function. This could allow an attacker to cause a denial
of service via an application crash. This issue affected Ubuntu 10.04
LTS, Ubuntu 10.10, Ubuntu 11.04 and Ubuntu 11.10. (CVE-2011-3267)

Maksymilian Arciemowicz discovered that the ZipArchive functions
addGlob() and addPattern() did not properly check their flag
arguments. This could allow a malicious script author to cause a
denial of service via application crash. This issue affected Ubuntu
10.04 LTS, Ubuntu 10.10, Ubuntu 11.04 and Ubuntu 11.10.
(CVE-2011-1657)

It was discovered that the Xend opcode parser in PHP could be
interrupted while handling the shift-left, shift-right, and
bitwise-xor opcodes. This could allow a malicious script author to
expose memory contents. This issue affected Ubuntu 10.04 LTS.
(CVE-2010-1914)

It was discovered that the strrchr function in PHP could be
interrupted by a malicious script, allowing the exposure of memory
contents. This issue affected Ubuntu 8.04 LTS. (CVE-2010-2484).

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/19");
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
if (! ereg(pattern:"^(8\.04|10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libapache2-mod-php5", pkgver:"5.2.4-2ubuntu5.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cgi", pkgver:"5.2.4-2ubuntu5.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-cli", pkgver:"5.2.4-2ubuntu5.18")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"php5-common", pkgver:"5.2.4-2ubuntu5.18")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.2-1ubuntu4.10")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cgi", pkgver:"5.3.2-1ubuntu4.10")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-cli", pkgver:"5.3.2-1ubuntu4.10")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"php5-common", pkgver:"5.3.2-1ubuntu4.10")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libapache2-mod-php5", pkgver:"5.3.3-1ubuntu9.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-cgi", pkgver:"5.3.3-1ubuntu9.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-cli", pkgver:"5.3.3-1ubuntu9.6")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"php5-common", pkgver:"5.3.3-1ubuntu9.6")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libapache2-mod-php5", pkgver:"5.3.5-1ubuntu7.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-cgi", pkgver:"5.3.5-1ubuntu7.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-cli", pkgver:"5.3.5-1ubuntu7.3")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"php5-common", pkgver:"5.3.5-1ubuntu7.3")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libapache2-mod-php5", pkgver:"5.3.6-13ubuntu3.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"php5-cgi", pkgver:"5.3.6-13ubuntu3.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"php5-cli", pkgver:"5.3.6-13ubuntu3.2")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"php5-common", pkgver:"5.3.6-13ubuntu3.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libapache2-mod-php5 / php5-cgi / php5-cli / php5-common");
}

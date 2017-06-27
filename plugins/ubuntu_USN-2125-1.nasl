#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2125-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72798);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/24 17:29:02 $");

  script_cve_id("CVE-2014-1912");
  script_bugtraq_id(65379);
  script_xref(name:"USN", value:"2125-1");

  script_name(english:"Ubuntu 10.04 LTS / 12.04 LTS / 12.10 / 13.10 : python2.6, python2.7, python3.2, python3.3 vulnerability (USN-2125-1)");
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
"Ryan Smith-Roberts discovered that Python incorrectly handled buffer
sizes when using the socket.recvfrom_into() function. An attacker
could possibly use this issue to cause Python to crash, resulting in
denial of service, or possibly execute arbitrary code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.6-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.2-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.3-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2016 Canonical, Inc. / NASL script (C) 2014-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(10\.04|12\.04|12\.10|13\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 12.04 / 12.10 / 13.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"python2.6", pkgver:"2.6.5-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"python2.6-minimal", pkgver:"2.6.5-1ubuntu6.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python2.7", pkgver:"2.7.3-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python2.7-minimal", pkgver:"2.7.3-0ubuntu3.5")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python3.2", pkgver:"3.2.3-0ubuntu3.6")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python3.2-minimal", pkgver:"3.2.3-0ubuntu3.6")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python2.7", pkgver:"2.7.3-5ubuntu4.4")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python2.7-minimal", pkgver:"2.7.3-5ubuntu4.4")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python3.2", pkgver:"3.2.3-6ubuntu3.5")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python3.2-minimal", pkgver:"3.2.3-6ubuntu3.5")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python3.3", pkgver:"3.3.0-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"python3.3-minimal", pkgver:"3.3.0-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"python2.7", pkgver:"2.7.5-8ubuntu3.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"python2.7-minimal", pkgver:"2.7.5-8ubuntu3.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"python3.3", pkgver:"3.3.2-7ubuntu3.1")) flag++;
if (ubuntu_check(osver:"13.10", pkgname:"python3.3-minimal", pkgver:"3.3.2-7ubuntu3.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2.6 / python2.6-minimal / python2.7 / python2.7-minimal / etc");
}

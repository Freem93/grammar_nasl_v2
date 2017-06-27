#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2653-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84428);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/24 17:44:50 $");

  script_cve_id("CVE-2013-1752", "CVE-2013-1753", "CVE-2014-4616", "CVE-2014-4650", "CVE-2014-7185");
  script_bugtraq_id(63804, 66958, 68119, 68147, 70089);
  script_osvdb_id(101381, 101382, 101383, 101384, 101385, 101386, 106016, 108354, 108369, 112028);
  script_xref(name:"USN", value:"2653-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 14.10 : python2.7, python3.2, python3.4 vulnerabilities (USN-2653-1)");
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
"It was discovered that multiple Python protocol libraries incorrectly
limited certain data when connecting to servers. A malicious ftp,
http, imap, nntp, pop or smtp server could use this issue to cause a
denial of service. (CVE-2013-1752)

It was discovered that the Python xmlrpc library did not limit
unpacking gzip-compressed HTTP bodies. A malicious server could use
this issue to cause a denial of service. (CVE-2013-1753)

It was discovered that the Python json module incorrectly handled a
certain argument. An attacker could possibly use this issue to read
arbitrary memory and expose sensitive information. This issue only
affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-4616)

It was discovered that the Python CGIHTTPServer incorrectly handled
URL-encoded path separators in URLs. A remote attacker could use this
issue to expose sensitive information, or possibly execute arbitrary
code. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS.
(CVE-2014-4650)

It was discovered that Python incorrectly handled sizes and offsets in
buffer functions. An attacker could possibly use this issue to read
arbitrary memory and obtain sensitive information. This issue only
affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-7185).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.2-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3.4-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2016 Canonical, Inc. / NASL script (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(12\.04|14\.04|14\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 14.04 / 14.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"python2.7", pkgver:"2.7.3-0ubuntu3.8")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python2.7-minimal", pkgver:"2.7.3-0ubuntu3.8")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python3.2", pkgver:"3.2.3-0ubuntu3.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"python3.2-minimal", pkgver:"3.2.3-0ubuntu3.7")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python2.7", pkgver:"2.7.6-8ubuntu0.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python2.7-minimal", pkgver:"2.7.6-8ubuntu0.2")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python3.4", pkgver:"3.4.0-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"python3.4-minimal", pkgver:"3.4.0-2ubuntu1.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"python2.7", pkgver:"2.7.8-10ubuntu1.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"python2.7-minimal", pkgver:"2.7.8-10ubuntu1.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"python3.4", pkgver:"3.4.2-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"python3.4-minimal", pkgver:"3.4.2-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2.7 / python2.7-minimal / python3.2 / python3.2-minimal / etc");
}

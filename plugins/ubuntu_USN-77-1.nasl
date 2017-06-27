#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-77-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20699);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/25 16:34:55 $");

  script_cve_id("CVE-2005-0173", "CVE-2005-0174", "CVE-2005-0175", "CVE-2005-0211");
  script_xref(name:"USN", value:"77-1");

  script_name(english:"Ubuntu 4.10 : squid vulnerabilities (USN-77-1)");
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
"A possible authentication bypass was discovered in the LDAP
authentication backend. LDAP ignores leading and trailing whitespace
in search filters. This could possibly be abused to bypass explicit
access controls or confuse accounting when using several variants of
the login name. (CAN-2005-0173)

Previous Squid versions were not strict enough while parsing HTTP
requests and responses. Various violations of the HTTP protocol, such
as multiple Content-Length header lines, invalid 'Carriage Return'
characters, and HTTP header names containing whitespace, led to cache
pollution and could possibly be exploited to deliver wrong content to
clients. (CAN-2005-0174)

Squid was susceptible to a cache poisoning attack called 'HTTP
response splitting', where false replies are injected in the HTTP
stream. This allowed malicious web servers to forge wrong cache
content for arbitrary websites, which was then delivered to Squid
clients. (CAN-2005-0175)

The FSC Vulnerability Research Team discovered a buffer overflow in
the WCCP handling protocol. By sending an overly large WCCP packet, a
remote attacker could crash the Squid server, and possibly even
execute arbitrary code with the privileges of the 'proxy' user.
(CAN-2005-0211).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squid-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:squidclient");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:4.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2005-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 4.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"4.10", pkgname:"squid", pkgver:"2.5.5-6ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"squid-cgi", pkgver:"2.5.5-6ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"squid-common", pkgver:"2.5.5-6ubuntu0.4")) flag++;
if (ubuntu_check(osver:"4.10", pkgname:"squidclient", pkgver:"2.5.5-6ubuntu0.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-cgi / squid-common / squidclient");
}

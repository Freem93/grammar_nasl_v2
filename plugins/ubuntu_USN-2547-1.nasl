#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2547-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82074);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/05 14:32:01 $");

  script_cve_id("CVE-2011-0992", "CVE-2012-3543", "CVE-2015-2318", "CVE-2015-2319", "CVE-2015-2320");
  script_bugtraq_id(47208, 55251, 73250, 73253, 73256);
  script_osvdb_id(56387, 85008, 119306, 119326);
  script_xref(name:"USN", value:"2547-1");

  script_name(english:"Ubuntu 12.04 LTS / 14.04 LTS / 14.10 : mono vulnerabilities (USN-2547-1)");
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
"It was discovered that the Mono TLS implementation was vulnerable to
the SKIP-TLS vulnerability. A remote attacker could possibly use this
issue to perform client impersonation attacks. (CVE-2015-2318)

It was discovered that the Mono TLS implementation was vulnerable to
the FREAK vulnerability. A remote attacker or a man in the middle
could possibly use this issue to force the use of insecure
ciphersuites. (CVE-2015-2319)

It was discovered that the Mono TLS implementation still supported a
fallback to SSLv2. This update removes the functionality as use of
SSLv2 is known to be insecure. (CVE-2015-2320)

It was discovered that Mono incorrectly handled memory in certain
circumstances. A remote attacker could possibly use this issue to
cause Mono to crash, resulting in a denial of service, or to obtain
sensitive information. This issue only applied to Ubuntu 12.04 LTS.
(CVE-2011-0992)

It was discovered that Mono incorrectly handled hash collisions. A
remote attacker could possibly use this issue to cause Mono to crash,
resulting in a denial of service. This issue only applied to Ubuntu
12.04 LTS. (CVE-2012-3543).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libmono-2.0-1 and / or mono-runtime packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmono-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mono-runtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/25");
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

if (ubuntu_check(osver:"12.04", pkgname:"libmono-2.0-1", pkgver:"2.10.8.1-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"mono-runtime", pkgver:"2.10.8.1-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libmono-2.0-1", pkgver:"3.2.8+dfsg-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"mono-runtime", pkgver:"3.2.8+dfsg-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"libmono-2.0-1", pkgver:"3.2.8+dfsg-4ubuntu2.1")) flag++;
if (ubuntu_check(osver:"14.10", pkgname:"mono-runtime", pkgver:"3.2.8+dfsg-4ubuntu2.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmono-2.0-1 / mono-runtime");
}
